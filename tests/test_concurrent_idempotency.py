import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core import initialize_database
from app.dependencies import (
    get_db_path,
    get_scope_repository,
    get_execution_repository,
    get_findings_repository,
    set_db_path,
)
from app.schemas.assessment import AssessmentCreate, AssessmentStatus
from app.schemas.common import (
    ExecutionStatus,
    ScopeDecision,
    TERMINAL_EXECUTION_STATUSES,
)
from app.schemas.engagement import EngagementCreate, EngagementStatus
from app.schemas.scope import ScopeItemCreate, ScopeType
from app.repositories.sqlite_execution_repository import SqliteExecutionRepository
from app.repositories.sqlite_findings_repository import SqliteFindingsRepository
from app.repositories.sqlite_scope_repository import SqliteScopeRepository
from app.schemas.check_execution import CheckExecution
from security.rules.web.sec_web_001 import SecWeb001Rule


@pytest.fixture
def idempotency_sandbox(tmp_path: Path):
    """Provides a fresh isolated SQLite database per test."""
    db_file = tmp_path / "idempotency_workbench.db"
    initialize_database(db_path=db_file)
    set_db_path(db_file)

    scope_repo = SqliteScopeRepository(db_path=db_file)
    exec_repo = SqliteExecutionRepository(db_path=db_file)
    findings_repo = SqliteFindingsRepository(db_path=db_file)

    app.dependency_overrides[get_db_path] = lambda: db_file
    app.dependency_overrides[get_scope_repository] = lambda: scope_repo
    app.dependency_overrides[get_execution_repository] = lambda: exec_repo
    app.dependency_overrides[get_findings_repository] = lambda: findings_repo

    client = TestClient(app)
    yield {
        "db_file": db_file,
        "scope_repo": scope_repo,
        "exec_repo": exec_repo,
        "findings_repo": findings_repo,
        "client": client,
    }

    set_db_path(None)
    app.dependency_overrides.clear()


def _seed_assessment(sandbox, eng_id="ENG-IDEMP", asm_id="ASM-IDEMP", scope_val="example.com"):
    now = datetime.now(timezone.utc)
    scope_repo = sandbox["scope_repo"]
    scope_repo.create_engagement(
        EngagementCreate(
            id=eng_id,
            workspaceId="WKS-IDEMP",
            name="Idempotency Test Engagement",
            assessor="Lead Assessor",
            status=EngagementStatus.ACTIVE,
            rulesOfEngagement="Defensive evaluation only.",
            createdAt=now,
        )
    )
    scope_repo.create_assessment(
        AssessmentCreate(
            id=asm_id,
            engagementId=eng_id,
            name="Idempotency Running Assessment",
            type="web",
            status=AssessmentStatus.RUNNING,
            startedAt=now,
            createdAt=now,
        )
    )
    scope_repo.create_scope_item(
        ScopeItemCreate(
            id=f"SCP-{eng_id}",
            engagementId=eng_id,
            type=ScopeType.DOMAIN,
            value=scope_val,
            inScope=True,
            environment="production",
            createdAt=now,
        )
    )


def test_concurrent_execution_invokes_collector_once(idempotency_sandbox, monkeypatch):
    """
    P1 Requirement: Concurrent requests with identical idempotency keys
    must not dispatch tools twice. Controlled synchronization barrier verifies
    that underlying rule/collector is invoked EXACTLY ONCE.
    """
    _seed_assessment(idempotency_sandbox, eng_id="ENG-CONC-01", asm_id="ASM-CONC-01")
    exec_repo = idempotency_sandbox["exec_repo"]
    client = idempotency_sandbox["client"]

    # Wrap SecWeb001Rule.evaluate with an atomic call counter and artificial delay
    original_evaluate = SecWeb001Rule.evaluate
    eval_call_count = 0
    eval_lock = threading.Lock()

    def wrapped_evaluate(self, assessment_id, asset_id, collector_result):
        nonlocal eval_call_count
        with eval_lock:
            eval_call_count += 1
        time.sleep(0.08)  # Hold in execution to allow concurrent threads to race
        return original_evaluate(self, assessment_id, asset_id, collector_result)

    monkeypatch.setattr(SecWeb001Rule, "evaluate", wrapped_evaluate)

    num_threads = 5
    barrier = threading.Barrier(num_threads)
    results = []

    def worker():
        barrier.wait()  # Synchronize all threads to fire simultaneously
        resp = client.post(
            "/api/v1/executions/run",
            headers={"Idempotency-Key": "CHK-BARRIER-RACE"},
            json={
                "id": "CHK-BARRIER-RACE",
                "assessmentId": "ASM-CONC-01",
                "engagementId": "ENG-CONC-01",
                "ruleId": "SEC-WEB-001",
                "target": "example.com",
                "simulatedData": {"strict-transport-security": "max-age=31536000"},
            },
        )
        results.append(resp)

    threads = [threading.Thread(target=worker) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    # 1. All threads must succeed (HTTP 200)
    assert len(results) == num_threads
    for r in results:
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"

    # 2. Rule evaluation must have been invoked EXACTLY ONCE
    assert eval_call_count == 1, f"Expected evaluate() to run exactly once, but ran {eval_call_count} times!"

    # 3. Database must have exactly one execution record for this ID
    exec_record = exec_repo.get_execution("CHK-BARRIER-RACE")
    assert exec_record is not None
    assert exec_record.status in TERMINAL_EXECUTION_STATUSES


def test_idempotency_key_header_matching_and_conflict(idempotency_sandbox):
    """Verify Idempotency-Key header support and conflict rejection on mismatched body id."""
    _seed_assessment(idempotency_sandbox, eng_id="ENG-IDEMP-02", asm_id="ASM-IDEMP-02")
    client = idempotency_sandbox["client"]

    # 1. Matching header and body ID -> Succeeds
    resp1 = client.post(
        "/api/v1/executions/run",
        headers={"Idempotency-Key": "CHK-MATCH-01"},
        json={
            "id": "CHK-MATCH-01",
            "assessmentId": "ASM-IDEMP-02",
            "engagementId": "ENG-IDEMP-02",
            "ruleId": "SEC-WEB-001",
            "target": "example.com",
        },
    )
    assert resp1.status_code == 200

    # 2. Conflicting header and body ID -> HTTP 400 Bad Request
    resp_conflict = client.post(
        "/api/v1/executions/run",
        headers={"Idempotency-Key": "CHK-HEADER-ID"},
        json={
            "id": "CHK-BODY-ID",
            "assessmentId": "ASM-IDEMP-02",
            "engagementId": "ENG-IDEMP-02",
            "ruleId": "SEC-WEB-001",
            "target": "example.com",
        },
    )
    assert resp_conflict.status_code == 400
    assert "Conflicting execution identifiers" in resp_conflict.json()["detail"]


def test_in_progress_state_replay_for_pending_and_running(idempotency_sandbox, monkeypatch):
    """Verify that requests for records currently in PENDING or RUNNING state return in-progress without re-execution."""
    _seed_assessment(idempotency_sandbox, eng_id="ENG-IDEMP-03", asm_id="ASM-IDEMP-03")
    exec_repo = idempotency_sandbox["exec_repo"]
    client = idempotency_sandbox["client"]

    # Ensure rule is never invoked during in-progress queries
    def fail_if_invoked(*args, **kwargs):
        pytest.fail("Security rule evaluate() must not be called for in-progress executions!")

    monkeypatch.setattr(SecWeb001Rule, "evaluate", fail_if_invoked)

    # 1. Direct reservation in PENDING state with matching fingerprint
    from app.api.executions import compute_request_fingerprint
    actual_fp = compute_request_fingerprint("ASM-IDEMP-03", "SEC-WEB-001", "example.com", "ENG-IDEMP-03", "AST-001", None, operation="run")

    pending = CheckExecution(
        id="CHK-INPROGRESS-01",
        assessmentId="ASM-IDEMP-03",
        ruleId="SEC-WEB-001",
        target="example.com",
        scopeDecision=ScopeDecision.ALLOW,
        status=ExecutionStatus.PENDING,
        requestFingerprint=actual_fp,
    )
    exec_repo.record_execution(pending)

    resp_pending = client.post(
        "/api/v1/executions/run",
        headers={"Idempotency-Key": "CHK-INPROGRESS-01"},
        json={
            "id": "CHK-INPROGRESS-01",
            "assessmentId": "ASM-IDEMP-03",
            "engagementId": "ENG-IDEMP-03",
            "ruleId": "SEC-WEB-001",
            "target": "example.com",
        },
    )
    assert resp_pending.status_code == 200
    assert "in-progress" in resp_pending.json()["message"]
    assert resp_pending.json()["executionRecord"]["status"] == "PENDING"

    # 2. Transition to RUNNING state
    pending.status = ExecutionStatus.RUNNING
    exec_repo.record_execution(pending)

    resp_running = client.post(
        "/api/v1/executions/run",
        headers={"Idempotency-Key": "CHK-INPROGRESS-01"},
        json={
            "id": "CHK-INPROGRESS-01",
            "assessmentId": "ASM-IDEMP-03",
            "engagementId": "ENG-IDEMP-03",
            "ruleId": "SEC-WEB-001",
            "target": "example.com",
        },
    )
    assert resp_running.status_code == 200
    assert "in-progress" in resp_running.json()["message"]
    assert resp_running.json()["executionRecord"]["status"] == "RUNNING"


def test_interrupted_state_never_triggers_automatic_retry(idempotency_sandbox, monkeypatch):
    """Verify that INTERRUPTED execution records replay as terminal and never re-execute."""
    _seed_assessment(idempotency_sandbox, eng_id="ENG-IDEMP-04", asm_id="ASM-IDEMP-04")
    exec_repo = idempotency_sandbox["exec_repo"]
    client = idempotency_sandbox["client"]

    def fail_if_invoked(*args, **kwargs):
        pytest.fail("Rule evaluate() should never be invoked when replaying INTERRUPTED executions!")

    monkeypatch.setattr(SecWeb001Rule, "evaluate", fail_if_invoked)

    from app.api.executions import compute_request_fingerprint
    actual_fp = compute_request_fingerprint("ASM-IDEMP-04", "SEC-WEB-001", "example.com", "ENG-IDEMP-04", "AST-001", None, operation="run")

    interrupted = CheckExecution(
        id="CHK-INTERRUPTED-01",
        assessmentId="ASM-IDEMP-04",
        ruleId="SEC-WEB-001",
        target="example.com",
        scopeDecision=ScopeDecision.ALLOW,
        status=ExecutionStatus.INTERRUPTED,
        errorCode="SYSTEM_INTERRUPTED",
        errorMessage="Process died.",
        requestFingerprint=actual_fp,
    )
    exec_repo.record_execution(interrupted)

    resp = client.post(
        "/api/v1/executions/run",
        headers={"Idempotency-Key": "CHK-INTERRUPTED-01"},
        json={
            "id": "CHK-INTERRUPTED-01",
            "assessmentId": "ASM-IDEMP-04",
            "engagementId": "ENG-IDEMP-04",
            "ruleId": "SEC-WEB-001",
            "target": "example.com",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "Idempotent replay" in data["message"]
    assert data["executionRecord"]["status"] == "INTERRUPTED"
