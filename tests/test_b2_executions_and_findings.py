import sqlite3
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.core import initialize_database
from app.dependencies import (
    get_db_path,
    get_execution_repository,
    get_findings_repository,
    get_scope_repository,
    set_db_path,
)
from app.schemas.assessment import AssessmentCreate, AssessmentStatus, AssessmentType
from app.schemas.common import (
    ExecutionStatus,
    FindingStatus,
    ScopeDecision,
    Severity,
    Confidence,
    TERMINAL_EXECUTION_STATUSES,
)
from app.schemas.engagement import EngagementCreate, EngagementStatus
from app.schemas.finding import FindingCreate
from app.schemas.scope import ScopeItemCreate, ScopeType
from app.repositories.sqlite_execution_repository import SqliteExecutionRepository
from app.repositories.sqlite_findings_repository import SqliteFindingsRepository
from app.repositories.sqlite_scope_repository import SqliteScopeRepository
from app.schemas.check_execution import CheckExecution
from evidence.storage import evidence_store


@pytest.fixture
def b2_sandbox(tmp_path):
    """Provides a fresh isolated SQLite database per test."""
    db_file = tmp_path / "b2_workbench.db"
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


def _seed_running_assessment(sandbox, eng_id="ENG-B2", asm_id="ASM-B2", scope_val="example.com"):
    """Helper to seed active engagement, running assessment, and scope."""
    now = datetime.now(timezone.utc)
    eng = sandbox["scope_repo"].create_engagement(
        EngagementCreate(
            id=eng_id,
            workspaceId="WKS-B2",
            name="B2 Persistence Verification Engagement",
            assessor="Lead Assessor",
            status=EngagementStatus.ACTIVE,
            rulesOfEngagement="Defensive evaluation only.",
            createdAt=now,
        )
    )
    asm = sandbox["scope_repo"].create_assessment(
        AssessmentCreate(
            id=asm_id,
            engagementId=eng_id,
            name="B2 Running Assessment",
            type=AssessmentType.WEB,
            status=AssessmentStatus.RUNNING,
            startedAt=now,
            createdAt=now,
        )
    )
    scp = sandbox["scope_repo"].create_scope_item(
        ScopeItemCreate(
            id=f"SCP-{eng_id}",
            engagementId=eng_id,
            type=ScopeType.DOMAIN,
            value=scope_val,
            environment="lab",
            inScope=True,
        )
    )
    return eng, asm, scp


def test_b2_01_execution_persistence_after_restart(b2_sandbox):
    """
    1. Execution persistence after backend restart:
    Ensure check execution records written to SQLite survive process restart without loss or corruption.
    """
    _seed_running_assessment(b2_sandbox, eng_id="ENG-B2-01", asm_id="ASM-B2-01", scope_val="example.com")
    client = b2_sandbox["client"]
    db_file = b2_sandbox["db_file"]

    # Run check with simulated headers to generate PASS
    resp = client.post(
        "/api/v1/executions/run",
        json={
            "id": "CHK-PERSIST-001",
            "assessmentId": "ASM-B2-01",
            "engagementId": "ENG-B2-01",
            "ruleId": "SEC-WEB-001",
            "target": "example.com",
            "simulatedData": {
                "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
            },
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["allowed"] is True
    assert data["executionRecord"]["id"] == "CHK-PERSIST-001"
    assert data["executionRecord"]["status"] == "PASS"

    # Simulate backend restart: Instantiate fresh repository pointing to same db file
    fresh_exec_repo = SqliteExecutionRepository(db_path=db_file)
    reloaded = fresh_exec_repo.get_execution("CHK-PERSIST-001")
    assert reloaded is not None
    assert reloaded.id == "CHK-PERSIST-001"
    assert reloaded.assessmentId == "ASM-B2-01"
    assert reloaded.ruleId == "SEC-WEB-001"
    assert reloaded.target == "example.com"
    assert reloaded.status == ExecutionStatus.PASS
    assert reloaded.scopeDecision == ScopeDecision.ALLOW


def test_b2_02_findings_persistence_after_restart(b2_sandbox):
    """
    2. Findings persistence after backend restart:
    Ensure security findings written to SQLite survive process restart with all attributes intact.
    """
    _seed_running_assessment(b2_sandbox, eng_id="ENG-B2-02", asm_id="ASM-B2-02")
    client = b2_sandbox["client"]
    db_file = b2_sandbox["db_file"]

    create_payload = {
        "id": "FND-RESTART-001",
        "assessmentId": "ASM-B2-02",
        "assetId": "AST-001",
        "ruleId": "SEC-WEB-001",
        "title": "Missing Strict-Transport-Security Header",
        "description": "The HSTS header is missing from the target response.",
        "status": "NEEDS_REVIEW",
        "severity": "high",
        "confidence": "high",
        "cwe": "CWE-319",
        "cvss": 7.5,
        "impact": "Man-in-the-middle attacks may downgrade secure transport.",
        "recommendation": "Configure Strict-Transport-Security with max-age=31536000.",
    }
    resp = client.post("/api/v1/findings", json=create_payload)
    assert resp.status_code == 201, resp.text
    assert resp.json()["id"] == "FND-RESTART-001"

    # Simulate backend restart: fresh repository instance
    fresh_findings_repo = SqliteFindingsRepository(db_path=db_file)
    fnd = fresh_findings_repo.get_finding("FND-RESTART-001")
    assert fnd is not None
    assert fnd.id == "FND-RESTART-001"
    assert fnd.title == "Missing Strict-Transport-Security Header"
    assert fnd.severity == Severity.HIGH
    assert fnd.confidence == Confidence.HIGH
    assert fnd.cvss == 7.5
    assert fnd.status == FindingStatus.NEEDS_REVIEW


def test_b2_03_duplicate_execution_idempotency_and_replay(b2_sandbox):
    """
    3. Duplicate execution request handling (idempotent retries):
    - Same execution ID + same request fingerprint: returns existing record without re-executing.
    - Preserves exactly one durable record in SQLite.
    """
    _seed_running_assessment(b2_sandbox, eng_id="ENG-B2-03", asm_id="ASM-B2-03", scope_val="example.com")
    client = b2_sandbox["client"]
    db_file = b2_sandbox["db_file"]

    payload = {
        "id": "CHK-IDEMP-001",
        "assessmentId": "ASM-B2-03",
        "engagementId": "ENG-B2-03",
        "ruleId": "SEC-WEB-001",
        "target": "example.com",
        "simulatedData": {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin",
        },
    }

    # Initial execution
    resp1 = client.post("/api/v1/executions/run", json=payload)
    assert resp1.status_code == 200
    assert resp1.json()["executionRecord"]["status"] == "PASS"

    # Retry execution with same ID and identical fingerprint
    resp2 = client.post("/api/v1/executions/run", json=payload)
    assert resp2.status_code == 200, resp2.text
    assert "Idempotent replay" in resp2.json()["message"]
    assert resp2.json()["executionRecord"]["id"] == "CHK-IDEMP-001"
    assert resp2.json()["executionRecord"]["status"] == "PASS"

    # Verify only 1 record exists in check_executions with this ID
    with sqlite3.connect(str(db_file)) as conn:
        count = conn.execute("SELECT COUNT(*) FROM check_executions WHERE id = 'CHK-IDEMP-001';").fetchone()[0]
        assert count == 1


def test_b2_04_execution_conflict_and_immutability(b2_sandbox):
    """
    4. Execution Conflict & Immutability (P1):
    - Same execution ID + different request fingerprint: reject with HTTP 409 Conflict.
    - Terminal execution records are immutable and cannot be overwritten.
    """
    _seed_running_assessment(b2_sandbox, eng_id="ENG-B2-04", asm_id="ASM-B2-04", scope_val="example.com")
    client = b2_sandbox["client"]
    exec_repo = b2_sandbox["exec_repo"]

    # 1. Run first check with ID CHK-CONFLICT-01
    resp1 = client.post(
        "/api/v1/executions/run",
        json={
            "id": "CHK-CONFLICT-01",
            "assessmentId": "ASM-B2-04",
            "engagementId": "ENG-B2-04",
            "ruleId": "SEC-WEB-001",
            "target": "example.com",
            "simulatedData": {"strict-transport-security": "max-age=31536000"},
        },
    )
    assert resp1.status_code == 200

    # 2. Attempt execution with SAME ID but DIFFERENT target -> HTTP 409 Conflict
    resp_conflict = client.post(
        "/api/v1/executions/run",
        json={
            "id": "CHK-CONFLICT-01",
            "assessmentId": "ASM-B2-04",
            "engagementId": "ENG-B2-04",
            "ruleId": "SEC-WEB-001",
            "target": "other.example.com",
            "simulatedData": {"strict-transport-security": "max-age=31536000"},
        },
    )
    assert resp_conflict.status_code == 409
    assert "Conflicting request" in resp_conflict.json()["detail"]

    # 3. Direct repository test: attempting to overwrite terminal record raises ValueError
    terminal_exec = exec_repo.get_execution("CHK-CONFLICT-01")
    assert terminal_exec is not None
    assert terminal_exec.status in TERMINAL_EXECUTION_STATUSES

    # Ensure we attempt to change to a different status to test immutability
    mutated_status = (
        ExecutionStatus.PASS
        if terminal_exec.status == ExecutionStatus.FAIL
        else ExecutionStatus.FAIL
    )
    mutated_exec = CheckExecution(
        id="CHK-CONFLICT-01",
        assessmentId="ASM-B2-04",
        ruleId="SEC-WEB-001",
        target="example.com",
        scopeDecision=ScopeDecision.ALLOW,
        status=mutated_status,
        requestFingerprint=terminal_exec.requestFingerprint,
    )
    with pytest.raises(ValueError, match="immutable"):
        exec_repo.record_execution(mutated_exec)


def test_b2_05_write_ahead_lifecycle_aborts_if_initial_db_write_fails(b2_sandbox, monkeypatch):
    """
    5. Write-Ahead Execution Lifecycle (P0):
    If the initial database write fails, the security tool must NOT be invoked,
    and an audit error (HTTP 500) must be raised.
    """
    _seed_running_assessment(b2_sandbox, eng_id="ENG-B2-05", asm_id="ASM-B2-05", scope_val="example.com")
    client = b2_sandbox["client"]

    tool_invoked = False

    def mock_evaluate(*args, **kwargs):
        nonlocal tool_invoked
        tool_invoked = True
        return ExecutionStatus.PASS, {}, {}, {}

    from security.rules.web.sec_web_001 import SecWeb001Rule
    monkeypatch.setattr(SecWeb001Rule, "evaluate", mock_evaluate)

    # Monkeypatch exec_repo to fail on initial record_execution
    def mock_fail_db(data):
        raise sqlite3.OperationalError("Simulated database failure during initial PENDING intent")

    monkeypatch.setattr(b2_sandbox["exec_repo"], "record_execution", mock_fail_db)

    resp = client.post(
        "/api/v1/executions/run",
        json={
            "assessmentId": "ASM-B2-05",
            "engagementId": "ENG-B2-05",
            "ruleId": "SEC-WEB-001",
            "target": "example.com",
        },
    )
    # Must fail closed: HTTP 500 audit failure
    assert resp.status_code == 500
    assert "Tool invocation aborted" in resp.json()["detail"]
    # Verify the tool was NEVER dispatched!
    assert tool_invoked is False


def test_b2_06_startup_reconciliation_of_stale_records(b2_sandbox):
    """
    6. Startup Stale Record Reconciliation (P0):
    Detect in-flight records left in PENDING or RUNNING when the process stops,
    and reconcile them to INTERRUPTED state without falsely claiming PASS or FAIL.
    """
    _seed_running_assessment(b2_sandbox, eng_id="ENG-B2-06", asm_id="ASM-B2-06", scope_val="example.com")
    db_file = b2_sandbox["db_file"]
    exec_repo = b2_sandbox["exec_repo"]

    # Insert an execution that was left in RUNNING when process died
    with sqlite3.connect(str(db_file)) as conn:
        conn.execute(
            """
            INSERT INTO check_executions (
                id, assessment_id, rule_id, target, scope_decision,
                status, rule_version, executed_at
            ) VALUES ('CHK-STALE-01', 'ASM-B2-06', 'SEC-WEB-001', 'example.com', 'ALLOW', 'RUNNING', '1.0.0', '2026-11-01T12:00:00Z');
            """
        )
        conn.execute(
            """
            INSERT INTO check_executions (
                id, assessment_id, rule_id, target, scope_decision,
                status, rule_version, executed_at
            ) VALUES ('CHK-STALE-02', 'ASM-B2-06', 'SEC-WEB-001', 'example.com', 'ALLOW', 'PENDING', '1.0.0', '2026-11-01T12:00:00Z');
            """
        )

    # Trigger startup reconciliation
    reconciled_count = exec_repo.reconcile_stale_executions()
    assert reconciled_count == 2

    # Verify both stale records are now INTERRUPTED (not PASS or FAIL)
    rec1 = exec_repo.get_execution("CHK-STALE-01")
    assert rec1 is not None
    assert rec1.status == ExecutionStatus.INTERRUPTED
    assert rec1.errorCode == "SYSTEM_INTERRUPTED"

    rec2 = exec_repo.get_execution("CHK-STALE-02")
    assert rec2 is not None
    assert rec2.status == ExecutionStatus.INTERRUPTED
    assert rec2.errorCode == "SYSTEM_INTERRUPTED"


def test_b2_07_scope_and_lifecycle_rejections(b2_sandbox):
    """
    7. Scope and Lifecycle Rejections:
    - Out of scope target returns BLOCKED_OUT_OF_SCOPE and logs block record.
    - Checks against non-RUNNING assessments or inactive engagements return HTTP 409 Conflict.
    """
    _seed_running_assessment(b2_sandbox, eng_id="ENG-B2-07", asm_id="ASM-B2-07", scope_val="authorized.local")
    client = b2_sandbox["client"]

    # 1. Out of scope execution
    resp_scope = client.post(
        "/api/v1/executions/run",
        json={
            "id": "CHK-BLOCKED-07",
            "assessmentId": "ASM-B2-07",
            "engagementId": "ENG-B2-07",
            "ruleId": "SEC-WEB-001",
            "target": "evil.unauthorized.com",
        },
    )
    assert resp_scope.status_code == 200
    assert resp_scope.json()["allowed"] is False
    assert resp_scope.json()["executionRecord"]["status"] == "BLOCKED_OUT_OF_SCOPE"

    # 2. DRAFT assessment lifecycle rejection
    b2_sandbox["scope_repo"].create_assessment(
        AssessmentCreate(
            id="ASM-B2-DRAFT",
            engagementId="ENG-B2-07",
            name="Draft Assessment",
            type=AssessmentType.GENERAL,
            status=AssessmentStatus.DRAFT,
        )
    )
    resp_draft = client.post(
        "/api/v1/executions/run",
        json={
            "assessmentId": "ASM-B2-DRAFT",
            "engagementId": "ENG-B2-07",
            "ruleId": "SEC-WEB-001",
            "target": "authorized.local",
        },
    )
    assert resp_draft.status_code == 409
    assert "DRAFT" in resp_draft.json()["detail"]


def test_b2_08_findings_filtering_and_soft_delete(b2_sandbox):
    """
    8. Findings filtering, ordering, status transitions, and soft deletion.
    """
    _seed_running_assessment(b2_sandbox, eng_id="ENG-B2-08", asm_id="ASM-B2-08")
    client = b2_sandbox["client"]
    db_file = b2_sandbox["db_file"]

    # Create 2 findings
    r1 = client.post(
        "/api/v1/findings",
        json={
            "id": "FND-08-CRIT",
            "assessmentId": "ASM-B2-08",
            "assetId": "AST-001",
            "title": "Critical Finding",
            "status": "CONFIRMED",
            "severity": "critical",
            "confidence": "high",
            "createdAt": "2026-11-01T10:00:00Z",
        },
    )
    assert r1.status_code == 201

    r2 = client.post(
        "/api/v1/findings",
        json={
            "id": "FND-08-MED",
            "assessmentId": "ASM-B2-08",
            "assetId": "AST-001",
            "title": "Medium Finding",
            "status": "NEEDS_REVIEW",
            "severity": "medium",
            "confidence": "medium",
            "createdAt": "2026-11-01T11:00:00Z",
        },
    )
    assert r2.status_code == 201

    # Filter by severity=critical
    r_crit = client.get("/api/v1/findings?assessmentId=ASM-B2-08&severity=critical")
    assert r_crit.status_code == 200
    assert len(r_crit.json()) == 1
    assert r_crit.json()[0]["id"] == "FND-08-CRIT"

    # Status update: transition to RESOLVED
    r_patch = client.patch("/api/v1/findings/FND-08-CRIT/status", json={"status": "RESOLVED"})
    assert r_patch.status_code == 200
    assert r_patch.json()["status"] == "RESOLVED"

    # Soft delete
    r_del = client.delete("/api/v1/findings/FND-08-CRIT")
    assert r_del.status_code == 204

    # Direct query 404
    assert client.get("/api/v1/findings/FND-08-CRIT").status_code == 404

    # DB persistence check: is_deleted = 1
    with sqlite3.connect(str(db_file)) as conn:
        row = conn.execute("SELECT is_deleted, deleted_at, status FROM findings WHERE id = 'FND-08-CRIT';").fetchone()
        assert row[0] == 1
        assert row[1] is not None
        assert row[2] == "RESOLVED"


def test_b2_09_reports_consistent_read_from_sqlite(b2_sandbox):
    """
    9. Reports Consistent Read from SQLite (P1):
    Verify reports read assessment metadata, scope items, and findings from SQLite
    within a consistent snapshot without in-memory fallbacks.
    """
    eng, asm, scp = _seed_running_assessment(
        b2_sandbox, eng_id="ENG-B2-09", asm_id="ASM-B2-09", scope_val="audit.target.local"
    )
    client = b2_sandbox["client"]

    # Persist finding directly to SQLite
    b2_sandbox["findings_repo"].create_finding(
        FindingCreate(
            id="FND-REP-01",
            assessmentId="ASM-B2-09",
            assetId="AST-001",
            ruleId="SEC-WEB-001",
            title="Consistent SQLite Finding in Report",
            description="Verified SQLite-persisted vulnerability.",
            status=FindingStatus.CONFIRMED,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            cwe="CWE-693",
            cvss=7.2,
            impact="Risk of data interception.",
            recommendation="Apply strict transport security.",
        )
    )

    # Test Markdown report
    resp_md = client.get("/api/v1/reports/ASM-B2-09/markdown")
    assert resp_md.status_code == 200
    assert "text/markdown" in resp_md.headers["content-type"]
    md_text = resp_md.text
    assert "ENG-B2-09" in md_text
    assert "ASM-B2-09" in md_text
    assert "Consistent SQLite Finding in Report" in md_text
    assert "HIGH" in md_text
    assert "CWE-693" in md_text

    # Test HTML report
    resp_html = client.get("/api/v1/reports/ASM-B2-09/html")
    assert resp_html.status_code == 200
    assert "text/html" in resp_html.headers["content-type"]
    assert "Content-Security-Policy" in resp_html.headers
    html_text = resp_html.text
    assert "ENG-B2-09" in html_text
    assert "Consistent SQLite Finding in Report" in html_text


def test_b2_10_empty_state_behavior(b2_sandbox):
    """
    10. Empty-state behavior:
    Verify fresh assessment with zero findings and zero executions reports truth-accurate empty states.
    """
    _seed_running_assessment(b2_sandbox, eng_id="ENG-B2-10", asm_id="ASM-B2-10")
    client = b2_sandbox["client"]

    # Findings list empty
    r_fnd = client.get("/api/v1/findings?assessmentId=ASM-B2-10")
    assert r_fnd.status_code == 200
    assert r_fnd.json() == []

    # Executions list empty
    r_exec = client.get("/api/v1/executions?assessment_id=ASM-B2-10")
    assert r_exec.status_code == 200
    assert r_exec.json() == []

    # Reports truthful empty summary
    r_report = client.get("/api/v1/reports/ASM-B2-10/markdown")
    assert r_report.status_code == 200
    assert "A total of **0** finding(s)" in r_report.text
    assert "No security vulnerabilities were identified in the assessed scope." in r_report.text
