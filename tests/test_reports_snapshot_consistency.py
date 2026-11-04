import threading
import time
from datetime import datetime, timezone
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core import initialize_database, create_connection, transaction
from app.dependencies import (
    get_db_path,
    get_scope_repository,
    get_execution_repository,
    get_findings_repository,
    set_db_path,
)
from app.schemas.assessment import AssessmentCreate, AssessmentStatus
from app.schemas.engagement import EngagementCreate, EngagementStatus
from app.schemas.scope import ScopeItemCreate, ScopeType
from app.schemas.finding import FindingCreate, Severity, Confidence
from app.schemas.check_execution import CheckExecution
from app.schemas.common import ExecutionStatus, ScopeDecision
from app.repositories.sqlite_execution_repository import SqliteExecutionRepository
from app.repositories.sqlite_findings_repository import SqliteFindingsRepository
from app.repositories.sqlite_scope_repository import SqliteScopeRepository
from app.api.reports import fetch_consistent_report_dataset
from reports.generator import SecurityReportGenerator


@pytest.fixture
def reports_sandbox(tmp_path: Path):
    """Provides a fresh isolated SQLite database per test."""
    db_file = tmp_path / "reports_workbench.db"
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


def _seed_base_data(sandbox, eng_id="ENG-REP", asm_id="ASM-REP"):
    now = datetime.now(timezone.utc)
    scope_repo = sandbox["scope_repo"]
    scope_repo.create_engagement(
        EngagementCreate(
            id=eng_id,
            workspaceId="WKS-REP",
            name="Report Consistency Engagement",
            assessor="Auditor",
            status=EngagementStatus.ACTIVE,
            rulesOfEngagement="Defensive evaluation only.",
            createdAt=now,
        )
    )
    scope_repo.create_assessment(
        AssessmentCreate(
            id=asm_id,
            engagementId=eng_id,
            name="Report Running Assessment",
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
            value="example.com",
            inScope=True,
            environment="production",
            createdAt=now,
        )
    )


def test_report_snapshot_isolation_under_concurrent_writes(reports_sandbox):
    """
    P1 Requirement: Verify that SQLite WAL snapshot isolation via 'BEGIN DEFERRED'
    guarantees a consistent report view even if concurrent writes occur mid-generation.
    """
    _seed_base_data(reports_sandbox, eng_id="ENG-SNAP-01", asm_id="ASM-SNAP-01")
    db_file = reports_sandbox["db_file"]
    findings_repo = reports_sandbox["findings_repo"]

    # 1. Insert Initial Baseline Finding
    findings_repo.create_finding(
        FindingCreate(
            id="FND-INITIAL-01",
            assessmentId="ASM-SNAP-01",
            assetId="AST-001",
            ruleId="SEC-WEB-001",
            title="Initial Baseline Vulnerability",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
        )
    )

    # 2. Open a reader connection with BEGIN DEFERRED and execute first query (establishing read snapshot)
    read_conn = create_connection(db_file)
    read_conn.execute("BEGIN DEFERRED;")
    initial_read = read_conn.execute(
        "SELECT COUNT(*) as c FROM findings WHERE assessment_id = 'ASM-SNAP-01' AND is_deleted = 0;"
    ).fetchone()
    assert initial_read["c"] == 1

    # 3. Concurrently, another thread/connection writes a new finding and commits
    def concurrent_writer():
        findings_repo.create_finding(
            FindingCreate(
                id="FND-CONCURRENT-02",
                assessmentId="ASM-SNAP-01",
                assetId="AST-001",
                ruleId="SEC-WEB-002",
                title="Concurrent Injected Finding",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
            )
        )

    t = threading.Thread(target=concurrent_writer)
    t.start()
    t.join(timeout=5)

    # 4. Continue reading on the original snapshot connection
    snapshot_findings = read_conn.execute(
        "SELECT * FROM findings WHERE assessment_id = 'ASM-SNAP-01' AND is_deleted = 0;"
    ).fetchall()
    read_conn.execute("COMMIT;")
    read_conn.close()

    # The snapshot connection must see ONLY the 1 initial finding, isolated from the concurrent commit
    assert len(snapshot_findings) == 1
    assert snapshot_findings[0]["id"] == "FND-INITIAL-01"

    # 5. A subsequent fresh report dataset fetch now sees both findings
    _, _, _, fresh_findings, _, _ = fetch_consistent_report_dataset(db_file, "ASM-SNAP-01")
    assert len(fresh_findings) == 2


def test_report_empty_state_truthfulness(reports_sandbox):
    """Verify that an empty assessment generates truthful empty sections with zero synthetic fixtures."""
    _seed_base_data(reports_sandbox, eng_id="ENG-EMPTY", asm_id="ASM-EMPTY")
    db_file = reports_sandbox["db_file"]
    client = reports_sandbox["client"]

    # Delete the seeded scope item so it's completely empty
    reports_sandbox["scope_repo"].soft_delete_scope_item("SCP-ENG-EMPTY")

    # Fetch report via API
    resp_md = client.get("/api/v1/reports/ASM-EMPTY/markdown")
    assert resp_md.status_code == 200
    md = resp_md.text

    assert "A total of **0** finding(s)" in md
    assert "*No security vulnerabilities were identified in the assessed scope.*" in md
    assert "ENG-001" not in md  # No lab fixtures injected

    resp_html = client.get("/api/v1/reports/ASM-EMPTY/html")
    assert resp_html.status_code == 200
    assert "Content-Security-Policy" in resp_html.headers
    assert "default-src 'none'" in resp_html.headers["Content-Security-Policy"]


def test_report_includes_check_executions(reports_sandbox):
    """Verify that check execution records are read from the SQLite snapshot and rendered in the report."""
    _seed_base_data(reports_sandbox, eng_id="ENG-EXEC-REP", asm_id="ASM-EXEC-REP")
    db_file = reports_sandbox["db_file"]
    exec_repo = reports_sandbox["exec_repo"]
    client = reports_sandbox["client"]

    exec_record = CheckExecution(
        id="CHK-AUDIT-SNAP-01",
        assessmentId="ASM-EXEC-REP",
        ruleId="SEC-WEB-001",
        target="example.com",
        scopeDecision=ScopeDecision.ALLOW,
        status=ExecutionStatus.PASS,
        durationMs=42,
        requestFingerprint="fp_audit",
    )
    exec_repo.record_execution(exec_record)

    # Fetch report
    resp = client.get("/api/v1/reports/ASM-EXEC-REP/markdown")
    assert resp.status_code == 200
    md = resp.text

    assert "CHK-AUDIT-SNAP-01" in md
    assert "SEC-WEB-001" in md
    assert "42ms" in md
    assert "ALLOW" in md
    assert "PASS" in md
