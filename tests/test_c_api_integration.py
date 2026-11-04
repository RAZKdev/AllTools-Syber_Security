import glob
import os
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from fastapi.testclient import TestClient

from app.core.database_init import initialize_database
from app.core.storage_paths import StoragePaths
from app.dependencies import (
    get_db_path,
    get_evidence_repository,
    get_execution_repository,
    get_findings_repository,
    get_scope_repository,
)
from app.main import app
from app.repositories.sqlite_scope_repository import SqliteScopeRepository
from app.repositories.sqlite_findings_repository import SqliteFindingsRepository
from app.repositories.sqlite_execution_repository import SqliteExecutionRepository
from app.repositories.sqlite_evidence_repository import SqliteEvidenceRepository
from app.schemas.assessment import AssessmentCreate, AssessmentStatus
from app.schemas.engagement import EngagementCreate, EngagementStatus
from app.schemas.scope import ScopeItemCreate, ScopeType


@pytest.fixture
def c_api_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    data_dir = tmp_path / "c_api_data"
    data_dir.mkdir(parents=True)
    monkeypatch.setenv("ALLTOOLS_DATA_DIR", str(data_dir))
    paths = StoragePaths(
        data_dir=data_dir,
        database_file=data_dir / "workbench.db",
        evidence_dir=data_dir / "evidence",
        quarantine_dir=data_dir / "quarantine",
        backups_dir=data_dir / "backups",
    )
    paths.evidence_dir.mkdir(parents=True)
    paths.quarantine_dir.mkdir(parents=True)
    paths.backups_dir.mkdir(parents=True)

    initialize_database(db_path=paths.database_file)

    scope_repo = SqliteScopeRepository(db_path=paths.database_file)
    exec_repo = SqliteExecutionRepository(db_path=paths.database_file)
    findings_repo = SqliteFindingsRepository(db_path=paths.database_file)
    evidence_repo = SqliteEvidenceRepository(db_path=paths.database_file)

    # Seed engagement, assessment, and authorized scope rule
    now = datetime.now(timezone.utc)
    eng = scope_repo.create_engagement(
        EngagementCreate(
            name="API Test Engagement",
            client="Cyber Corp",
            startDate=now,
            endDate=now + timedelta(days=7),
            workspaceId="WKS-C-API",
            status=EngagementStatus.ACTIVE,
        )
    )
    asm = scope_repo.create_assessment(
        AssessmentCreate(
            engagementId=eng.id,
            name="API Test Assessment",
            type="web",
            status=AssessmentStatus.RUNNING,
        )
    )
    scp = scope_repo.create_scope_item(
        ScopeItemCreate(
            engagementId=eng.id,
            type=ScopeType.DOMAIN,
            value="target.local",
            notes="Authorized target",
        )
    )

    # Dependency overrides
    app.dependency_overrides[get_db_path] = lambda: paths.database_file
    app.dependency_overrides[get_scope_repository] = lambda: scope_repo
    app.dependency_overrides[get_execution_repository] = lambda: exec_repo
    app.dependency_overrides[get_findings_repository] = lambda: findings_repo
    app.dependency_overrides[get_evidence_repository] = lambda: evidence_repo

    client = TestClient(app)

    yield {
        "client": client,
        "paths": paths,
        "scope_repo": scope_repo,
        "evidence_repo": evidence_repo,
        "engagement": eng,
        "assessment": asm,
    }

    app.dependency_overrides.clear()


def test_executions_run_produces_persisted_evidence(c_api_env):
    client: TestClient = c_api_env["client"]
    evidence_repo: SqliteEvidenceRepository = c_api_env["evidence_repo"]
    asm = c_api_env["assessment"]
    paths: StoragePaths = c_api_env["paths"]

    # Execute SEC-WEB-001 with simulated headers
    resp = client.post(
        "/api/v1/executions/run",
        json={
            "assessmentId": asm.id,
            "ruleId": "SEC-WEB-001",
            "target": "target.local",
            "simulatedData": {
                "server": "nginx/1.20",
                "content-type": "text/html",
            },
        },
    )
    if resp.status_code != 200:
        print("RESP ERROR:", resp.status_code, resp.text)
    assert resp.status_code == 200
    data = resp.json()
    assert data["allowed"] is True

    # Verify evidence was recorded in SQLite
    ev_records = evidence_repo.list_evidence(assessment_id=asm.id)
    assert len(ev_records) == 1
    ev = ev_records[0]
    assert ev.assessmentId == asm.id
    assert ev.syncStatus == "COMMITTED"
    assert ev.findingId is not None

    # Verify evidence physical file exists in configured data_dir/evidence
    evidence_file = paths.data_dir / ev.artifactPath
    assert evidence_file.is_file()

    # Query GET /evidence API
    list_resp = client.get(f"/api/v1/evidence?assessmentId={asm.id}")
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert len(items) == 1
    assert items[0]["id"] == ev.id

    # Query GET /evidence/{id} API
    detail_resp = client.get(f"/api/v1/evidence/{ev.id}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["id"] == ev.id


def test_reports_includes_sqlite_evidence_in_snapshot(c_api_env):
    client: TestClient = c_api_env["client"]
    evidence_repo: SqliteEvidenceRepository = c_api_env["evidence_repo"]
    asm = c_api_env["assessment"]

    # Run check to generate finding and evidence
    client.post(
        "/api/v1/executions/run",
        json={
            "assessmentId": asm.id,
            "ruleId": "SEC-WEB-001",
            "target": "target.local",
            "simulatedData": {
                "server": "nginx",
                "content-type": "text/html",
            },
        },
    )

    # Fetch markdown report
    report_resp = client.get(f"/api/v1/reports/{asm.id}/markdown")
    assert report_resp.status_code == 200
    md = report_resp.text

    assert "## 7. Cryptographic Evidence Log" in md
    ev_record = evidence_repo.list_evidence(assessment_id=asm.id)[0]
    assert ev_record.id in md
    assert ev_record.sha256[:16] in md


def test_legacy_evidence_files_remain_untouched():
    """
    Strict Verification: Exactly zero files in database/evidence/ were deleted,
    moved, or adopted by Phase C operations.
    """
    legacy_files = glob.glob("database/evidence/**/*", recursive=True)
    legacy_files = [f for f in legacy_files if os.path.isfile(f)]

    # Confirm ASM-001 and ASM-01 are intact
    asm_001 = [f for f in legacy_files if "ASM-001" in f]
    asm_01 = [f for f in legacy_files if "ASM-01" in f]

    assert len(asm_001) == 3, f"Expected 3 legacy ASM-001 files, found {len(asm_001)}"
    assert len(asm_01) == 52, f"Expected 52 legacy ASM-01 files, found {len(asm_01)}"
