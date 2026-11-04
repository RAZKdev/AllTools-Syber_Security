import hashlib
import time
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.core.database_init import initialize_database
from app.core.storage_paths import StoragePaths
from app.repositories.sqlite_scope_repository import SqliteScopeRepository
from app.repositories.sqlite_findings_repository import SqliteFindingsRepository
from app.repositories.sqlite_evidence_repository import SqliteEvidenceRepository
from app.schemas.assessment import AssessmentCreate
from app.schemas.engagement import EngagementCreate
from app.schemas.evidence import EvidenceType
from app.services.durable_evidence_writer import (
    DurableEvidenceWriter,
    EvidenceCollisionError,
    EvidenceIntegrityError,
)


@pytest.fixture
def writer_env(tmp_path: Path):
    data_dir = tmp_path / "alltools_data"
    data_dir.mkdir(parents=True)
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
    evidence_repo = SqliteEvidenceRepository(db_path=paths.database_file)

    eng = scope_repo.create_engagement(
        EngagementCreate(
            name="Writer Test Engagement",
            client="Writer Corp",
            startDate=datetime.now(timezone.utc),
            endDate=datetime.now(timezone.utc) + timedelta(days=7),
            workspaceId="WKS-WRITER-01",
        )
    )
    asm = scope_repo.create_assessment(
        AssessmentCreate(
            engagementId=eng.id,
            name="Writer Test Assessment",
            type="web",
        )
    )

    writer = DurableEvidenceWriter(paths=paths, evidence_repo=evidence_repo)
    return {
        "paths": paths,
        "writer": writer,
        "evidence_repo": evidence_repo,
        "assessment": asm,
    }


def test_durable_write_state_machine_success(writer_env):
    writer: DurableEvidenceWriter = writer_env["writer"]
    repo: SqliteEvidenceRepository = writer_env["evidence_repo"]
    asm = writer_env["assessment"]
    paths: StoragePaths = writer_env["paths"]

    raw_payload = {"status": "ok", "target": "https://api.internal.local"}
    ev = writer.write_evidence(
        assessment_id=asm.id,
        evidence_type=EvidenceType.JSON_RESULT,
        source="https://api.internal.local",
        raw_content=raw_payload,
        notes="Automated check result",
    )

    # 1. Returned record is COMMITTED
    assert ev.id.startswith("EVD-")
    assert ev.syncStatus == "COMMITTED"
    assert len(ev.sha256) == 64

    # 2. Disk file physically exists in evidence_dir / asm.id
    dest_file = paths.evidence_dir / asm.id / f"{ev.id}.json"
    assert dest_file.is_file()

    # 3. Checksum matches disk bytes exactly
    disk_bytes = dest_file.read_bytes()
    assert hashlib.sha256(disk_bytes).hexdigest() == ev.sha256

    # 4. Database record is persisted with matching fields
    db_record = repo.get_evidence(ev.id)
    assert db_record is not None
    assert db_record.sha256 == ev.sha256
    assert db_record.syncStatus == "COMMITTED"

    # 5. Staging directory has no leftover temp files
    staging_files = list(writer.staging_dir.glob("*.tmp"))
    assert len(staging_files) == 0


def test_durable_write_sensitive_redaction(writer_env):
    writer: DurableEvidenceWriter = writer_env["writer"]
    asm = writer_env["assessment"]
    paths: StoragePaths = writer_env["paths"]

    sensitive_content = {
        "auth": "Bearer secret_api_token_1234567890_abcdef",
        "cookie": "Set-Cookie: session_user_id=SECRET_SESSION_9988; Secure",
    }
    ev = writer.write_evidence(
        assessment_id=asm.id,
        evidence_type=EvidenceType.HTTP_RESPONSE,
        source="https://auth.internal.local",
        raw_content=sensitive_content,
    )

    assert ev.redacted is True
    dest_file = paths.evidence_dir / asm.id / f"{ev.id}.json"
    content_text = dest_file.read_text(encoding="utf-8")
    assert "secret_api_token" not in content_text
    assert "[REDACTED_TOKEN]" in content_text
    assert "SECRET_SESSION_9988" not in content_text


def test_durable_write_collision_protection(writer_env):
    writer: DurableEvidenceWriter = writer_env["writer"]
    asm = writer_env["assessment"]
    paths: StoragePaths = writer_env["paths"]

    # Pre-create artifact file on disk
    dest_dir = paths.evidence_dir / asm.id
    dest_dir.mkdir(parents=True, exist_ok=True)
    colliding_file = dest_dir / "EVD-COLLISION.json"
    colliding_file.write_text("existing content", encoding="utf-8")

    # Attempt to write with colliding ID must fail closed
    with pytest.raises(EvidenceCollisionError, match="already exists"):
        writer.write_evidence(
            assessment_id=asm.id,
            evidence_type=EvidenceType.JSON_RESULT,
            source="test",
            raw_content="new content",
            evidence_id="EVD-COLLISION",
        )

    # Pre-existing file is completely unmodified
    assert colliding_file.read_text(encoding="utf-8") == "existing content"


def test_cleanup_stale_staging_and_reconciliation(writer_env):
    writer: DurableEvidenceWriter = writer_env["writer"]
    repo: SqliteEvidenceRepository = writer_env["evidence_repo"]
    asm = writer_env["assessment"]
    paths: StoragePaths = writer_env["paths"]

    # 1. Create a stale temporary file in .staging
    stale_tmp = writer.staging_dir / "stale_temp_file.tmp"
    stale_tmp.write_text("abandoned temp content", encoding="utf-8")
    # Backdate mtime by 2 hours
    old_time = time.time() - 7200
    import os
    os.utime(stale_tmp, (old_time, old_time))

    # 2. Create a stranded PREPARED record in database whose destination file exists
    test_ev_id = "EVD-STRANDED-01"
    dest_file = paths.evidence_dir / asm.id / f"{test_ev_id}.json"
    dest_file.parent.mkdir(parents=True, exist_ok=True)
    file_bytes = b'{"stranded": "data"}'
    dest_file.write_bytes(file_bytes)
    file_sha = hashlib.sha256(file_bytes).hexdigest()

    from app.schemas.evidence import EvidenceCreate
    repo.create_evidence(
        EvidenceCreate(
            id=test_ev_id,
            assessmentId=asm.id,
            type=EvidenceType.JSON_RESULT,
            source="test",
            artifactPath=str(dest_file.relative_to(paths.data_dir)).replace("\\", "/"),
            sha256=file_sha,
            syncStatus="PREPARED",
        ),
        sync_status="PREPARED",
    )

    # 3. Create another stranded PREPARED record whose file is completely missing
    missing_ev_id = "EVD-STRANDED-02"
    repo.create_evidence(
        EvidenceCreate(
            id=missing_ev_id,
            assessmentId=asm.id,
            type=EvidenceType.JSON_RESULT,
            source="test",
            artifactPath=f"evidence/{asm.id}/{missing_ev_id}.json",
            sha256="0" * 64,
            syncStatus="PREPARED",
        ),
        sync_status="PREPARED",
    )

    # Run cleanup
    cleaned = writer.cleanup_stale_staging(max_age_seconds=3600)
    assert cleaned == 1
    assert not stale_tmp.exists()

    # Reconciled stranded records
    rec1 = repo.get_evidence(test_ev_id)
    assert rec1.syncStatus == "COMMITTED"

    rec2 = repo.get_evidence(missing_ev_id)
    assert rec2.syncStatus == "MISSING_FILE"
