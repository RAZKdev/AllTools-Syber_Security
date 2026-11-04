import hashlib
import json
import os
import shutil
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
import uuid
from unittest.mock import patch, MagicMock
import pytest

from app.core.database import create_connection
from app.core.database_init import initialize_database
from app.core.instance_lock import InstanceLock, ProcessLockError
from app.core.storage_paths import StoragePaths
from app.core.write_fence import WriteFence, global_backup_hold, global_write_fence
from app.repositories.sqlite_backup_repository import SqliteBackupRepository
from app.repositories.sqlite_evidence_repository import SqliteEvidenceRepository
from app.repositories.sqlite_quarantine_repository import SqliteQuarantineRepository
from app.repositories.sqlite_scope_repository import SqliteScopeRepository
from app.schemas.assessment import AssessmentCreate
from app.schemas.backup import BackupFileEntry, BackupManifest, BackupStatus
from app.schemas.engagement import EngagementCreate
from app.schemas.evidence import EvidenceType
from app.schemas.quarantine import QuarantineReason
from app.services.backup_engine import (
    BackupCollisionError,
    BackupEngine,
    BackupError,
    BackupIntegrityError,
    InsufficientDiskSpaceError,
)
from app.services.durable_evidence_writer import DurableEvidenceWriter
from app.services.quarantine_service import QuarantineError, QuarantineService
from app.services.restore_engine import (
    MaintenanceLockError,
    ProductionCutoverDisabledError,
    ProductionCutoverError,
    RestoreEngine,
    RestoreError,
    RestoreValidationError,
)


@pytest.fixture
def backup_test_env(tmp_path: Path):
    """
    Creates an isolated operational environment with:
    - Initialized SQLite database.
    - Active Engagement and Assessment.
    - Written and published evidence artifact.
    - Quarantined artifact with manifest hash chain.
    - Dedicated StoragePaths and BackupEngine.
    """
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
    quarantine_repo = SqliteQuarantineRepository(db_path=paths.database_file)
    quarantine_svc = QuarantineService(paths=paths, quarantine_repo=quarantine_repo)
    backup_repo = SqliteBackupRepository(db_path=paths.database_file)

    eng = scope_repo.create_engagement(
        EngagementCreate(
            name="Backup Test Engagement",
            client="Cyber Corp",
            startDate=datetime.now(timezone.utc),
            endDate=datetime.now(timezone.utc) + timedelta(days=7),
            workspaceId="WKS-BKP-01",
        )
    )
    asm = scope_repo.create_assessment(
        AssessmentCreate(
            engagementId=eng.id,
            name="Backup Test Assessment",
            type="web",
        )
    )

    # 1. Write an active evidence file via DurableEvidenceWriter
    writer = DurableEvidenceWriter(paths=paths, evidence_repo=evidence_repo)
    sample_content = '{"nmap_output": "open ports: 80, 443", "status": "verified"}'
    ev_record = writer.write_evidence(
        assessment_id=asm.id,
        evidence_type=EvidenceType.RAW_OUTPUT,
        source="nmap",
        raw_content=sample_content,
        notes="nmap scan evidence for backup test",
    )

    # 2. Write a quarantined item with valid tamper-evident hash chain
    corrupt_source = paths.data_dir / "temp_corrupt_file.bin"
    corrupt_source.write_bytes(b"corrupted payload data")
    quarantine_svc.quarantine_file(
        source_path=corrupt_source,
        reason=QuarantineReason.HASH_MISMATCH,
        details="Checksum failure detected during reconciliation",
    )

    engine = BackupEngine(paths=paths, backup_repo=backup_repo, write_fence=global_write_fence)
    restore_eng = RestoreEngine(paths=paths)

    return {
        "paths": paths,
        "backup_repo": backup_repo,
        "evidence_repo": evidence_repo,
        "quarantine_repo": quarantine_repo,
        "scope_repo": scope_repo,
        "engine": engine,
        "restore_engine": restore_eng,
        "engagement": eng,
        "assessment": asm,
        "evidence": ev_record,
        "quarantine_service": quarantine_svc,
    }


def test_backup_creation_and_atomic_promotion(backup_test_env):
    """
    Test full hot backup creation:
    - Preflight disk space verification.
    - Write-fence snapshot of SQLite database.
    - Background streaming copying of evidence and quarantine files.
    - Manifest generation with integrity info and SHA-256 digests.
    - Atomic promotion from .staging to final backup directory.
    - Repository record transitioned to COMPLETED.
    """
    engine: BackupEngine = backup_test_env["engine"]
    paths: StoragePaths = backup_test_env["paths"]
    backup_repo: SqliteBackupRepository = backup_test_env["backup_repo"]

    manifest = engine.create_backup(generation_id="BKP-20261101-001")

    assert manifest.generationId == "BKP-20261101-001"
    assert manifest.backupFormatVersion == "1.0"
    assert manifest.schemaVersion >= 1
    assert manifest.databaseIntegrity is not None
    assert manifest.databaseIntegrity.quickCheck == "ok"
    assert manifest.databaseIntegrity.pageCount > 0
    assert manifest.totalBytes > 0
    assert manifest.manifestSha256 is not None
    assert manifest.coordinationDurationMs >= 0

    # Verify backup directory structure on disk
    final_backup_dir = paths.backups_dir / "BKP-20261101-001"
    assert final_backup_dir.exists()
    assert (final_backup_dir / "database" / "workbench.db").exists()
    assert (final_backup_dir / "backup_manifest.json").exists()
    assert (final_backup_dir / "quarantine" / "quarantine_manifest.jsonl").exists()

    # Verify staging cleanup
    staging_dir = paths.backups_dir / ".staging"
    assert len(list(staging_dir.glob("*.tmp"))) == 0

    # Verify repository record
    record = backup_repo.get_backup("BKP-20261101-001")
    assert record is not None
    assert record.status == BackupStatus.COMPLETED
    assert record.manifestSha256 == manifest.manifestSha256
    assert record.byteSize == manifest.totalBytes
    assert record.evidenceCount >= 1
    assert record.quarantineCount >= 1

    # Verify each file listed in manifest exists and matches size and SHA-256
    for entry in manifest.files:
        p = final_backup_dir / entry.path
        assert p.exists(), f"File {entry.path} must exist in backup"
        hasher = hashlib.sha256()
        with open(p, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        assert hasher.hexdigest() == entry.sha256
        assert p.stat().st_size == entry.byteSize


def test_write_fence_coordination_and_target_timing(backup_test_env):
    """
    Test write-fence behavior:
    - Coordination barrier (< 500 ms target).
    - Concurrent in-flight writes block during the fence and resume after release.
    - Reports coordination duration.
    """
    fence = WriteFence()
    write_executed = []

    # 1. Normal write execution acquires fence without issue
    with fence.acquire_write():
        write_executed.append("write_1")
    assert "write_1" in write_executed

    # 2. Fence blocks writers during snapshot coordination
    start_time = time.perf_counter()
    with fence.fence_writes(timeout_ms=500) as info:
        elapsed_coordination = (time.perf_counter() - start_time) * 1000
        assert elapsed_coordination < 500
        assert "coordination_duration_ms" in info
        assert fence.is_fenced

    # 3. Writers resume after fence is released
    assert not fence.is_fenced
    with fence.acquire_write():
        write_executed.append("write_2")
    assert "write_2" in write_executed


def test_preflight_insufficient_disk_space(backup_test_env, monkeypatch):
    """
    ADR-06 requirement: Fail closed with InsufficientDiskSpaceError if available
    disk space is less than 2x estimated backup size.
    """
    engine: BackupEngine = backup_test_env["engine"]
    paths: StoragePaths = backup_test_env["paths"]

    # Mock shutil.disk_usage to report only 512 bytes free
    import shutil
    from collections import namedtuple
    DiskUsage = namedtuple("DiskUsage", ["total", "used", "free"])
    monkeypatch.setattr(shutil, "disk_usage", lambda p: DiskUsage(total=10**9, used=10**9 - 512, free=512))

    with pytest.raises(InsufficientDiskSpaceError) as exc_info:
        engine.create_backup(generation_id="BKP-NO-DISK")

    assert "less than required 2x estimated backup size" in str(exc_info.value)

    # Verify no backup directory or staged files were created
    assert not (paths.backups_dir / "BKP-NO-DISK").exists()
    assert len(list((paths.backups_dir / ".staging").glob("*.tmp"))) == 0


def test_backup_collision_protection(backup_test_env):
    """
    Verify BackupCollisionError is raised if the target backup directory already exists,
    preventing accidental overwriting of completed snapshots.
    """
    engine: BackupEngine = backup_test_env["engine"]
    paths: StoragePaths = backup_test_env["paths"]

    colliding_dir = paths.backups_dir / "BKP-EXISTING-01"
    colliding_dir.mkdir(parents=True)

    with pytest.raises(BackupCollisionError) as exc_info:
        engine.create_backup(generation_id="BKP-EXISTING-01")

    assert "Backup directory already exists" in str(exc_info.value)
    # Staging cleaned up
    assert len(list((paths.backups_dir / ".staging").glob("*.tmp"))) == 0


def test_interrupted_backup_recovery(backup_test_env):
    """
    Verify cleanup_stale_staging scans and deletes abandoned staging .tmp directories
    and marks stranded IN_PROGRESS database records as FAILED.
    """
    engine: BackupEngine = backup_test_env["engine"]
    paths: StoragePaths = backup_test_env["paths"]
    backup_repo: SqliteBackupRepository = backup_test_env["backup_repo"]

    # 1. Create a stranded IN_PROGRESS record
    backup_repo.record_backup_started("BKP-STRANDED-999", sqlite_data_version=1)
    rec_before = backup_repo.get_backup("BKP-STRANDED-999")
    assert rec_before.status == BackupStatus.IN_PROGRESS

    # 2. Create an abandoned staging temp directory
    stale_tmp = paths.backups_dir / ".staging" / "BKP-STRANDED-999_abandoned.tmp"
    stale_tmp.mkdir(parents=True)
    (stale_tmp / "dummy.dat").write_bytes(b"temp data")

    # 3. Run stale staging cleanup with max_age_seconds=0
    cleaned_count = engine.cleanup_stale_staging(max_age_seconds=0)
    assert cleaned_count == 1
    assert not stale_tmp.exists()

    # 4. Verify stranded database record marked FAILED
    rec_after = backup_repo.get_backup("BKP-STRANDED-999")
    assert rec_after.status == BackupStatus.FAILED


def test_atomic_promotion_verification_failure(backup_test_env, monkeypatch):
    """
    Verify that if a staged file is corrupted or modified before atomic promotion,
    the pre-promotion integrity check fails, staging is cleaned up, and record is marked FAILED.
    """
    engine: BackupEngine = backup_test_env["engine"]
    paths: StoragePaths = backup_test_env["paths"]
    backup_repo: SqliteBackupRepository = backup_test_env["backup_repo"]

    original_stream_copy = BackupEngine._stream_copy_with_hash

    # Inject corruption: tamper with copied file after copying into staging
    def corrupted_stream_copy(src, dest):
        sha, size = original_stream_copy(src, dest)
        # Append corrupt byte after hashing so stored hash does not match file
        with open(dest, "ab") as f:
            f.write(b"CORRUPTION")
        return sha, size

    monkeypatch.setattr(BackupEngine, "_stream_copy_with_hash", staticmethod(corrupted_stream_copy))

    with pytest.raises(BackupIntegrityError) as exc_info:
        engine.create_backup(generation_id="BKP-TAMPERED-01")

    assert "checksum mismatch" in str(exc_info.value).lower()
    # Backup directory must not exist
    assert not (paths.backups_dir / "BKP-TAMPERED-01").exists()
    # Staging must be cleaned up
    assert len(list((paths.backups_dir / ".staging").glob("*.tmp"))) == 0


def test_retention_and_last_known_good_protection(backup_test_env):
    """
    ADR-06 retention enforcement:
    - Retains maximum N completed snapshots (default 10).
    - Prunes oldest verified backups first.
    - NEVER deletes the last known-good backup even if retention is 0.
    """
    engine: BackupEngine = backup_test_env["engine"]
    paths: StoragePaths = backup_test_env["paths"]
    backup_repo: SqliteBackupRepository = backup_test_env["backup_repo"]

    # Create 12 completed backups
    created_ids = []
    for i in range(1, 13):
        gen_id = f"BKP-RET-{i:03d}"
        engine.create_backup(generation_id=gen_id, retention_limit=10)
        created_ids.append(gen_id)

    # After creating 12 backups with retention_limit=10:
    # 2 oldest (BKP-RET-001 and BKP-RET-002) should have been pruned
    remaining = backup_repo.list_backups(status=BackupStatus.COMPLETED)
    assert len(remaining) == 10
    remaining_ids = {b.id for b in remaining}
    assert "BKP-RET-001" not in remaining_ids
    assert "BKP-RET-002" not in remaining_ids
    assert not (paths.backups_dir / "BKP-RET-001").exists()
    assert not (paths.backups_dir / "BKP-RET-002").exists()
    assert "BKP-RET-012" in remaining_ids
    assert (paths.backups_dir / "BKP-RET-012").exists()

    # Invariant: Never delete the last known-good backup
    # Try enforcing retention limit = 0
    engine._enforce_retention(retention_limit=0)
    final_remaining = backup_repo.list_backups(status=BackupStatus.COMPLETED)
    # At least 1 backup must be preserved
    assert len(final_remaining) == 1
    last_known_good = backup_repo.get_last_known_good_backup()
    assert last_known_good is not None
    assert (paths.backups_dir / last_known_good.id).exists()


def test_restore_engine_validation_and_clean_restore(backup_test_env, tmp_path: Path):
    """
    Test RestoreEngine:
    - Deep pre-flight validation succeeds on authentic backup.
    - Full clean restore into an isolated destination directory.
    - Post-restore database integrity check and data verification.
    """
    engine: BackupEngine = backup_test_env["engine"]
    paths: StoragePaths = backup_test_env["paths"]
    restore_eng: RestoreEngine = backup_test_env["restore_engine"]

    gen_id = "BKP-FOR-RESTORE"
    manifest = engine.create_backup(generation_id=gen_id)
    backup_dir = paths.backups_dir / gen_id

    # 1. Pre-flight validation
    is_valid, errors, validated_manifest = restore_eng.validate_backup(backup_dir)
    assert is_valid is True
    assert len(errors) == 0
    assert validated_manifest is not None
    assert validated_manifest.generationId == gen_id

    # 2. Restore into isolated destination directory
    restore_target = tmp_path / "restored_system"
    summary = restore_eng.restore_backup(
        backup_dir=backup_dir,
        target_dir=restore_target,
        confirm_production_overwrite=False,
    )

    assert summary.generation_id == gen_id
    assert summary.restored_files_count == len(manifest.files)
    assert summary.database_verified is True
    assert summary.manifest_verified is True
    assert summary.quarantine_verified is True

    # 3. Verify restored files on disk
    restored_db = restore_target / "workbench.db"
    assert restored_db.exists()

    # Query restored SQLite database
    conn = create_connection(restored_db)
    try:
        check = conn.execute("PRAGMA quick_check;").fetchone()[0]
        assert check == "ok"

        # Verify engagements restored
        engs = conn.execute("SELECT id, name FROM engagements;").fetchall()
        assert len(engs) == 1
        assert engs[0]["name"] == "Backup Test Engagement"

        # Verify evidence restored
        ev_rows = conn.execute("SELECT id, artifact_path, sha256 FROM evidence;").fetchall()
        assert len(ev_rows) >= 1
        for row in ev_rows:
            art_file = restore_target / row["artifact_path"]
            assert art_file.exists()
            assert hashlib.sha256(art_file.read_bytes()).hexdigest() == row["sha256"]

        # Verify quarantine restored
        q_manifest = restore_target / "quarantine" / "quarantine_manifest.jsonl"
        assert q_manifest.exists()
    finally:
        conn.close()


def test_restore_engine_tamper_detection(backup_test_env):
    """
    Test RestoreEngine tamper detection:
    - Checksum mismatch detection.
    - Missing file detection.
    - Manifest JSON corruption detection.
    - Path traversal rejection.
    - Quarantine hash chain corruption detection.
    """
    engine: BackupEngine = backup_test_env["engine"]
    paths: StoragePaths = backup_test_env["paths"]
    restore_eng: RestoreEngine = backup_test_env["restore_engine"]

    gen_id = "BKP-TAMPER-TEST"
    engine.create_backup(generation_id=gen_id)
    backup_dir = paths.backups_dir / gen_id

    # Case 1: Tampered database byte
    db_file = backup_dir / "database" / "workbench.db"
    orig_db_bytes = db_file.read_bytes()
    try:
        with open(db_file, "r+b") as f:
            f.seek(100)
            f.write(b"\xFF\xFF")
        valid, errors, _ = restore_eng.validate_backup(backup_dir)
        assert valid is False
        assert any("checksum mismatch for 'database/workbench.db'" in e.lower() for e in errors)
    finally:
        db_file.write_bytes(orig_db_bytes)

    # Case 2: Missing evidence file
    manifest_p = backup_dir / "backup_manifest.json"
    manifest_data = json.loads(manifest_p.read_text(encoding="utf-8"))
    ev_entry = next(f for f in manifest_data["files"] if f["path"].startswith("evidence/"))
    ev_file = backup_dir / ev_entry["path"]
    orig_ev_bytes = ev_file.read_bytes()
    try:
        ev_file.unlink()
        valid, errors, _ = restore_eng.validate_backup(backup_dir)
        assert valid is False
        assert any("missing file" in e.lower() for e in errors)
    finally:
        ev_file.write_bytes(orig_ev_bytes)

    # Case 3: Malformed manifest JSON
    orig_manifest_text = manifest_p.read_text(encoding="utf-8")
    try:
        manifest_p.write_text("INVALID JSON NOT A DICT", encoding="utf-8")
        valid, errors, _ = restore_eng.validate_backup(backup_dir)
        assert valid is False
        assert any("failed to parse backup_manifest.json" in e.lower() for e in errors)
    finally:
        manifest_p.write_text(orig_manifest_text, encoding="utf-8")

    # Case 4: Path traversal in manifest
    try:
        traversal_manifest = json.loads(orig_manifest_text)
        traversal_manifest["files"].append({
            "path": "../evil.txt",
            "byteSize": 10,
            "sha256": "0" * 64,
        })
        manifest_p.write_text(json.dumps(traversal_manifest), encoding="utf-8")
        valid, errors, _ = restore_eng.validate_backup(backup_dir)
        assert valid is False
        assert any("illegal path traversal" in e.lower() for e in errors)
    finally:
        manifest_p.write_text(orig_manifest_text, encoding="utf-8")

    # Case 5: Broken quarantine manifest hash chain
    qm_file = backup_dir / "quarantine" / "quarantine_manifest.jsonl"
    orig_qm_text = qm_file.read_text(encoding="utf-8")
    try:
        lines = orig_qm_text.strip().splitlines()
        first_entry = json.loads(lines[0])
        first_entry["entryHash"] = "a" * 64  # Corrupt entryHash
        qm_file.write_text(json.dumps(first_entry) + "\n", encoding="utf-8")

        # Also update manifest sha for quarantine_manifest so file checksum matches
        hasher = hashlib.sha256(qm_file.read_bytes())
        updated_manifest = json.loads(orig_manifest_text)
        for f in updated_manifest["files"]:
            if f["path"] == "quarantine/quarantine_manifest.jsonl":
                f["sha256"] = hasher.hexdigest()
                f["byteSize"] = qm_file.stat().st_size
        manifest_p.write_text(json.dumps(updated_manifest), encoding="utf-8")

        valid, errors, _ = restore_eng.validate_backup(backup_dir)
        assert valid is False
        assert any("quarantine manifest" in e.lower() for e in errors)
    finally:
        qm_file.write_text(orig_qm_text, encoding="utf-8")
        manifest_p.write_text(orig_manifest_text, encoding="utf-8")


def test_restore_production_overwrite_guard(backup_test_env):
    """
    P0 Safety Containment (ADR-06, F-02):
    Verify that all attempts to restore into the active production data directory
    are rejected fail-closed with ProductionCutoverDisabledError, even when
    confirm_production_overwrite=True is supplied.
    """
    engine: BackupEngine = backup_test_env["engine"]
    paths: StoragePaths = backup_test_env["paths"]
    restore_eng: RestoreEngine = backup_test_env["restore_engine"]

    gen_id = "BKP-GUARD-TEST"
    engine.create_backup(generation_id=gen_id)
    backup_dir = paths.backups_dir / gen_id

    orig_db_sha = hashlib.sha256(paths.database_file.read_bytes()).hexdigest()
    orig_db_mtime = paths.database_file.stat().st_mtime_ns

    # 1. Refused without confirm_production_overwrite
    with pytest.raises(ProductionCutoverDisabledError) as exc_info:
        restore_eng.restore_backup(
            backup_dir=backup_dir,
            target_dir=paths.data_dir,
            confirm_production_overwrite=False,
        )
    assert "Production restore cutover is currently disabled" in str(exc_info.value)

    # 2. Refused even WITH confirm_production_overwrite=True
    with pytest.raises(ProductionCutoverDisabledError) as exc_info2:
        restore_eng.restore_backup(
            backup_dir=backup_dir,
            target_dir=paths.data_dir,
            confirm_production_overwrite=True,
        )
    assert "Production restore cutover is currently disabled" in str(exc_info2.value)

    # Invariant: Active production files remain untouched
    assert paths.database_file.stat().st_mtime_ns == orig_db_mtime
    assert hashlib.sha256(paths.database_file.read_bytes()).hexdigest() == orig_db_sha


def test_concurrent_quarantine_and_snapshot_coordination(backup_test_env):
    """
    F-01 requirement: Quarantine mutations must synchronize with WriteFence.
    Verify that when WriteFence has writes fenced (during snapshot creation),
    a quarantine operation in another thread waits until the fence is released
    and completes successfully without corruption.
    """
    paths: StoragePaths = backup_test_env["paths"]
    quarantine_svc: QuarantineService = backup_test_env["quarantine_service"]
    fence: WriteFence = quarantine_svc.write_fence

    target_file = paths.data_dir / "threat_sample.bin"
    target_file.write_bytes(b"suspicious binary content")

    quarantine_started = threading.Event()
    quarantine_finished = threading.Event()
    thread_result = {}

    def quarantine_worker():
        quarantine_started.set()
        try:
            item = quarantine_svc.quarantine_file(
                source_path=target_file,
                reason=QuarantineReason.HASH_MISMATCH,
                details="Concurrent fence test isolation",
            )
            thread_result["item"] = item
        except Exception as e:
            thread_result["error"] = e
        finally:
            quarantine_finished.set()

    # Hold write fence
    with fence.fence_writes(timeout_ms=500):
        t = threading.Thread(target=quarantine_worker, daemon=True)
        t.start()
        quarantine_started.wait(timeout=1.0)
        time.sleep(0.1)
        assert not quarantine_finished.is_set(), "Quarantine should block while write fence is held"

    # Once fence is released, worker should complete
    quarantine_finished.wait(timeout=5.0)
    assert quarantine_finished.is_set(), "Quarantine should complete after write fence is released"
    assert "error" not in thread_result
    item = thread_result.get("item")
    assert item is not None
    assert item.reason == QuarantineReason.HASH_MISMATCH.value
    assert not target_file.exists()
    assert Path(item.quarantinePath).exists()


def test_quarantine_interruption_sqlite_ledger_rollback(backup_test_env):
    """
    F-01 requirement: Coordinated atomic quarantine.
    If database ledger recording fails after physical file isolation,
    the physical file must be rolled back to its original location,
    preventing orphaned unrecorded quarantine files.
    """
    paths: StoragePaths = backup_test_env["paths"]
    quarantine_svc: QuarantineService = backup_test_env["quarantine_service"]

    sample_file = paths.data_dir / "interrupted_quarantine.bin"
    sample_file.write_bytes(b"payload for rollback test")

    with patch.object(
        quarantine_svc.quarantine_repo,
        "record_quarantine_item",
        side_effect=sqlite3.OperationalError("Simulated database disk I/O failure"),
    ):
        with pytest.raises(QuarantineError) as exc_info:
            quarantine_svc.quarantine_file(
                source_path=sample_file,
                reason=QuarantineReason.HASH_MISMATCH,
                details="Rollback test",
            )
        assert "Simulated database disk I/O failure" in str(exc_info.value)

    assert sample_file.exists(), "Source file must be restored to original path on ledger failure"
    assert sample_file.read_bytes() == b"payload for rollback test"

    quarantined_files = list(paths.quarantine_dir.glob("*.quarantine"))
    assert len(quarantined_files) == 1  # Only the 1 from fixture


def test_quarantine_interruption_manifest_recovery(backup_test_env):
    """
    F-01 requirement: No silent loss of ledger events.
    If manifest is missing entries that exist in SQLite quarantine ledger,
    reconcile_quarantine_storage restores missing manifest entries.
    """
    paths: StoragePaths = backup_test_env["paths"]
    quarantine_svc: QuarantineService = backup_test_env["quarantine_service"]
    manifest_file = paths.quarantine_dir / "quarantine_manifest.jsonl"

    file2 = paths.data_dir / "file2.bin"
    file2.write_bytes(b"content 2")
    item2 = quarantine_svc.quarantine_file(
        source_path=file2,
        reason=QuarantineReason.MANUAL_QUARANTINE,
        details="Second item for manifest recovery test",
    )

    lines = manifest_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2

    # Simulate interruption/loss: truncate manifest so item2 is missing
    manifest_file.write_text(lines[0] + "\n", encoding="utf-8")
    assert len(manifest_file.read_text(encoding="utf-8").strip().splitlines()) == 1

    reconciled = quarantine_svc.reconcile_quarantine_storage()
    assert reconciled == 1

    restored_lines = manifest_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(restored_lines) == 2
    entry2 = json.loads(restored_lines[1])
    assert entry2["quarantineId"] == item2.quarantineId
    assert entry2["seq"] == item2.seq


def test_recovery_of_partially_completed_quarantine_operations(backup_test_env):
    """
    F-01 requirement: Recovery after interruption.
    If a process crashed after moving a file to quarantine directory but before
    recording in SQLite or manifest, reconcile_quarantine_storage discovers the
    unrecorded .quarantine artifact, adopts it into SQLite ledger, and writes manifest.
    """
    paths: StoragePaths = backup_test_env["paths"]
    quarantine_svc: QuarantineService = backup_test_env["quarantine_service"]
    quarantine_repo: SqliteQuarantineRepository = backup_test_env["quarantine_repo"]

    orphan_file = paths.quarantine_dir / "ORPHAN-CRASHED-001.quarantine"
    orphan_file.write_bytes(b"isolated file from interrupted process")

    reconciled = quarantine_svc.reconcile_quarantine_storage()
    assert reconciled >= 1

    items = quarantine_repo.list_quarantine_items()
    adopted = next((it for it in items if "ORPHAN-CRASHED-001.quarantine" in it.quarantinePath), None)
    assert adopted is not None
    assert adopted.reason == QuarantineReason.ORPHAN_NO_ASSESSMENT.value
    assert adopted.byteSize == len(b"isolated file from interrupted process")
    assert adopted.sha256 == hashlib.sha256(b"isolated file from interrupted process").hexdigest()

    manifest_file = paths.quarantine_dir / "quarantine_manifest.jsonl"
    lines = manifest_file.read_text(encoding="utf-8").strip().splitlines()
    last_entry = json.loads(lines[-1])
    assert last_entry["quarantineId"] == adopted.quarantineId


def test_restore_staging_without_production_modification(backup_test_env, tmp_path: Path):
    """
    F-02 requirement: All restores initially target an isolated staging directory.
    stage_restore must unpack and verify the snapshot without modifying active production data.
    """
    engine: BackupEngine = backup_test_env["engine"]
    paths: StoragePaths = backup_test_env["paths"]
    restore_eng: RestoreEngine = backup_test_env["restore_engine"]

    gen_id = "BKP-STAGE-ONLY"
    engine.create_backup(generation_id=gen_id)
    backup_dir = paths.backups_dir / gen_id

    orig_db_sha = hashlib.sha256(paths.database_file.read_bytes()).hexdigest()
    orig_db_mtime = paths.database_file.stat().st_mtime_ns

    staging_dir = tmp_path / "stage_test"
    summary, manifest = restore_eng.stage_restore(backup_dir, staging_dir)

    assert summary.database_verified is True
    assert (staging_dir / "workbench.db").exists()
    assert (staging_dir / "evidence").exists()
    assert (staging_dir / "quarantine").exists()

    assert paths.database_file.stat().st_mtime_ns == orig_db_mtime
    assert hashlib.sha256(paths.database_file.read_bytes()).hexdigest() == orig_db_sha


def test_production_cutover_disabled_fails_closed(backup_test_env):
    """
    P0 Safety Containment (ADR-06, F-02):
    - Rejects all attempts to replace or cut over the active production data directory.
    - confirm_production_overwrite=True CANNOT bypass the guard.
    - Invariant: Production directory is not altered, and no files are renamed or deleted.
    """
    engine: BackupEngine = backup_test_env["engine"]
    paths: StoragePaths = backup_test_env["paths"]
    restore_eng: RestoreEngine = backup_test_env["restore_engine"]
    scope_repo: SqliteScopeRepository = backup_test_env["scope_repo"]

    gen_id = "BKP-CONTAINMENT-TEST"
    engine.create_backup(generation_id=gen_id)
    backup_dir = paths.backups_dir / gen_id

    # Record active production DB fingerprint
    orig_db_sha = hashlib.sha256(paths.database_file.read_bytes()).hexdigest()
    orig_db_mtime = paths.database_file.stat().st_mtime_ns
    orig_eng_count = len(scope_repo.list_engagements())

    # 1. Calling execute_production_restore directly raises ProductionCutoverDisabledError
    with pytest.raises(ProductionCutoverDisabledError) as exc_info:
        restore_eng.execute_production_restore(
            backup_dir=backup_dir,
            confirm_production_overwrite=True,
            safety_backup=True,
        )
    assert "Production restore cutover is currently disabled" in str(exc_info.value)
    assert "crash-recovery implementation" in str(exc_info.value)

    # 2. Invariant: Production directory was NOT modified at all
    assert paths.database_file.stat().st_mtime_ns == orig_db_mtime
    assert hashlib.sha256(paths.database_file.read_bytes()).hexdigest() == orig_db_sha
    assert len(scope_repo.list_engagements()) == orig_eng_count
    # No temporary rollback folders left
    assert len(list(paths.data_dir.glob(".previous_prod_*"))) == 0


def test_production_restore_cannot_bypass_guard_via_subdirectory(backup_test_env):
    """
    P0 Safety Containment (ADR-06, F-02):
    Verify that callers cannot bypass the production restore cutover guard
    by targeting subdirectories inside the production data directory.
    """
    engine: BackupEngine = backup_test_env["engine"]
    paths: StoragePaths = backup_test_env["paths"]
    restore_eng: RestoreEngine = backup_test_env["restore_engine"]

    gen_id = "BKP-BYPASS-TEST"
    engine.create_backup(generation_id=gen_id)
    backup_dir = paths.backups_dir / gen_id

    # Attempt to target subdirectories inside production data directory
    for sub_path in [paths.evidence_dir, paths.quarantine_dir, paths.data_dir / "nested" / "sub"]:
        with pytest.raises(ProductionCutoverDisabledError) as exc_info:
            restore_eng.restore_backup(
                backup_dir=backup_dir,
                target_dir=sub_path,
                confirm_production_overwrite=True,
            )
        assert "Production restore cutover is currently disabled" in str(exc_info.value)


def test_decommissioned_cutover_fails_closed(backup_test_env):
    """
    F-02 requirement: Legacy cutover method audit & decommissioning.
    Verify that direct invocation of _execute_production_cutover_unsupported fails closed
    unconditionally, cannot modify production storage, and raises ProductionCutoverDisabledError.
    """
    engine: BackupEngine = backup_test_env["engine"]
    paths: StoragePaths = backup_test_env["paths"]
    restore_eng: RestoreEngine = backup_test_env["restore_engine"]
    scope_repo: SqliteScopeRepository = backup_test_env["scope_repo"]

    gen_id = "BKP-LEGACY-METHOD-TEST"
    engine.create_backup(generation_id=gen_id)
    backup_dir = paths.backups_dir / gen_id

    pre_db_sha = hashlib.sha256(paths.database_file.read_bytes()).hexdigest()
    pre_db_mtime = paths.database_file.stat().st_mtime_ns
    pre_eng_count = len(scope_repo.list_engagements())

    # Test all flag combinations: confirm=True, confirm=False, safety_backup=True/False
    for confirm_flag in [True, False]:
        for safety_flag in [True, False]:
            with pytest.raises(ProductionCutoverDisabledError) as exc_info:
                restore_eng._execute_production_cutover_unsupported(
                    backup_dir=backup_dir,
                    confirm_production_overwrite=confirm_flag,
                    safety_backup=safety_flag,
                )
            assert "Production restore cutover is disabled across all public and internal methods" in str(exc_info.value)

    # Invariant: Database completely untouched
    assert paths.database_file.stat().st_mtime_ns == pre_db_mtime
    assert hashlib.sha256(paths.database_file.read_bytes()).hexdigest() == pre_db_sha
    assert len(scope_repo.list_engagements()) == pre_eng_count
    # Invariant: No staging, safety backup, or rollback directories created
    assert len(list(paths.data_dir.glob(".staging_restore_*"))) == 0
    assert len(list(paths.data_dir.glob(".previous_prod_*"))) == 0
    assert len(list(paths.backups_dir.glob("BKP-SAFETY-*"))) == 0


def test_production_path_boundary_windows_cases(backup_test_env, monkeypatch):
    """
    F-02 requirement: Path boundary verification on Windows.
    Tests all 7 cases specified in P0 audit:
    1. Exact production directory
    2. Child directory inside production storage (existing and non-existing)
    3. Relative path resolving to production storage
    4. Path containing .. that resolves into production storage
    5. Symlink or junction alias pointing to production storage (where supported)
    6. Case-variant path referring to the same Windows directory
    7. Ordinary isolated directory outside production storage (allowed and succeeds)
    """
    engine: BackupEngine = backup_test_env["engine"]
    paths: StoragePaths = backup_test_env["paths"]
    restore_eng: RestoreEngine = backup_test_env["restore_engine"]

    gen_id = "BKP-PATH-MATRIX-TEST"
    engine.create_backup(generation_id=gen_id)
    backup_dir = paths.backups_dir / gen_id

    # Case 1: Exact production directory
    with pytest.raises(ProductionCutoverDisabledError):
        restore_eng.restore_backup(backup_dir, target_dir=paths.data_dir, confirm_production_overwrite=True)

    # Case 2: Child directory inside production storage
    # 2a: Existing child
    with pytest.raises(ProductionCutoverDisabledError):
        restore_eng.restore_backup(backup_dir, target_dir=paths.evidence_dir, confirm_production_overwrite=True)
    # 2b: Non-existing child
    with pytest.raises(ProductionCutoverDisabledError):
        restore_eng.restore_backup(backup_dir, target_dir=paths.data_dir / "nonexistent_subfolder", confirm_production_overwrite=True)
    # 2c: Deep non-existing child
    with pytest.raises(ProductionCutoverDisabledError):
        restore_eng.restore_backup(backup_dir, target_dir=paths.data_dir / "deep" / "nonexistent" / "path", confirm_production_overwrite=True)

    # Case 3: Relative path resolving to production storage
    # Change working directory to parent so we can construct true non-absolute relative paths
    monkeypatch.chdir(paths.data_dir.parent)
    rel_path = Path(paths.data_dir.name)
    assert not rel_path.is_absolute()
    with pytest.raises(ProductionCutoverDisabledError):
        restore_eng.restore_backup(backup_dir, target_dir=rel_path, confirm_production_overwrite=True)
    rel_child = Path(paths.data_dir.name) / "evidence"
    assert not rel_child.is_absolute()
    with pytest.raises(ProductionCutoverDisabledError):
        restore_eng.restore_backup(backup_dir, target_dir=rel_child, confirm_production_overwrite=True)

    # Case 4: Path containing .. that resolves into production storage
    rel_dotdot = Path(paths.data_dir.name) / "evidence" / ".."
    with pytest.raises(ProductionCutoverDisabledError):
        restore_eng.restore_backup(backup_dir, target_dir=rel_dotdot, confirm_production_overwrite=True)
    dotdot_child = Path(paths.data_dir.name) / "evidence" / ".." / "quarantine"
    with pytest.raises(ProductionCutoverDisabledError):
        restore_eng.restore_backup(backup_dir, target_dir=dotdot_child, confirm_production_overwrite=True)
    # Also test absolute path containing ..
    dotdot_abs = paths.evidence_dir / ".."
    with pytest.raises(ProductionCutoverDisabledError):
        restore_eng.restore_backup(backup_dir, target_dir=dotdot_abs, confirm_production_overwrite=True)

    # Case 5: Symlink or junction alias pointing to production storage
    # Test Windows directory junction
    test_junction = paths.data_dir.parent / f"junction_to_prod_{uuid.uuid4().hex[:6]}"
    try:
        import _winapi
        _winapi.CreateJunction(str(paths.data_dir), str(test_junction))
        junction_created = True
    except Exception:
        junction_created = False

    if junction_created:
        try:
            with pytest.raises(ProductionCutoverDisabledError):
                restore_eng.restore_backup(backup_dir, target_dir=test_junction, confirm_production_overwrite=True)
            with pytest.raises(ProductionCutoverDisabledError):
                restore_eng.restore_backup(backup_dir, target_dir=test_junction / "evidence", confirm_production_overwrite=True)
            with pytest.raises(ProductionCutoverDisabledError):
                restore_eng.restore_backup(backup_dir, target_dir=test_junction / "nonexistent", confirm_production_overwrite=True)
        finally:
            try:
                os.rmdir(str(test_junction))
            except Exception:
                pass

    # Test Windows symlink (where supported)
    test_symlink = paths.data_dir.parent / f"symlink_to_prod_{uuid.uuid4().hex[:6]}"
    try:
        os.symlink(str(paths.data_dir), str(test_symlink), target_is_directory=True)
        symlink_created = True
    except (OSError, NotImplementedError):
        symlink_created = False

    if symlink_created:
        try:
            with pytest.raises(ProductionCutoverDisabledError):
                restore_eng.restore_backup(backup_dir, target_dir=test_symlink, confirm_production_overwrite=True)
            with pytest.raises(ProductionCutoverDisabledError):
                restore_eng.restore_backup(backup_dir, target_dir=test_symlink / "evidence", confirm_production_overwrite=True)
        finally:
            try:
                os.rmdir(str(test_symlink))
            except Exception:
                pass

    # Case 6: Case-variant path referring to the same Windows directory
    case_variant_prod = Path(str(paths.data_dir).swapcase())
    with pytest.raises(ProductionCutoverDisabledError):
        restore_eng.restore_backup(backup_dir, target_dir=case_variant_prod, confirm_production_overwrite=True)
    case_variant_child = Path(str(paths.data_dir).swapcase()) / "evidence"
    with pytest.raises(ProductionCutoverDisabledError):
        restore_eng.restore_backup(backup_dir, target_dir=case_variant_child, confirm_production_overwrite=True)

    # Case 7: Ordinary isolated directory outside production storage (allowed and succeeds)
    isolated_dir = paths.data_dir.parent / f"isolated_dest_{uuid.uuid4().hex[:6]}"
    try:
        summary = restore_eng.restore_backup(
            backup_dir=backup_dir,
            target_dir=isolated_dir,
            confirm_production_overwrite=False,
        )
        assert summary.generation_id == gen_id
        assert (isolated_dir / "workbench.db").exists()
        assert summary.database_verified is True
    finally:
        shutil.rmtree(isolated_dir, ignore_errors=True)


def test_guard_ordering_and_zero_filesystem_mutations(backup_test_env):
    """
    F-02 requirement: Guard ordering verification.
    Verify that production restore rejection happens BEFORE:
    - Creating or deleting restore staging directories.
    - Moving or renaming files.
    - Creating a safety backup.
    - Deleting or replacing production data.
    - Any other filesystem mutation related to restore.
    """
    engine: BackupEngine = backup_test_env["engine"]
    paths: StoragePaths = backup_test_env["paths"]
    restore_eng: RestoreEngine = backup_test_env["restore_engine"]
    scope_repo: SqliteScopeRepository = backup_test_env["scope_repo"]

    gen_id = "BKP-GUARD-ORDERING-TEST"
    engine.create_backup(generation_id=gen_id)
    backup_dir = paths.backups_dir / gen_id

    # Pre-existing staging folder in external location to prove it is untouched
    pre_existing_ext = paths.data_dir.parent / "pre_existing_staging"
    pre_existing_ext.mkdir(parents=True, exist_ok=True)
    sentinel_file = pre_existing_ext / "sentinel.txt"
    sentinel_file.write_text("must survive unchanged")

    pre_db_sha = hashlib.sha256(paths.database_file.read_bytes()).hexdigest()
    pre_db_mtime = paths.database_file.stat().st_mtime_ns
    pre_backups = set(os.listdir(paths.backups_dir))
    pre_data_dir_contents = set(os.listdir(paths.data_dir))

    # Reject attempt
    with pytest.raises(ProductionCutoverDisabledError):
        restore_eng.restore_backup(
            backup_dir=backup_dir,
            target_dir=paths.data_dir,
            confirm_production_overwrite=True,
        )

    # Assert ZERO mutations occurred
    assert set(os.listdir(paths.backups_dir)) == pre_backups, "No safety backups should have been created"
    assert set(os.listdir(paths.data_dir)) == pre_data_dir_contents, "Data directory contents should be identical"
    assert paths.database_file.stat().st_mtime_ns == pre_db_mtime, "DB mtime must not change"
    assert hashlib.sha256(paths.database_file.read_bytes()).hexdigest() == pre_db_sha, "DB SHA-256 must not change"
    assert sentinel_file.read_text() == "must survive unchanged", "Pre-existing staging data must be untouched"

    shutil.rmtree(pre_existing_ext, ignore_errors=True)


def test_active_in_progress_backup_protection_and_stale_cleanup(backup_test_env):
    """
    F-03 requirement: Only genuinely stale staging directories and records are cleaned up.
    An active IN_PROGRESS backup younger than max_age_seconds is preserved.
    """
    engine: BackupEngine = backup_test_env["engine"]
    paths: StoragePaths = backup_test_env["paths"]
    backup_repo: SqliteBackupRepository = backup_test_env["backup_repo"]

    backup_repo.record_backup_started("BKP-ACTIVE-FRESH", sqlite_data_version=1)
    fresh_staging = paths.backups_dir / ".staging" / "BKP-ACTIVE-FRESH.tmp"
    fresh_staging.mkdir(parents=True)
    (fresh_staging / "active_file.bin").write_bytes(b"in flight snapshot")

    cleaned = engine.cleanup_stale_staging(max_age_seconds=3600)
    assert cleaned == 0, "Active recent backup should not be cleaned up"

    rec = backup_repo.get_backup("BKP-ACTIVE-FRESH")
    assert rec.status == BackupStatus.IN_PROGRESS, "Status must remain IN_PROGRESS"
    assert fresh_staging.exists(), "Staging directory must NOT be deleted"

    cleaned_stale = engine.cleanup_stale_staging(max_age_seconds=0)
    assert cleaned_stale == 1, "Abandoned backup should be cleaned up on startup sweep"

    rec_stale = backup_repo.get_backup("BKP-ACTIVE-FRESH")
    assert rec_stale.status == BackupStatus.FAILED, "Status must transition to FAILED"
    assert not fresh_staging.exists(), "Staging directory must be removed"
