"""
Dedicated Test Suite: Archive Manifest Hardening & Fault Scenarios (Phase E3A / E3B Readiness).

Validates all 18 specified concurrency, integrity, recovery, and fault-injection scenarios:
 1. Existing valid manifest record and valid target.
 2. Existing valid record but missing target (raises MigrationIntegrityError).
 3. Existing record with changed target hash (raises MigrationIntegrityError).
 4. Existing record with changed target size (raises MigrationIntegrityError).
 5. Missing manifest entry with verified committed target (backfills successfully).
 6. Missing manifest entry with unowned/missing target (raises MigrationIntegrityError).
 7. Same record appended concurrently by two threads (thread serialization, 1 line written).
 8. Two ArchiveManager instances using the same manifest path (shared lock, 1 line written).
 9. Crash before append (clean, safe retry).
10. Crash during append (malformed tail, preserved, safe retry).
11. Crash after append before fsync (detected on next scan).
12. Crash after fsync before delivery marker (idempotent no-op).
13. Valid final JSON record without newline (preserved, prepends \\n on next append).
14. Malformed partial trailing record (preserved, anomaly recorded, prepends \\n).
15. Duplicate identical record (idempotent no-op).
16. Conflicting duplicate record (raises MigrationIntegrityError).
17. Target path outside archive root (raises MigrationIntegrityError).
18. Reparse point or symlink target rejection (raises MigrationIntegrityError).

All tests execute in isolated synthetic sandboxes. Zero mutation of production data.
"""

import concurrent.futures
import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path
import pytest

from app.core.instance_lock import InstanceLock, MaintenanceSession
from app.services.archive_manager import ArchiveManager, is_reparse_point_or_symlink
from app.services.migration_journal import MigrationJournal
from app.services.migration_models import (
    ArchiveManifestEntry,
    MigrationIntegrityError,
    MigrationRecoveryError,
    MigrationState,
    generate_manifest_record_id,
)
from app.services.migration_recovery_service import MigrationRecoveryService


@pytest.fixture
def manifest_sandbox(tmp_path: Path):
    """Provides an isolated sandbox with clean directory hierarchy and MaintenanceSession."""
    data_dir = tmp_path / "sandbox_data"
    data_dir.mkdir(parents=True)

    db_path = data_dir / "workbench.db"
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("PRAGMA foreign_keys = ON;")
    cur.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT, description TEXT);")
    cur.execute("INSERT INTO schema_version VALUES (1, '2026-11-01', 'Initial schema');")
    conn.commit()

    # Ensure migration journal and outbox tables exist
    MigrationJournal.ensure_schema(conn)

    lock_file = data_dir / "workbench.lock"
    lock = InstanceLock(lock_file)
    lock.acquire()
    session = MaintenanceSession(lock)

    archive_mgr = ArchiveManager(data_dir=data_dir, maintenance_session=session)

    yield {
        "tmp_path": tmp_path,
        "data_dir": data_dir,
        "db_path": db_path,
        "conn": conn,
        "lock": lock,
        "session": session,
        "archive_mgr": archive_mgr,
    }

    conn.close()
    lock.release()


def _create_synthetic_target(
    archive_mgr: ArchiveManager,
    disposition: str,
    folder: str,
    filename: str,
    content: bytes,
) -> Tuple[Path, str, int]:
    """Helper to compute path and write synthetic target file."""
    target_p = archive_mgr.get_target_path(disposition, folder, filename)
    target_p.parent.mkdir(parents=True, exist_ok=True)
    target_p.write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()
    return target_p, sha, len(content)


# =====================================================================
# SCENARIOS 1 - 6: TARGET VALIDATION & SQLite BACKFILL
# =====================================================================

def test_scenario_01_existing_valid_manifest_record_and_valid_target(manifest_sandbox):
    """Scenario 1: Existing valid manifest record and valid physical target on disk."""
    archive_mgr = manifest_sandbox["archive_mgr"]
    content = b'{"type": "historical", "status": "valid"}'
    target_p, sha, size = _create_synthetic_target(archive_mgr, "HISTORICAL_ARCHIVE", "ASM-01", "EVD-01.json", content)

    # Initial append
    e1 = archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-01.json",
        target_path=str(target_p),
        sha256=sha,
        byte_size=size,
        filename="EVD-01.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-01",
        artifact_id="EVD-01",
    )
    assert len(e1.manifest_record_id) == 64
    assert e1.identity_version == 2

    # Verify physical file
    archive_mgr.verify_physical_target(target_p, sha, size, "OP-01", "EVD-01")

    # Repeat append is idempotent no-op
    e2 = archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-01.json",
        target_path=str(target_p),
        sha256=sha,
        byte_size=size,
        filename="EVD-01.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-01",
        artifact_id="EVD-01",
    )
    assert e1.manifest_record_id == e2.manifest_record_id

    entries = archive_mgr.read_manifest_entries()
    assert len(entries) == 1


def test_scenario_02_existing_valid_record_missing_target(manifest_sandbox):
    """Scenario 2: Existing valid record but missing physical target raises MigrationIntegrityError."""
    archive_mgr = manifest_sandbox["archive_mgr"]
    non_existent = archive_mgr.get_target_path("HISTORICAL_ARCHIVE", "ASM-01", "EVD-missing.json")

    with pytest.raises(MigrationIntegrityError) as exc_info:
        archive_mgr.verify_physical_target(
            target_path=non_existent,
            expected_sha256="abc123sha",
            expected_size=100,
            operation_id="OP-02",
            artifact_id="EVD-missing",
        )
    assert "Physical archive target missing" in str(exc_info.value)


def test_scenario_03_existing_record_changed_target_hash(manifest_sandbox):
    """Scenario 3: Existing record with changed target hash raises MigrationIntegrityError."""
    archive_mgr = manifest_sandbox["archive_mgr"]
    content = b'{"type": "historical", "status": "original"}'
    target_p, sha, size = _create_synthetic_target(archive_mgr, "HISTORICAL_ARCHIVE", "ASM-01", "EVD-tampered.json", content)

    # Tamper with file
    target_p.write_bytes(b'{"type": "historical", "status": "tampered"}')

    with pytest.raises(MigrationIntegrityError) as exc_info:
        archive_mgr.verify_physical_target(
            target_path=target_p,
            expected_sha256=sha,
            expected_size=size,
            operation_id="OP-03",
            artifact_id="EVD-tampered",
        )
    assert "Physical SHA-256 mismatch" in str(exc_info.value)


def test_scenario_04_existing_record_changed_target_size(manifest_sandbox):
    """Scenario 4: Existing record with changed target size raises MigrationIntegrityError."""
    archive_mgr = manifest_sandbox["archive_mgr"]
    content = b'{"type": "test", "data": "abc"}'
    target_p, sha, size = _create_synthetic_target(archive_mgr, "LEGACY_TEST_ARCHIVE", "ASM-01", "EVD-size.json", content)

    # Truncate file by 1 byte
    target_p.write_bytes(content[:-1])

    with pytest.raises(MigrationIntegrityError) as exc_info:
        archive_mgr.verify_physical_target(
            target_path=target_p,
            expected_sha256=sha,
            expected_size=size,
            operation_id="OP-04",
            artifact_id="EVD-size",
        )
    assert "Physical size mismatch" in str(exc_info.value)


def test_scenario_05_missing_manifest_entry_verified_committed_target(manifest_sandbox):
    """Scenario 5: Missing manifest entry with verified committed target backfills successfully."""
    conn = manifest_sandbox["conn"]
    archive_mgr = manifest_sandbox["archive_mgr"]

    content = b'{"disposition": "historical", "verified": true}'
    target_p, sha, size = _create_synthetic_target(archive_mgr, "HISTORICAL_ARCHIVE", "ASM-01", "EVD-bf01.json", content)

    # Populate SQLite migration journal with COMMITTED record
    entry = MigrationJournal.record_discovered(
        conn=conn,
        operation_id="OP-BF01",
        artifact_id="EVD-bf01",
        parent_folder="ASM-01",
        source_path="database/evidence/ASM-01/EVD-bf01.json",
        staged_path="staged.tmp",
        target_path=str(target_p),
        sha256=sha,
        byte_size=size,
        sequence=1,
    )
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.DISCOVERED, MigrationState.VALIDATED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.VALIDATED, MigrationState.STAGED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.STAGED, MigrationState.VERIFIED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.VERIFIED, MigrationState.PROMOTION_INTENT_RECORDED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.PROMOTION_INTENT_RECORDED, MigrationState.PROMOTED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.PROMOTED, MigrationState.COMMITTED)

    # Manifest is empty before backfill
    assert len(archive_mgr.read_manifest_entries()) == 0

    backfilled = archive_mgr.backfill_from_committed_journal(conn, operation_id="OP-BF01")
    assert len(backfilled) == 1
    assert backfilled[0].artifact_id == "EVD-bf01"
    assert backfilled[0].physical_sha256 == sha

    manifest_entries = archive_mgr.read_manifest_entries()
    assert len(manifest_entries) == 1
    assert manifest_entries[0].manifest_record_id == backfilled[0].manifest_record_id


def test_scenario_06_missing_manifest_entry_unowned_missing_target(manifest_sandbox):
    """Scenario 6: Missing manifest entry with unowned/missing target raises MigrationIntegrityError."""
    conn = manifest_sandbox["conn"]
    archive_mgr = manifest_sandbox["archive_mgr"]
    non_existent = archive_mgr.get_target_path("HISTORICAL_ARCHIVE", "ASM-01", "EVD-ghost.json")

    entry = MigrationJournal.record_discovered(
        conn=conn,
        operation_id="OP-GHOST",
        artifact_id="EVD-ghost",
        parent_folder="ASM-01",
        source_path="database/evidence/ASM-01/EVD-ghost.json",
        staged_path="staged.tmp",
        target_path=str(non_existent),
        sha256="deadbeef",
        byte_size=50,
        sequence=1,
    )
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.DISCOVERED, MigrationState.VALIDATED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.VALIDATED, MigrationState.STAGED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.STAGED, MigrationState.VERIFIED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.VERIFIED, MigrationState.PROMOTION_INTENT_RECORDED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.PROMOTION_INTENT_RECORDED, MigrationState.PROMOTED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.PROMOTED, MigrationState.COMMITTED)

    with pytest.raises(MigrationIntegrityError) as exc_info:
        archive_mgr.backfill_from_committed_journal(conn, operation_id="OP-GHOST")
    assert "Physical archive target missing" in str(exc_info.value)


# =====================================================================
# SCENARIOS 7 - 8: THREAD CONCURRENCY & INSTANCE SERIALIZATION
# =====================================================================

def test_scenario_07_same_record_appended_concurrently_by_two_threads(manifest_sandbox):
    """Scenario 7: Same record appended concurrently by two threads serializes cleanly to 1 line."""
    archive_mgr = manifest_sandbox["archive_mgr"]
    content = b'{"concurrent": "test_threads"}'
    target_p, sha, size = _create_synthetic_target(archive_mgr, "HISTORICAL_ARCHIVE", "ASM-01", "EVD-thread.json", content)

    results = []
    errors = []

    def worker():
        try:
            entry = archive_mgr.append_manifest_entry(
                source_path="ASM-01/EVD-thread.json",
                target_path=str(target_p),
                sha256=sha,
                byte_size=size,
                filename="EVD-thread.json",
                classification="HISTORICAL_ARCHIVE",
                operation_id="OP-THREAD",
                artifact_id="EVD-thread",
            )
            results.append(entry)
        except Exception as e:
            errors.append(e)

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert len(errors) == 0
    assert len(results) == 2
    assert results[0].manifest_record_id == results[1].manifest_record_id

    # Manifest file contains exactly 1 physical record
    lines = [l for l in archive_mgr.manifest_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 1


def test_scenario_08_two_archive_manager_instances_shared_lock(manifest_sandbox):
    """Scenario 8: Two ArchiveManager instances using the same manifest path share the same canonical lock."""
    data_dir = manifest_sandbox["data_dir"]
    session = manifest_sandbox["session"]

    # Create two distinct ArchiveManager instances
    mgr_a = ArchiveManager(data_dir=data_dir, maintenance_session=session)
    mgr_b = ArchiveManager(data_dir=data_dir, maintenance_session=session)

    # Verify shared lock identity
    assert mgr_a._lock is mgr_b._lock

    content = b'{"multi": "instances"}'
    target_p, sha, size = _create_synthetic_target(mgr_a, "HISTORICAL_ARCHIVE", "ASM-01", "EVD-inst.json", content)

    # Append from mgr_a then mgr_b
    e_a = mgr_a.append_manifest_entry(
        source_path="ASM-01/EVD-inst.json",
        target_path=str(target_p),
        sha256=sha,
        byte_size=size,
        filename="EVD-inst.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-INST",
        artifact_id="EVD-inst",
    )
    e_b = mgr_b.append_manifest_entry(
        source_path="ASM-01/EVD-inst.json",
        target_path=str(target_p),
        sha256=sha,
        byte_size=size,
        filename="EVD-inst.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-INST",
        artifact_id="EVD-inst",
    )

    assert e_a.manifest_record_id == e_b.manifest_record_id
    entries = mgr_b.read_manifest_entries()
    assert len(entries) == 1


# =====================================================================
# SCENARIOS 9 - 14: CRASH BEHAVIOR & NON-DESTRUCTIVE RECOVERY
# =====================================================================

def test_scenario_09_crash_before_append_clean_retry(manifest_sandbox):
    """Scenario 9: Crash before append leaves manifest clean; retry appends safely."""
    archive_mgr = manifest_sandbox["archive_mgr"]
    content = b'{"crash": "before_append"}'
    target_p, sha, size = _create_synthetic_target(archive_mgr, "HISTORICAL_ARCHIVE", "ASM-01", "EVD-crash09.json", content)

    # Simulated crash: target was published, but manifest was not yet written
    assert not archive_mgr.manifest_file.exists()

    # Recovery/retry:
    entry = archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-crash09.json",
        target_path=str(target_p),
        sha256=sha,
        byte_size=size,
        filename="EVD-crash09.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-CRASH09",
        artifact_id="EVD-crash09",
    )
    assert entry.artifact_id == "EVD-crash09"
    assert len(archive_mgr.read_manifest_entries()) == 1


def test_scenario_10_crash_during_append_malformed_tail_preserved(manifest_sandbox):
    """Scenario 10: Crash during append leaves malformed tail; preserved without data loss on retry."""
    archive_mgr = manifest_sandbox["archive_mgr"]
    archive_mgr.manifest_file.parent.mkdir(parents=True, exist_ok=True)

    # Incomplete JSON fragment at EOF without newline
    corrupt_tail = b'{"manifest_record_id": "man-PARTIAL", "operat'
    archive_mgr.manifest_file.write_bytes(corrupt_tail)

    seen, diag = archive_mgr.scan_existing_records()
    assert diag is not None
    assert diag["is_valid_json_without_newline"] is False
    assert diag["length"] == len(corrupt_tail)
    assert diag["sha256"] == hashlib.sha256(corrupt_tail).hexdigest()

    content = b'{"valid": "after_crash"}'
    target_p, sha, size = _create_synthetic_target(archive_mgr, "HISTORICAL_ARCHIVE", "ASM-01", "EVD-recov10.json", content)

    entry = archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-recov10.json",
        target_path=str(target_p),
        sha256=sha,
        byte_size=size,
        filename="EVD-recov10.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-RECOV10",
        artifact_id="EVD-recov10",
    )

    # The file bytes must contain both the original corrupted fragment AND the new line
    raw_bytes = archive_mgr.manifest_file.read_bytes()
    assert raw_bytes.startswith(corrupt_tail)
    assert b"\n" in raw_bytes
    assert entry.manifest_record_id.encode("utf-8") in raw_bytes

    # Reading manifest entries successfully parses the valid entry
    entries = archive_mgr.read_manifest_entries()
    assert len(entries) == 1
    assert entries[0].artifact_id == "EVD-recov10"


def test_scenario_11_crash_after_append_before_fsync(manifest_sandbox):
    """Scenario 11: Crash after append before fsync is detectable and recoverable on next scan."""
    archive_mgr = manifest_sandbox["archive_mgr"]
    content = b'{"scan": "detectable"}'
    target_p, sha, size = _create_synthetic_target(archive_mgr, "HISTORICAL_ARCHIVE", "ASM-01", "EVD-s11.json", content)

    entry = ArchiveManifestEntry(
        manifest_record_id=generate_manifest_record_id("OP-11", "EVD-s11", sha),
        operation_id="OP-11",
        artifact_id="EVD-s11",
        source_relative_path="ASM-01/EVD-s11.json",
        destination_relative_path="archive/evidence/ASM-01/EVD-s11.json",
        physical_sha256=sha,
        size_bytes=size,
        disposition="HISTORICAL_ARCHIVE",
        committed_timestamp="2026-11-01T00:00:00Z",
    )
    # Write directly to simulate un-synced line in file
    archive_mgr.manifest_file.parent.mkdir(parents=True, exist_ok=True)
    with open(archive_mgr.manifest_file, "wb") as f:
        f.write((entry.model_dump_json() + "\n").encode("utf-8"))

    seen, diag = archive_mgr.scan_existing_records()
    assert entry.manifest_record_id in seen
    assert diag is None


def test_scenario_12_crash_after_fsync_before_delivery_marker(manifest_sandbox):
    """Scenario 12: Crash after fsync before delivery marker is an idempotent no-op upon retry."""
    archive_mgr = manifest_sandbox["archive_mgr"]
    content = b'{"idempotent": "after_fsync"}'
    target_p, sha, size = _create_synthetic_target(archive_mgr, "HISTORICAL_ARCHIVE", "ASM-01", "EVD-s12.json", content)

    # First attempt succeeds and fsyncs
    e1 = archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-s12.json",
        target_path=str(target_p),
        sha256=sha,
        byte_size=size,
        filename="EVD-s12.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-12",
        artifact_id="EVD-s12",
    )

    # Simulated crash: recovery process calls append_manifest_entry again
    e2 = archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-s12.json",
        target_path=str(target_p),
        sha256=sha,
        byte_size=size,
        filename="EVD-s12.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-12",
        artifact_id="EVD-s12",
    )

    assert e1.manifest_record_id == e2.manifest_record_id
    assert len(archive_mgr.read_manifest_entries()) == 1


def test_scenario_13_valid_final_json_record_without_newline(manifest_sandbox):
    """Scenario 13: Valid final JSON record without trailing newline is preserved and delimited on next append."""
    archive_mgr = manifest_sandbox["archive_mgr"]
    content1 = b'{"record": 1}'
    target1, sha1, size1 = _create_synthetic_target(archive_mgr, "HISTORICAL_ARCHIVE", "ASM-01", "EVD-nl01.json", content1)

    rec1 = ArchiveManifestEntry(
        manifest_record_id=generate_manifest_record_id("OP-NL", "EVD-nl01", sha1),
        operation_id="OP-NL",
        artifact_id="EVD-nl01",
        source_relative_path="ASM-01/EVD-nl01.json",
        destination_relative_path="archive/evidence/ASM-01/EVD-nl01.json",
        physical_sha256=sha1,
        size_bytes=size1,
        disposition="HISTORICAL_ARCHIVE",
        committed_timestamp="2026-11-01T00:00:00Z",
    )
    # Write valid JSON WITHOUT newline
    archive_mgr.manifest_file.parent.mkdir(parents=True, exist_ok=True)
    archive_mgr.manifest_file.write_bytes(rec1.model_dump_json().encode("utf-8"))

    seen, diag = archive_mgr.scan_existing_records()
    assert rec1.manifest_record_id in seen
    assert diag is not None
    assert diag["is_valid_json_without_newline"] is True

    # Next append must prepend newline delimiter and succeed cleanly
    content2 = b'{"record": 2}'
    target2, sha2, size2 = _create_synthetic_target(archive_mgr, "HISTORICAL_ARCHIVE", "ASM-01", "EVD-nl02.json", content2)

    rec2 = archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-nl02.json",
        target_path=str(target2),
        sha256=sha2,
        byte_size=size2,
        filename="EVD-nl02.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-NL",
        artifact_id="EVD-nl02",
    )

    entries = archive_mgr.read_manifest_entries()
    assert len(entries) == 2
    assert entries[0].artifact_id == "EVD-nl01"
    assert entries[1].artifact_id == "EVD-nl02"


def test_scenario_14_malformed_partial_trailing_record_preserved(manifest_sandbox):
    """Scenario 14: Malformed partial trailing record is preserved as anomaly, next record prepends delimiter."""
    archive_mgr = manifest_sandbox["archive_mgr"]
    archive_mgr.manifest_file.parent.mkdir(parents=True, exist_ok=True)

    # Valid entry followed by newline, then broken bytes
    valid_line = b'{"manifest_record_id":"man-V1","operation_id":"OP-1","artifact_id":"A1","source_relative_path":"s","destination_relative_path":"d","physical_sha256":"h","size_bytes":10,"disposition":"HISTORICAL_ARCHIVE","committed_timestamp":"t","provenance":{}}\n'
    broken_bytes = b'CORRUPTED_BYTES_WITHOUT_JSON'
    archive_mgr.manifest_file.write_bytes(valid_line + broken_bytes)

    seen, diag = archive_mgr.scan_existing_records()
    assert "man-V1" in seen
    assert diag is not None
    assert diag["is_valid_json_without_newline"] is False
    assert diag["length"] == len(broken_bytes)

    # Append new record
    content = b'{"record": "fresh"}'
    target_p, sha, size = _create_synthetic_target(archive_mgr, "HISTORICAL_ARCHIVE", "ASM-01", "EVD-fresh.json", content)

    fresh_entry = archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-fresh.json",
        target_path=str(target_p),
        sha256=sha,
        byte_size=size,
        filename="EVD-fresh.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-FRESH",
        artifact_id="EVD-fresh",
    )

    raw_file = archive_mgr.manifest_file.read_bytes()
    assert broken_bytes in raw_file
    assert fresh_entry.manifest_record_id.encode("utf-8") in raw_file


# =====================================================================
# SCENARIOS 15 - 18: INTEGRITY CHECKS & BOUNDARY CONSTRAINTS
# =====================================================================

def test_scenario_15_duplicate_identical_record_idempotent(manifest_sandbox):
    """Scenario 15: Duplicate identical record append is idempotent and returns existing entry."""
    archive_mgr = manifest_sandbox["archive_mgr"]
    content = b'{"duplicate": "test"}'
    target_p, sha, size = _create_synthetic_target(archive_mgr, "HISTORICAL_ARCHIVE", "ASM-01", "EVD-s15.json", content)

    e1 = archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-s15.json",
        target_path=str(target_p),
        sha256=sha,
        byte_size=size,
        filename="EVD-s15.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-15",
        artifact_id="EVD-s15",
    )
    e2 = archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-s15.json",
        target_path=str(target_p),
        sha256=sha,
        byte_size=size,
        filename="EVD-s15.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-15",
        artifact_id="EVD-s15",
    )
    assert e1 == e2
    assert len(archive_mgr.read_manifest_entries()) == 1


def test_scenario_16_conflicting_duplicate_record_fails(manifest_sandbox):
    """Scenario 16: Conflicting duplicate record with differing metadata raises MigrationIntegrityError."""
    archive_mgr = manifest_sandbox["archive_mgr"]
    content = b'{"conflict": "test"}'
    target_p, sha, size = _create_synthetic_target(archive_mgr, "HISTORICAL_ARCHIVE", "ASM-01", "EVD-s16.json", content)

    archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-s16.json",
        target_path=str(target_p),
        sha256=sha,
        byte_size=size,
        filename="EVD-s16.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-16",
        artifact_id="EVD-s16",
    )

    # Attempt appending conflicting record with same ID but different disposition
    with pytest.raises(MigrationIntegrityError) as exc_info:
        archive_mgr.append_manifest_entry(
            source_path="ASM-01/EVD-s16.json",
            target_path=str(target_p),
            sha256=sha,
            byte_size=size,
            filename="EVD-s16.json",
            classification="LEGACY_TEST_ARCHIVE",  # Conflicting classification!
            operation_id="OP-16",
            artifact_id="EVD-s16",
        )
    assert "Different disposition for existing identity" in str(exc_info.value) or "Conflicting" in str(exc_info.value)


def test_scenario_17_target_path_outside_archive_root(manifest_sandbox):
    """Scenario 17: Target path escaping archive root raises MigrationIntegrityError."""
    archive_mgr = manifest_sandbox["archive_mgr"]
    data_dir = manifest_sandbox["data_dir"]

    # Target path in active evidence rather than archive/
    escaped_dir = data_dir / "evidence" / "ASM-01"
    escaped_dir.mkdir(parents=True, exist_ok=True)
    escaped_target = escaped_dir / "EVD-escaped.json"
    content = b'{"escaped": true}'
    escaped_target.write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()

    with pytest.raises(MigrationIntegrityError) as exc_info:
        archive_mgr.verify_physical_target(
            target_path=escaped_target,
            expected_sha256=sha,
            expected_size=len(content),
            operation_id="OP-17",
            artifact_id="EVD-escaped",
        )
    assert "escapes approved archive root" in str(exc_info.value)


def test_scenario_18_reparse_point_or_symlink_target_rejection(manifest_sandbox):
    """Scenario 18: Reparse point or symlink target rejection raises MigrationIntegrityError."""
    archive_mgr = manifest_sandbox["archive_mgr"]
    content = b'{"real": "file"}'
    real_target, sha, size = _create_synthetic_target(archive_mgr, "HISTORICAL_ARCHIVE", "ASM-01", "real_target.json", content)

    symlink_target = archive_mgr.historical_archive_dir / "ASM-01" / "symlink_target.json"

    # Attempt creating actual symlink; if OS permissions allow, test real symlink
    created_real_symlink = False
    try:
        os.symlink(real_target, symlink_target)
        created_real_symlink = True
    except OSError:
        pass

    if created_real_symlink:
        assert is_reparse_point_or_symlink(symlink_target) is True
        with pytest.raises(MigrationIntegrityError) as exc_info:
            archive_mgr.verify_physical_target(
                target_path=symlink_target,
                expected_sha256=sha,
                expected_size=size,
                operation_id="OP-18",
                artifact_id="EVD-symlink",
            )
        assert "symlink or reparse point" in str(exc_info.value)

    # Also test monkeypatched detection to guarantee coverage in all environments
    original_fn = is_reparse_point_or_symlink
    try:
        import app.services.archive_manager as am_mod
        am_mod.is_reparse_point_or_symlink = lambda p: True
        with pytest.raises(MigrationIntegrityError) as exc_info:
            archive_mgr.verify_physical_target(
                target_path=real_target,
                expected_sha256=sha,
                expected_size=size,
                operation_id="OP-18-MOCK",
                artifact_id="EVD-mock",
            )
        assert "symlink or reparse point" in str(exc_info.value)
    finally:
        am_mod.is_reparse_point_or_symlink = original_fn
