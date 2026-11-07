"""
Tests for Phase E3A Evidence Migration Engine & State Machine.

Validates the 7-stage state machine, Windows NTFS hard-linking, atomic SQLite
journaling, failure-closed boundaries, recovery service idempotency, secondary
JSONL audit outbox with durable fsync, archive manifests, and all 15 approved
fault-injection interruption points.
Includes F-01 Maintenance Lock Enforcement and F-02 Archive Manifest Recovery & Idempotency.
"""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
import pytest

from app.core.instance_lock import (
    InstanceLock,
    MaintenanceContext,
    MaintenanceSession,
    ProcessLockError,
)
from app.core.storage_paths import StoragePaths
from app.services.archive_manager import ArchiveManager
from app.services.jsonl_audit_outbox import JSONLAuditOutbox
from app.services.migration_engine import MigrationEngine
from app.services.migration_journal import MigrationJournal
from app.services.migration_models import (
    ArchiveManifestEntry,
    InvalidStateTransitionError,
    MigrationBatchPlan,
    MigrationBatchResult,
    MigrationCollisionError,
    MigrationError,
    MigrationIntegrityError,
    MigrationJournalEntry,
    MigrationRecoveryError,
    MigrationSafetyError,
    MigrationState,
    generate_manifest_record_id,
    generate_manifest_record_id_v1,
    generate_manifest_record_id_v2,
)
from app.services.migration_recovery_service import MigrationRecoveryService


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    Creates an isolated synthetic test environment with clean SQLite schema,
    synthetic source evidence, sandboxed storage paths, and acquired MaintenanceSession.

    The session-wide conftest sets ALLTOOLS_DATA_DIR to tmp_path for isolation. These
    tests pass explicit StoragePaths, so the override is removed here to keep the
    sandbox from being classified as the configured production data directory.
    """
    monkeypatch.delenv("ALLTOOLS_DATA_DIR", raising=False)

    source_dir = tmp_path / "source_evidence"
    source_dir.mkdir(parents=True)

    dest_data_dir = tmp_path / "app_data"
    dest_data_dir.mkdir(parents=True)

    db_path = dest_data_dir / "workbench.db"
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("PRAGMA foreign_keys = ON;")
    cur.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT, description TEXT);")
    cur.execute("INSERT INTO schema_version VALUES (1, '2026-11-01', 'Initial schema');")
    cur.execute("""
        CREATE TABLE engagements (
            id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL DEFAULT 'WKP-DEFAULT',
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)
    cur.execute("""
        CREATE TABLE assessments (
            id TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL REFERENCES engagements(id),
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)
    cur.execute("""
        CREATE TABLE findings (
            id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL REFERENCES assessments(id),
            asset_id TEXT NOT NULL,
            title TEXT NOT NULL,
            status TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)
    cur.execute("""
        CREATE TABLE evidence (
            id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL REFERENCES assessments(id),
            finding_id TEXT REFERENCES findings(id),
            type TEXT NOT NULL,
            source TEXT NOT NULL,
            artifact_path TEXT NOT NULL UNIQUE,
            captured_at TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            redacted INTEGER NOT NULL,
            notes TEXT,
            sync_status TEXT NOT NULL,
            retention_policy TEXT NOT NULL,
            legal_hold INTEGER NOT NULL DEFAULT 0,
            is_deleted INTEGER NOT NULL DEFAULT 0
        );
    """)
    conn.commit()
    conn.close()

    paths = StoragePaths(
        data_dir=dest_data_dir,
        database_file=db_path,
        evidence_dir=dest_data_dir / "evidence",
        quarantine_dir=dest_data_dir / "quarantine",
        backups_dir=dest_data_dir / "backups",
        lock_file=dest_data_dir / "workbench.lock",
    )

    # Establish maintenance lock & session
    lock = InstanceLock(paths.lock_file)
    lock.acquire()
    session = MaintenanceSession(lock)

    # Create synthetic test artifacts
    hist_folder = source_dir / "ASM-01"
    hist_folder.mkdir(parents=True)
    hist_file = hist_folder / "EVD-hist01.json"
    hist_content = json.dumps({"test": "historical", "timestamp": "2026-10-31"}).encode("utf-8")
    hist_file.write_bytes(hist_content)
    hist_sha = hashlib.sha256(hist_content).hexdigest()

    active_folder = source_dir / "ASM-001"
    active_folder.mkdir(parents=True)
    active_file = active_folder / "EVD-active01.json"
    active_content = json.dumps({"test": "active", "id": "EVD-active01"}).encode("utf-8")
    active_file.write_bytes(active_content)
    active_sha = hashlib.sha256(active_content).hexdigest()

    yield {
        "tmp_path": tmp_path,
        "source_dir": source_dir,
        "dest_data_dir": dest_data_dir,
        "db_path": db_path,
        "paths": paths,
        "lock": lock,
        "session": session,
        "hist_file": hist_file,
        "hist_sha": hist_sha,
        "hist_size": len(hist_content),
        "active_file": active_file,
        "active_sha": active_sha,
        "active_size": len(active_content),
    }

    lock.release()


# =====================================================================
# 1. STATE MACHINE & TRANSITION TESTS
# =====================================================================

def test_state_machine_valid_transitions(isolated_env):
    """Test valid sequential progression through the 7 migration states."""
    paths = isolated_env["paths"]
    engine = MigrationEngine(paths=paths, maintenance_session=isolated_env["session"])
    conn = engine.connect_database()

    entry = MigrationJournal.record_discovered(
        conn=conn,
        operation_id="OP-001",
        artifact_id="ART-001",
        parent_folder="ASM-01",
        source_path="ASM-01/ART-001.json",
        staged_path=str(paths.data_dir / ".staging" / "ART-001.tmp"),
        target_path=str(paths.data_dir / "archive" / "evidence" / "ASM-01" / "ART-001.json"),
        sha256="abc123",
        byte_size=100,
        sequence=1,
    )
    assert entry.state == MigrationState.DISCOVERED

    # DISCOVERED -> VALIDATED
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.DISCOVERED, MigrationState.VALIDATED)
    assert entry.state == MigrationState.VALIDATED

    # VALIDATED -> STAGED
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.VALIDATED, MigrationState.STAGED)
    assert entry.state == MigrationState.STAGED

    # STAGED -> VERIFIED
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.STAGED, MigrationState.VERIFIED)
    assert entry.state == MigrationState.VERIFIED

    # VERIFIED -> PROMOTION_INTENT_RECORDED
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.VERIFIED, MigrationState.PROMOTION_INTENT_RECORDED)
    assert entry.state == MigrationState.PROMOTION_INTENT_RECORDED

    # PROMOTION_INTENT_RECORDED -> PROMOTED
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.PROMOTION_INTENT_RECORDED, MigrationState.PROMOTED)
    assert entry.state == MigrationState.PROMOTED

    # PROMOTED -> COMMITTED
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.PROMOTED, MigrationState.COMMITTED)
    assert entry.state == MigrationState.COMMITTED
    conn.close()


def test_state_machine_invalid_transitions(isolated_env):
    """Test illegal state transitions raise InvalidStateTransitionError."""
    paths = isolated_env["paths"]
    engine = MigrationEngine(paths=paths, maintenance_session=isolated_env["session"])
    conn = engine.connect_database()

    entry = MigrationJournal.record_discovered(
        conn=conn,
        operation_id="OP-002",
        artifact_id="ART-002",
        parent_folder="ASM-01",
        source_path="ASM-01/ART-002.json",
        staged_path=str(paths.data_dir / ".staging" / "ART-002.tmp"),
        target_path=str(paths.data_dir / "archive" / "evidence" / "ASM-01" / "ART-002.json"),
        sha256="abc123",
        byte_size=100,
        sequence=1,
    )

    # Illegal: DISCOVERED -> COMMITTED
    with pytest.raises(InvalidStateTransitionError):
        MigrationJournal.transition_state(conn, entry.id, MigrationState.DISCOVERED, MigrationState.COMMITTED)

    # Illegal: DISCOVERED -> PROMOTED
    with pytest.raises(InvalidStateTransitionError):
        MigrationJournal.transition_state(conn, entry.id, MigrationState.DISCOVERED, MigrationState.PROMOTED)

    # Illegal: Current state mismatch (expected VALIDATED but actual is DISCOVERED)
    with pytest.raises(InvalidStateTransitionError):
        MigrationJournal.transition_state(conn, entry.id, MigrationState.VALIDATED, MigrationState.STAGED)

    conn.close()


# =====================================================================
# 2. NTFS HARD-LINKING & SAMEFILE SEMANTICS
# =====================================================================

def test_ntfs_hard_linking_and_samefile(isolated_env):
    """
    Verify same-volume hard-linking (os.link) and inode equality (os.path.samefile).
    """
    data_dir = isolated_env["dest_data_dir"]
    staging_file = data_dir / "staged.tmp"
    target_file = data_dir / "published.json"

    content = b"hardlink-payload-test"
    staging_file.write_bytes(content)

    os.link(str(staging_file), str(target_file))
    assert target_file.exists()
    assert os.path.samefile(staging_file, target_file)

    # Target content is identical
    assert target_file.read_bytes() == content

    # Removing staging file does not affect published target
    staging_file.unlink()
    assert not staging_file.exists()
    assert target_file.exists()
    assert target_file.read_bytes() == content


# =====================================================================
# 3. 15 FAULT-INJECTION INTERRUPTION TESTS
# =====================================================================

def test_fault_01_before_source_hashing(isolated_env):
    """Fault 1: Interruption before source hashing."""
    class Interrupted(Exception): pass

    def injector(hook_name):
        if hook_name == "before_source_hashing":
            raise Interrupted("Crash before source hashing")

    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"], fault_injector=injector)
    conn = engine.connect_database()

    item = {
        "source_path": str(isolated_env["hist_file"]),
        "parent_folder": "ASM-01",
        "artifact_id": "EVD-hist01",
        "primary_disposition": "HISTORICAL_ARCHIVE",
        "sha256": isolated_env["hist_sha"],
        "byte_size": isolated_env["hist_size"],
    }

    with pytest.raises(Interrupted):
        engine.migrate_single_artifact(conn, "OP-F01", item, sequence=1)

    # Verify no journal entry committed
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM migration_journal WHERE operation_id = 'OP-F01';")
    assert cursor.fetchone()[0] == 0
    # Source untouched
    assert isolated_env["hist_file"].exists()
    conn.close()


def test_fault_02_during_staging_copy(isolated_env):
    """Fault 2: Interruption during staging copy leaves partial file, cleaned up on recovery."""
    class Interrupted(Exception): pass

    def injector(hook_name):
        if hook_name == "during_staging_copy":
            raise Interrupted("Crash during staging copy")

    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"], fault_injector=injector)
    conn = engine.connect_database()

    item = {
        "source_path": str(isolated_env["hist_file"]),
        "parent_folder": "ASM-01",
        "artifact_id": "EVD-hist01",
        "primary_disposition": "HISTORICAL_ARCHIVE",
        "sha256": isolated_env["hist_sha"],
        "byte_size": isolated_env["hist_size"],
    }

    with pytest.raises(Interrupted):
        engine.migrate_single_artifact(conn, "OP-F02", item, sequence=1)

    cursor = conn.cursor()
    cursor.execute("SELECT id, state, staged_path FROM migration_journal WHERE operation_id = 'OP-F02';")
    row = cursor.fetchone()
    assert row[1] == MigrationState.VALIDATED.value

    # Simulate dirty partial staging file created during interrupted copy
    staged_p = Path(row[2])
    staged_p.parent.mkdir(parents=True, exist_ok=True)
    staged_p.write_bytes(b"partial-data")
    assert staged_p.exists()

    # Recovery should clean up incomplete staging file
    rec_svc = MigrationRecoveryService(conn=conn, outbox=engine.outbox, archive_mgr=engine.archive_mgr, maintenance_session=isolated_env["session"])
    rec_svc.recover_all_pending(operation_id="OP-F02")
    assert not staged_p.exists()
    conn.close()


def test_fault_03_after_staging_fsync(isolated_env):
    """Fault 3: Interruption after staging fsync before STAGED state transition."""
    class Interrupted(Exception): pass

    def injector(hook_name):
        if hook_name == "after_staging_fsync":
            raise Interrupted("Crash after staging fsync")

    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"], fault_injector=injector)
    conn = engine.connect_database()

    item = {
        "source_path": str(isolated_env["hist_file"]),
        "parent_folder": "ASM-01",
        "artifact_id": "EVD-hist01",
        "primary_disposition": "HISTORICAL_ARCHIVE",
        "sha256": isolated_env["hist_sha"],
        "byte_size": isolated_env["hist_size"],
    }

    with pytest.raises(Interrupted):
        engine.migrate_single_artifact(conn, "OP-F03", item, sequence=1)

    cursor = conn.cursor()
    cursor.execute("SELECT id, state, staged_path FROM migration_journal WHERE operation_id = 'OP-F03';")
    row = cursor.fetchone()
    assert row[1] == MigrationState.VALIDATED.value
    staged_p = Path(row[2])
    assert staged_p.exists()

    # Recovery cleans orphan staging file for DISCOVERED/VALIDATED state
    rec_svc = MigrationRecoveryService(conn=conn, outbox=engine.outbox, archive_mgr=engine.archive_mgr, maintenance_session=isolated_env["session"])
    rec_svc.recover_all_pending(operation_id="OP-F03")
    assert not staged_p.exists()
    conn.close()


def test_fault_04_after_sha256_verification(isolated_env):
    """Fault 4: Interruption after SHA-256 verification (state is VERIFIED, target absent)."""
    class Interrupted(Exception): pass

    def injector(hook_name):
        if hook_name == "after_sha256_verification":
            raise Interrupted("Crash after SHA-256 verification")

    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"], fault_injector=injector)
    conn = engine.connect_database()

    item = {
        "source_path": str(isolated_env["hist_file"]),
        "parent_folder": "ASM-01",
        "artifact_id": "EVD-hist01",
        "primary_disposition": "HISTORICAL_ARCHIVE",
        "sha256": isolated_env["hist_sha"],
        "byte_size": isolated_env["hist_size"],
    }

    with pytest.raises(Interrupted):
        engine.migrate_single_artifact(conn, "OP-F04", item, sequence=1)

    cursor = conn.cursor()
    cursor.execute("SELECT id, state, staged_path, target_path FROM migration_journal WHERE operation_id = 'OP-F04';")
    row = cursor.fetchone()
    assert row[1] == MigrationState.VERIFIED.value
    staged_p = Path(row[2])
    target_p = Path(row[3])
    assert staged_p.exists()
    assert not target_p.exists()

    rec_svc = MigrationRecoveryService(conn=conn, outbox=engine.outbox, archive_mgr=engine.archive_mgr, maintenance_session=isolated_env["session"])
    rec_svc.recover_all_pending(operation_id="OP-F04")
    # Recovery removes staging file since target was never linked
    assert not staged_p.exists()
    assert not target_p.exists()
    conn.close()


def test_fault_05_after_promotion_intent_recorded(isolated_env):
    """Fault 5: Interruption after PROMOTION_INTENT_RECORDED (target absent, recovery hard-links)."""
    class Interrupted(Exception): pass

    def injector(hook_name):
        if hook_name == "after_promotion_intent_recorded":
            raise Interrupted("Crash after promotion intent recorded")

    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"], fault_injector=injector)
    conn = engine.connect_database()

    item = {
        "source_path": str(isolated_env["hist_file"]),
        "parent_folder": "ASM-01",
        "artifact_id": "EVD-hist01",
        "primary_disposition": "HISTORICAL_ARCHIVE",
        "sha256": isolated_env["hist_sha"],
        "byte_size": isolated_env["hist_size"],
    }

    with pytest.raises(Interrupted):
        engine.migrate_single_artifact(conn, "OP-F05", item, sequence=1)

    cursor = conn.cursor()
    cursor.execute("SELECT id, state, staged_path, target_path FROM migration_journal WHERE operation_id = 'OP-F05';")
    row = cursor.fetchone()
    assert row[1] == MigrationState.PROMOTION_INTENT_RECORDED.value
    staged_p = Path(row[2])
    target_p = Path(row[3])
    assert staged_p.exists()
    assert not target_p.exists()

    # Recovery resumes by hard-linking target and advancing through to COMMITTED
    rec_svc = MigrationRecoveryService(conn=conn, outbox=engine.outbox, archive_mgr=engine.archive_mgr, maintenance_session=isolated_env["session"])
    rec_svc.recover_all_pending(operation_id="OP-F05")

    assert target_p.exists()
    assert not staged_p.exists()  # unlinked after commit
    cursor.execute("SELECT state FROM migration_journal WHERE operation_id = 'OP-F05';")
    assert cursor.fetchone()[0] == MigrationState.COMMITTED.value
    conn.close()


def test_fault_06_after_hard_link_publication(isolated_env):
    """Fault 6: Interruption after hard-link publication (target linked, state still PROMOTION_INTENT_RECORDED)."""
    class Interrupted(Exception): pass

    def injector(hook_name):
        if hook_name == "after_hard_link_publication":
            raise Interrupted("Crash after hard-link publication")

    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"], fault_injector=injector)
    conn = engine.connect_database()

    item = {
        "source_path": str(isolated_env["hist_file"]),
        "parent_folder": "ASM-01",
        "artifact_id": "EVD-hist01",
        "primary_disposition": "HISTORICAL_ARCHIVE",
        "sha256": isolated_env["hist_sha"],
        "byte_size": isolated_env["hist_size"],
    }

    with pytest.raises(Interrupted):
        engine.migrate_single_artifact(conn, "OP-F06", item, sequence=1)

    cursor = conn.cursor()
    cursor.execute("SELECT id, state, staged_path, target_path FROM migration_journal WHERE operation_id = 'OP-F06';")
    row = cursor.fetchone()
    assert row[1] == MigrationState.PROMOTION_INTENT_RECORDED.value
    staged_p = Path(row[2])
    target_p = Path(row[3])
    # Both files exist and share the same inode
    assert staged_p.exists()
    assert target_p.exists()
    assert os.path.samefile(staged_p, target_p)

    # Recovery recognizes samefile, promotes and commits
    rec_svc = MigrationRecoveryService(conn=conn, outbox=engine.outbox, archive_mgr=engine.archive_mgr, maintenance_session=isolated_env["session"])
    rec_svc.recover_all_pending(operation_id="OP-F06")

    assert target_p.exists()
    assert not staged_p.exists()
    cursor.execute("SELECT state FROM migration_journal WHERE operation_id = 'OP-F06';")
    assert cursor.fetchone()[0] == MigrationState.COMMITTED.value
    conn.close()


def test_fault_07_after_samefile_verification(isolated_env):
    """Fault 7: Interruption after samefile verification before PROMOTED journal update."""
    class Interrupted(Exception): pass

    def injector(hook_name):
        if hook_name == "after_samefile_verification":
            raise Interrupted("Crash after samefile verification")

    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"], fault_injector=injector)
    conn = engine.connect_database()

    item = {
        "source_path": str(isolated_env["hist_file"]),
        "parent_folder": "ASM-01",
        "artifact_id": "EVD-hist01",
        "primary_disposition": "HISTORICAL_ARCHIVE",
        "sha256": isolated_env["hist_sha"],
        "byte_size": isolated_env["hist_size"],
    }

    with pytest.raises(Interrupted):
        engine.migrate_single_artifact(conn, "OP-F07", item, sequence=1)

    cursor = conn.cursor()
    cursor.execute("SELECT id, state, staged_path, target_path FROM migration_journal WHERE operation_id = 'OP-F07';")
    row = cursor.fetchone()
    assert row[1] == MigrationState.PROMOTION_INTENT_RECORDED.value

    rec_svc = MigrationRecoveryService(conn=conn, outbox=engine.outbox, archive_mgr=engine.archive_mgr, maintenance_session=isolated_env["session"])
    rec_svc.recover_all_pending(operation_id="OP-F07")

    cursor.execute("SELECT state FROM migration_journal WHERE operation_id = 'OP-F07';")
    assert cursor.fetchone()[0] == MigrationState.COMMITTED.value
    conn.close()


def test_fault_08_after_promoted_journal_commit(isolated_env):
    """Fault 8: Interruption after PROMOTED journal commit before database transaction."""
    class Interrupted(Exception): pass

    def injector(hook_name):
        if hook_name == "after_promoted_journal_commit":
            raise Interrupted("Crash after PROMOTED journal commit")

    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"], fault_injector=injector)
    conn = engine.connect_database()

    item = {
        "source_path": str(isolated_env["hist_file"]),
        "parent_folder": "ASM-01",
        "artifact_id": "EVD-hist01",
        "primary_disposition": "HISTORICAL_ARCHIVE",
        "sha256": isolated_env["hist_sha"],
        "byte_size": isolated_env["hist_size"],
    }

    with pytest.raises(Interrupted):
        engine.migrate_single_artifact(conn, "OP-F08", item, sequence=1)

    cursor = conn.cursor()
    cursor.execute("SELECT id, state, staged_path, target_path FROM migration_journal WHERE operation_id = 'OP-F08';")
    row = cursor.fetchone()
    assert row[1] == MigrationState.PROMOTED.value

    rec_svc = MigrationRecoveryService(conn=conn, outbox=engine.outbox, archive_mgr=engine.archive_mgr, maintenance_session=isolated_env["session"])
    rec_svc.recover_all_pending(operation_id="OP-F08")

    cursor.execute("SELECT state FROM migration_journal WHERE operation_id = 'OP-F08';")
    assert cursor.fetchone()[0] == MigrationState.COMMITTED.value
    conn.close()


def test_fault_09_during_evidence_insert_transaction(isolated_env):
    """Fault 9: Interruption during active evidence INSERT rolls back cleanly."""
    class Interrupted(Exception): pass

    def injector(hook_name):
        if hook_name == "during_evidence_insert_transaction":
            raise Interrupted("Crash during evidence INSERT transaction")

    # Seed parent hierarchy
    conn = sqlite3.connect(isolated_env["db_path"])
    cur = conn.cursor()
    cur.execute("INSERT INTO engagements VALUES ('ENG-01', 'WKP-DEFAULT', 'Eng', 'active', '2026-11-01', '2026-11-01');")
    cur.execute("INSERT INTO assessments VALUES ('ASM-001', 'ENG-01', 'Asm', 'completed', '2026-11-01', '2026-11-01');")
    conn.commit()
    conn.close()

    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"], fault_injector=injector)
    conn = engine.connect_database()

    item = {
        "source_path": str(isolated_env["active_file"]),
        "parent_folder": "ASM-001",
        "artifact_id": "EVD-active01",
        "assessment_id": "ASM-001",
        "primary_disposition": "ACTIVE_MIGRATION_CANDIDATE",
        "sha256": isolated_env["active_sha"],
        "byte_size": isolated_env["active_size"],
    }

    with pytest.raises(Interrupted):
        engine.migrate_single_artifact(conn, "OP-F09", item, sequence=1)

    # Assert 0 rows inserted in evidence table (clean transaction rollback)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM evidence WHERE id = 'EVD-active01';")
    assert cursor.fetchone()[0] == 0

    # Journal state is still PROMOTED
    cursor.execute("SELECT state FROM migration_journal WHERE operation_id = 'OP-F09';")
    assert cursor.fetchone()[0] == MigrationState.PROMOTED.value
    conn.close()


def test_fault_10_after_database_commit_before_staging_cleanup(isolated_env):
    """Fault 10: Interruption after DB commit before staging cleanup; recovery cleans staging."""
    class Interrupted(Exception): pass

    def injector(hook_name):
        if hook_name == "after_database_commit_before_staging_cleanup":
            raise Interrupted("Crash after DB commit before staging cleanup")

    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"], fault_injector=injector)
    conn = engine.connect_database()

    item = {
        "source_path": str(isolated_env["hist_file"]),
        "parent_folder": "ASM-01",
        "artifact_id": "EVD-hist01",
        "primary_disposition": "HISTORICAL_ARCHIVE",
        "sha256": isolated_env["hist_sha"],
        "byte_size": isolated_env["hist_size"],
    }

    with pytest.raises(Interrupted):
        engine.migrate_single_artifact(conn, "OP-F10", item, sequence=1)

    cursor = conn.cursor()
    cursor.execute("SELECT id, state, staged_path, target_path FROM migration_journal WHERE operation_id = 'OP-F10';")
    row = cursor.fetchone()
    assert row[1] == MigrationState.COMMITTED.value
    staged_p = Path(row[2])
    target_p = Path(row[3])
    assert staged_p.exists()
    assert target_p.exists()

    # Recovery removes the orphan staging file without altering committed state
    rec_svc = MigrationRecoveryService(conn=conn, outbox=engine.outbox, archive_mgr=engine.archive_mgr, maintenance_session=isolated_env["session"])
    rec_svc.recover_all_pending(operation_id="OP-F10")

    assert not staged_p.exists()
    assert target_p.exists()
    cursor.execute("SELECT state FROM migration_journal WHERE operation_id = 'OP-F10';")
    assert cursor.fetchone()[0] == MigrationState.COMMITTED.value
    conn.close()


def test_fault_11_during_jsonl_append(isolated_env):
    """Fault 11: Interruption during JSONL append leaves jsonl_delivered_at NULL; recovery delivers."""
    class Interrupted(Exception): pass

    def injector(hook_name):
        if hook_name == "during_jsonl_append":
            raise Interrupted("Crash during JSONL append")

    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"], fault_injector=injector)
    conn = engine.connect_database()

    item = {
        "source_path": str(isolated_env["hist_file"]),
        "parent_folder": "ASM-01",
        "artifact_id": "EVD-hist01",
        "primary_disposition": "HISTORICAL_ARCHIVE",
        "sha256": isolated_env["hist_sha"],
        "byte_size": isolated_env["hist_size"],
    }

    with pytest.raises(Interrupted):
        engine.migrate_single_artifact(conn, "OP-F11", item, sequence=1)

    cursor = conn.cursor()
    cursor.execute("SELECT id, state, jsonl_delivered_at FROM migration_journal WHERE operation_id = 'OP-F11';")
    row = cursor.fetchone()
    assert row[1] == MigrationState.COMMITTED.value
    assert row[2] is None

    # Recovery detects undelivered event and delivers to JSONL outbox
    rec_svc = MigrationRecoveryService(conn=conn, outbox=engine.outbox, archive_mgr=engine.archive_mgr, maintenance_session=isolated_env["session"])
    rec_svc.recover_all_pending(operation_id="OP-F11")

    cursor.execute("SELECT jsonl_delivered_at FROM migration_journal WHERE operation_id = 'OP-F11';")
    assert cursor.fetchone()[0] is not None
    assert engine.outbox.outbox_path.exists()
    conn.close()


def test_fault_12_after_jsonl_fsync_before_delivered_at_update(isolated_env):
    """Fault 12: Event in JSONL but SQLite jsonl_delivered_at NULL; recovery avoids duplicate."""
    class Interrupted(Exception): pass

    def injector(hook_name):
        if hook_name == "after_jsonl_fsync_before_delivered_at_update":
            raise Interrupted("Crash after JSONL fsync before delivered_at update")

    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"], fault_injector=injector)
    conn = engine.connect_database()

    item = {
        "source_path": str(isolated_env["hist_file"]),
        "parent_folder": "ASM-01",
        "artifact_id": "EVD-hist01",
        "primary_disposition": "HISTORICAL_ARCHIVE",
        "sha256": isolated_env["hist_sha"],
        "byte_size": isolated_env["hist_size"],
    }

    with pytest.raises(Interrupted):
        engine.migrate_single_artifact(conn, "OP-F12", item, sequence=1)

    cursor = conn.cursor()
    cursor.execute("SELECT id, event_id, jsonl_delivered_at FROM migration_journal WHERE operation_id = 'OP-F12';")
    row = cursor.fetchone()
    event_id = row[1]
    assert row[2] is None

    # JSONL already contains this event!
    seen, _ = engine.outbox.scan_existing_events()
    assert event_id in seen
    initial_line_count = len(engine.outbox.outbox_path.read_text(encoding="utf-8").strip().splitlines())

    # Recovery runs: must NOT re-append duplicate event into JSONL
    rec_svc = MigrationRecoveryService(conn=conn, outbox=engine.outbox, archive_mgr=engine.archive_mgr, maintenance_session=isolated_env["session"])
    rec_svc.recover_all_pending(operation_id="OP-F12")

    post_line_count = len(engine.outbox.outbox_path.read_text(encoding="utf-8").strip().splitlines())
    assert post_line_count == initial_line_count

    cursor.execute("SELECT jsonl_delivered_at FROM migration_journal WHERE operation_id = 'OP-F12';")
    assert cursor.fetchone()[0] is not None
    conn.close()


def test_fault_13_recovery_idempotency(isolated_env):
    """Fault 13: Recovery is completely idempotent when invoked repeatedly."""
    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"])
    conn = engine.connect_database()

    item = {
        "source_path": str(isolated_env["hist_file"]),
        "parent_folder": "ASM-01",
        "artifact_id": "EVD-hist01",
        "primary_disposition": "HISTORICAL_ARCHIVE",
        "sha256": isolated_env["hist_sha"],
        "byte_size": isolated_env["hist_size"],
    }
    engine.migrate_single_artifact(conn, "OP-F13", item, sequence=1)

    rec_svc = MigrationRecoveryService(conn=conn, outbox=engine.outbox, archive_mgr=engine.archive_mgr, maintenance_session=isolated_env["session"])
    # Run recovery 3 times consecutively
    r1 = rec_svc.recover_all_pending(operation_id="OP-F13")
    r2 = rec_svc.recover_all_pending(operation_id="OP-F13")
    r3 = rec_svc.recover_all_pending(operation_id="OP-F13")

    assert len(r1) == 0
    assert len(r2) == 0
    assert len(r3) == 0
    conn.close()


def test_fault_14_process_lock_contention(isolated_env):
    """Fault 14: Two-process lock contention raises ProcessLockError."""
    lock_file = isolated_env["tmp_path"] / "contention_test.lock"
    lock1 = InstanceLock(lock_file)
    lock1.acquire()

    lock2 = InstanceLock(lock_file)
    with pytest.raises(ProcessLockError):
        lock2.acquire()

    lock1.release()
    # Now lock2 can acquire
    lock2.acquire()
    lock2.release()


def test_fault_15_destination_collision_fails_closed(isolated_env):
    """Fault 15: Destination pre-exists; fails closed with MigrationCollisionError."""
    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"])
    conn = engine.connect_database()

    target_path = isolated_env["dest_data_dir"] / "archive" / "evidence" / "ASM-01" / "EVD-hist01.json"
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_bytes(b"existing-important-data")

    item = {
        "source_path": str(isolated_env["hist_file"]),
        "parent_folder": "ASM-01",
        "artifact_id": "EVD-hist01",
        "primary_disposition": "HISTORICAL_ARCHIVE",
        "sha256": isolated_env["hist_sha"],
        "byte_size": isolated_env["hist_size"],
    }

    with pytest.raises(MigrationCollisionError):
        engine.migrate_single_artifact(conn, "OP-F15", item, sequence=1)

    # Verify existing target was NEVER overwritten
    assert target_path.read_bytes() == b"existing-important-data"

    # Journal recorded BLOCKED_COLLISION
    cursor = conn.cursor()
    cursor.execute("SELECT state FROM migration_journal WHERE operation_id = 'OP-F15';")
    assert cursor.fetchone()[0] == MigrationState.BLOCKED_COLLISION.value
    conn.close()


# =====================================================================
# 4. SAFETY, PARENT VALIDATION & ARCHIVE MANIFESTS
# =====================================================================

def test_production_safety_guard_rejects_production_dir(isolated_env):
    """Verify MigrationSafetyError raised when targeting %LOCALAPPDATA%\\AllTools-CyberSec."""
    local_app = os.environ.get("LOCALAPPDATA")
    if not local_app:
        pytest.skip("LOCALAPPDATA environment variable not defined on this platform.")

    prod_dir = Path(local_app) / "AllTools-CyberSec"
    with pytest.raises(MigrationSafetyError):
        MigrationEngine(data_dir=prod_dir, maintenance_session=isolated_env["session"])


def test_active_candidate_blocked_missing_parent(isolated_env):
    """Verify active candidate transitions to BLOCKED_MISSING_PARENT when relational parents missing."""
    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"])
    conn = engine.connect_database()

    item = {
        "source_path": str(isolated_env["active_file"]),
        "parent_folder": "ASM-001",
        "artifact_id": "EVD-active01",
        "assessment_id": "ASM-001",
        "primary_disposition": "ACTIVE_MIGRATION_CANDIDATE",
        "sha256": isolated_env["active_sha"],
        "byte_size": isolated_env["active_size"],
    }

    result = engine.migrate_single_artifact(conn, "OP-ACT-BLOCK", item, sequence=1)
    assert result.state == MigrationState.BLOCKED_MISSING_PARENT
    conn.close()


def test_active_candidate_commits_when_parents_exist(isolated_env):
    """Verify active candidate atomically inserts into evidence table and commits."""
    # Seed parent hierarchy
    conn = sqlite3.connect(isolated_env["db_path"])
    cur = conn.cursor()
    cur.execute("INSERT INTO engagements VALUES ('ENG-01', 'WKP-DEFAULT', 'Eng', 'active', '2026-11-01', '2026-11-01');")
    cur.execute("INSERT INTO assessments VALUES ('ASM-001', 'ENG-01', 'Asm', 'completed', '2026-11-01', '2026-11-01');")
    conn.commit()
    conn.close()

    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"])
    conn = engine.connect_database()

    item = {
        "source_path": str(isolated_env["active_file"]),
        "parent_folder": "ASM-001",
        "artifact_id": "EVD-active01",
        "assessment_id": "ASM-001",
        "primary_disposition": "ACTIVE_MIGRATION_CANDIDATE",
        "sha256": isolated_env["active_sha"],
        "byte_size": isolated_env["active_size"],
    }

    result = engine.migrate_single_artifact(conn, "OP-ACT-OK", item, sequence=1)
    assert result.state == MigrationState.COMMITTED

    # Verify inserted row in evidence table
    cursor = conn.cursor()
    cursor.execute("SELECT id, assessment_id, sync_status, sha256 FROM evidence WHERE id = 'EVD-active01';")
    row = cursor.fetchone()
    assert row is not None
    assert row[0] == "EVD-active01"
    assert row[1] == "ASM-001"
    assert row[2] == "COMMITTED"
    assert row[3] == isolated_env["active_sha"]
    conn.close()


def test_archive_manifest_and_jsonl_tail_preservation(isolated_env):
    """Verify archive_manifest.jsonl writing and non-destructive malformed tail handling."""
    data_dir = isolated_env["dest_data_dir"]
    outbox_file = data_dir / "migration_journal.jsonl"
    outbox = JSONLAuditOutbox(outbox_file)

    # Simulate existing corrupted tail fragment without newline
    outbox_file.write_bytes(b'{"event_id":"old-evt-1"}\n{"incomplete_tail":"some-bytes')

    seen_ids, tail_diag = outbox.scan_existing_events()
    assert "old-evt-1" in seen_ids
    assert tail_diag is not None
    assert tail_diag["length"] > 0

    # Append new event: verify it prepends newline and preserves existing tail
    entry = MigrationJournalEntry(
        operation_id="OP-TAIL",
        artifact_id="ART-100",
        parent_folder="ASM-01",
        source_path="ASM-01/ART-100.json",
        staged_path="staged.tmp",
        target_path="target.json",
        sha256="abc",
        byte_size=10,
        state=MigrationState.COMMITTED,
        sequence=1,
        created_at="2026-11-01T00:00:00Z",
        updated_at="2026-11-01T00:00:00Z",
        event_id="new-evt-2",
    )
    outbox.append_event(entry)

    # Verify both incomplete tail and new event are in the file
    content = outbox_file.read_bytes()
    assert b'{"incomplete_tail":"some-bytes' in content
    assert b'new-evt-2' in content

    # Test ArchiveManager manifest with maintenance session
    archive_mgr = ArchiveManager(data_dir=data_dir, maintenance_session=isolated_env["session"])
    target_art = data_dir / "archive" / "evidence" / "ASM-01" / "ART-100.json"
    target_art.parent.mkdir(parents=True, exist_ok=True)
    content_art = b'{"art": 100}'
    target_art.write_bytes(content_art)
    sha_art = hashlib.sha256(content_art).hexdigest()

    m_entry = archive_mgr.append_manifest_entry(
        source_path="ASM-01/ART-100.json",
        target_path=str(target_art),
        sha256=sha_art,
        byte_size=len(content_art),
        filename="ART-100.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-TAIL",
    )
    assert m_entry.filename == "ART-100.json"
    manifest_entries = archive_mgr.read_manifest_entries()
    assert len(manifest_entries) == 1
    assert manifest_entries[0].operation_id == "OP-TAIL"


# =====================================================================
# 5. F-01: ENGINE-LEVEL MAINTENANCE LOCK ENFORCEMENT TESTS
# =====================================================================

def test_f01_direct_engine_invocation_without_lock_fails(isolated_env):
    """F-01: Direct MigrationEngine invocation without valid lock ownership must fail closed."""
    paths = isolated_env["paths"]
    with pytest.raises(ProcessLockError) as exc_info:
        MigrationEngine(paths=paths)  # No maintenance session or lock provided
    assert "Direct MigrationEngine invocation without exclusive maintenance lock ownership is strictly prohibited" in str(exc_info.value)


def test_f01_direct_recovery_invocation_without_lock_fails(isolated_env):
    """F-01: Direct recovery invocation without valid lock ownership must fail closed."""
    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"])
    conn = engine.connect_database()
    with pytest.raises(ProcessLockError) as exc_info:
        MigrationRecoveryService(conn=conn, outbox=engine.outbox, archive_mgr=engine.archive_mgr)
    assert "Direct MigrationRecoveryService invocation without exclusive maintenance lock ownership is strictly prohibited" in str(exc_info.value)
    conn.close()


def test_f01_direct_archive_manager_publication_without_lock_fails(isolated_env):
    """F-01: Direct ArchiveManager publication without valid lock ownership must fail closed."""
    unlocked_archive_mgr = ArchiveManager(data_dir=isolated_env["dest_data_dir"])
    with pytest.raises(ProcessLockError) as exc_info:
        unlocked_archive_mgr.append_manifest_entry(
            source_path="ASM-01/test.json",
            target_path=str(isolated_env["dest_data_dir"] / "archive/evidence/ASM-01/test.json"),
            sha256="aaa",
            byte_size=10,
            filename="test.json",
            classification="HISTORICAL_ARCHIVE",
            operation_id="OP-NOLOCK",
        )
    assert "Direct ArchiveManager publication without an active exclusive maintenance lock is strictly prohibited" in str(exc_info.value)


def test_f01_cli_acquires_lock_successfully(isolated_env):
    """F-01: CLI acquires lock successfully in an isolated test sandbox."""
    cli_sandbox = isolated_env["tmp_path"] / "cli_sandbox"
    cli_sandbox.mkdir()
    cmd = [
        sys.executable,
        str(Path(__file__).resolve().parent.parent / "backend" / "app" / "cli" / "migrate_evidence.py"),
        "--data-dir",
        str(cli_sandbox),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0
    assert "Migration CLI initialized in isolated sandbox" in proc.stdout


def test_f01_backend_owned_lock_rejects_cli(isolated_env):
    """F-01: Backend-owned lock rejects CLI with exit code 3 (fail-closed)."""
    # isolated_env["lock"] is already acquired in the fixture!
    cmd = [
        sys.executable,
        str(Path(__file__).resolve().parent.parent / "backend" / "app" / "cli" / "migrate_evidence.py"),
        "--data-dir",
        str(isolated_env["dest_data_dir"]),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 3
    assert "[FATAL] Lock acquisition failed" in proc.stderr


# =====================================================================
# 6. F-02: ARCHIVE MANIFEST RECOVERY & IDEMPOTENCY TESTS
# =====================================================================

def test_f02_archive_manifest_stable_record_id(isolated_env):
    """F-02: Verify stable deterministic record ID derived from canonical identity fields."""
    from app.services.migration_models import generate_manifest_record_id_v1, generate_manifest_record_id_v2

    # V1 legacy generator check
    rec_v1_1 = generate_manifest_record_id_v1("OP-01", "ART-01", "sha256_value_abc")
    rec_v1_2 = generate_manifest_record_id_v1("OP-01", "ART-01", "sha256_value_abc")
    rec_v1_3 = generate_manifest_record_id_v1("OP-02", "ART-01", "sha256_value_abc")
    assert rec_v1_1 == rec_v1_2
    assert rec_v1_1 != rec_v1_3
    assert rec_v1_1.startswith("man-ART-01-")

    # V2 permanent generator check
    rec_v2_1 = generate_manifest_record_id_v2("ASM-01/ART-01.json", "ART-01")
    rec_v2_2 = generate_manifest_record_id_v2("asm-01/art-01.json", "ART-01")
    assert rec_v2_1 == rec_v2_2
    assert len(rec_v2_1) == 64


def test_f02_archive_manifest_idempotent_duplicate_append(isolated_env):
    """F-02: Repeated append of the same manifest entry does not duplicate records in JSONL."""
    archive_mgr = ArchiveManager(data_dir=isolated_env["dest_data_dir"], maintenance_session=isolated_env["session"])
    target_p = isolated_env["dest_data_dir"] / "archive" / "evidence" / "ASM-01" / "EVD-01.json"
    target_p.parent.mkdir(parents=True, exist_ok=True)
    content = b'{"evd": "01", "test": true}'
    target_p.write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()
    size = len(content)

    e1 = archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-01.json",
        target_path=str(target_p),
        sha256=sha,
        byte_size=size,
        filename="EVD-01.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-IDEM",
        artifact_id="EVD-01",
    )
    # Append identical entry again
    e2 = archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-01.json",
        target_path=str(target_p),
        sha256=sha,
        byte_size=size,
        filename="EVD-01.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-IDEM",
        artifact_id="EVD-01",
    )
    assert e1.manifest_record_id == e2.manifest_record_id

    records = archive_mgr.read_manifest_entries()
    assert len(records) == 1


def test_f02_archive_manifest_conflicting_record_id_fails(isolated_env):
    """F-02: Conflicting manifest record ID with differing content raises MigrationIntegrityError."""
    archive_mgr = ArchiveManager(data_dir=isolated_env["dest_data_dir"], maintenance_session=isolated_env["session"])
    target_p = isolated_env["dest_data_dir"] / "archive" / "evidence" / "ASM-01" / "EVD-01.json"
    target_p.parent.mkdir(parents=True, exist_ok=True)
    content = b'{"evd": "01", "test": true}'
    target_p.write_bytes(content)
    sha = hashlib.sha256(content).hexdigest()
    size = len(content)

    archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-01.json",
        target_path=str(target_p),
        sha256=sha,
        byte_size=size,
        filename="EVD-01.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-CONFLICT",
        artifact_id="EVD-01",
    )

    # Force conflicting entry by injecting different target path under the same record ID
    rec_id = generate_manifest_record_id_v2("ASM-01/EVD-01.json", "EVD-01")
    seen_records, _ = archive_mgr.scan_existing_records()
    assert rec_id in seen_records

    # Create the different target file on disk so the conflict check (not missing target check) triggers
    diff_target = isolated_env["dest_data_dir"] / "archive" / "evidence" / "ASM-01" / "DIFFERENT_TARGET.json"
    diff_target.write_bytes(content)

    # Attempt appending same record ID to a conflicting target destination
    with pytest.raises(MigrationIntegrityError) as exc_info:
        archive_mgr.append_manifest_entry(
            source_path="ASM-01/EVD-01.json",
            target_path=str(diff_target),
            sha256=sha,
            byte_size=size,
            filename="DIFFERENT_TARGET.json",
            classification="HISTORICAL_ARCHIVE",
            operation_id="OP-CONFLICT",
            artifact_id="EVD-01",
        )
    assert "Different destination path for existing identity" in str(exc_info.value) or "Conflicting" in str(exc_info.value)


def test_f02_archive_manifest_recovery_backfills_missing_records(isolated_env):
    """F-02: Recovery backfills missing archive manifest entries from committed SQLite journal."""
    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"])
    conn = engine.connect_database()

    # Simulate an artifact committed in SQLite with target published on disk, but manifest was missing
    target_p = isolated_env["dest_data_dir"] / "archive" / "evidence" / "ASM-01" / "EVD-hist01.json"
    target_p.parent.mkdir(parents=True, exist_ok=True)
    target_p.write_bytes(b"{\"test\": \"historical\", \"timestamp\": \"2026-10-31\"}")

    staged_p = isolated_env["dest_data_dir"] / ".staging" / "OP-BACKFILL" / "staged.tmp"

    entry = MigrationJournal.record_discovered(
        conn=conn,
        operation_id="OP-BACKFILL",
        artifact_id="EVD-hist01",
        parent_folder="ASM-01",
        source_path=str(isolated_env["hist_file"]),
        staged_path=str(staged_p),
        target_path=str(target_p),
        sha256=isolated_env["hist_sha"],
        byte_size=isolated_env["hist_size"],
        sequence=1,
    )
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.DISCOVERED, MigrationState.VALIDATED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.VALIDATED, MigrationState.STAGED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.STAGED, MigrationState.VERIFIED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.VERIFIED, MigrationState.PROMOTION_INTENT_RECORDED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.PROMOTION_INTENT_RECORDED, MigrationState.PROMOTED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.PROMOTED, MigrationState.COMMITTED)

    # Manifest file is currently empty!
    assert len(engine.archive_mgr.read_manifest_entries()) == 0

    # Run recovery
    rec_svc = MigrationRecoveryService(
        conn=conn,
        outbox=engine.outbox,
        archive_mgr=engine.archive_mgr,
        maintenance_session=isolated_env["session"],
    )
    rec_svc.recover_all_pending(operation_id="OP-BACKFILL")

    # Manifest must now have the backfilled record!
    manifest_records = engine.archive_mgr.read_manifest_entries()
    assert len(manifest_records) == 1
    assert manifest_records[0].artifact_id == "EVD-hist01"
    assert manifest_records[0].operation_id == "OP-BACKFILL"
    assert manifest_records[0].physical_sha256 == isolated_env["hist_sha"]

    # Target destination was preserved
    assert target_p.exists()
    conn.close()


def test_f02_archive_manifest_repeated_recovery_idempotency(isolated_env):
    """F-02: Repeated recovery runs on backfilled records are 100% idempotent."""
    engine = MigrationEngine(paths=isolated_env["paths"], maintenance_session=isolated_env["session"])
    conn = engine.connect_database()

    target_p = isolated_env["dest_data_dir"] / "archive" / "evidence" / "ASM-01" / "EVD-hist01.json"
    target_p.parent.mkdir(parents=True, exist_ok=True)
    target_p.write_bytes(b"{\"test\": \"historical\", \"timestamp\": \"2026-10-31\"}")

    entry = MigrationJournal.record_discovered(
        conn=conn,
        operation_id="OP-IDEM-REC",
        artifact_id="EVD-hist01",
        parent_folder="ASM-01",
        source_path=str(isolated_env["hist_file"]),
        staged_path="staged.tmp",
        target_path=str(target_p),
        sha256=isolated_env["hist_sha"],
        byte_size=isolated_env["hist_size"],
        sequence=1,
    )
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.DISCOVERED, MigrationState.VALIDATED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.VALIDATED, MigrationState.STAGED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.STAGED, MigrationState.VERIFIED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.VERIFIED, MigrationState.PROMOTION_INTENT_RECORDED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.PROMOTION_INTENT_RECORDED, MigrationState.PROMOTED)
    entry = MigrationJournal.transition_state(conn, entry.id, MigrationState.PROMOTED, MigrationState.COMMITTED)

    rec_svc = MigrationRecoveryService(
        conn=conn,
        outbox=engine.outbox,
        archive_mgr=engine.archive_mgr,
        maintenance_session=isolated_env["session"],
    )

    # Run recovery 3 times consecutively
    rec_svc.recover_all_pending(operation_id="OP-IDEM-REC")
    rec_svc.recover_all_pending(operation_id="OP-IDEM-REC")
    rec_svc.recover_all_pending(operation_id="OP-IDEM-REC")

    manifest_records = engine.archive_mgr.read_manifest_entries()
    assert len(manifest_records) == 1
    conn.close()
