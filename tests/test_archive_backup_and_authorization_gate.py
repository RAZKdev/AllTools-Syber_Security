"""
Tests for Archive Backup Manager and Production Authorization Gate - Phase E3B.

Covers 14 synthetic scenarios:
1. Physical device independence checks (same disk fails closed, distinct disks passes).
2. Archive backup generation with streaming copy and hash/size verification.
3. Backup integrity verification (archive_backup_manifest.json).
4. Archive restore validation in an isolated target directory.
5. Interrupted archive backup recovery (.staging cleanup).
6. Authorization bound to exact plan hash.
7. Authorization invalidation after plan modification.
8. Authorization invalidation after inventory modification.
9. Destination mismatch rejection.
10. One-time authorization nonce consumption (replay fails closed).
11. Active candidate exclusion guard (ASM-001/EVD-3965036b.json).
12. Source retention invariant (source files unmutated).
13. No-clobber backup publication.
14. Maintenance lock enforcement on backup and gate operations.
"""

import hashlib
import json
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import pytest

from app.core.instance_lock import InstanceLock, MaintenanceSession, ProcessLockError
from app.core.storage_paths import StoragePaths
from app.services.archive_backup_manager import (
    ArchiveBackupCollisionError,
    ArchiveBackupIntegrityError,
    ArchiveBackupManager,
    ArchiveRestoreError,
    PhysicalStorageIndependenceError,
    verify_physical_device_independence,
)
from app.services.migration_authorization import (
    AuthorizationConfirmationError,
    AuthorizationConsumedError,
    AuthorizationDestinationError,
    AuthorizationExpiredError,
    AuthorizationGateError,
    AuthorizationIntegrityError,
    AuthorizationLedger,
    AuthorizationScopeError,
    AuthorizationVolumeError,
    ProductionMigrationAuthorization,
    ProductionMigrationAuthorizationGate,
)
from app.services.migration_engine import MigrationEngine
from app.services.migration_models import MigrationSafetyError


@pytest.fixture
def synthetic_archive(tmp_path: Path):
    """Create a synthetic archive root with sample files and a manifest."""
    archive_root = tmp_path / "archive"
    archive_root.mkdir(parents=True)

    ev_dir = archive_root / "evidence" / "ASM-001"
    ev_dir.mkdir(parents=True)
    f1 = ev_dir / "EVD-syn1.json"
    f1.write_text(json.dumps({"id": "EVD-syn1", "content": "synthetic_1"}), encoding="utf-8")

    test_dir = archive_root / "tests" / "ASM-002"
    test_dir.mkdir(parents=True)
    f2 = test_dir / "EVD-syn2.json"
    f2.write_text(json.dumps({"id": "EVD-syn2", "content": "synthetic_2"}), encoding="utf-8")

    malformed_dir = archive_root / "tests" / "malformed"
    malformed_dir.mkdir(parents=True)
    f3 = malformed_dir / "EVD-syn3.json"
    f3.write_text("{invalid_json: true", encoding="utf-8")

    manifest = archive_root / "archive_manifest.jsonl"
    manifest.write_text(
        json.dumps({"manifest_record_id": "rec-1", "artifact_id": "EVD-syn1"}) + "\n" +
        json.dumps({"manifest_record_id": "rec-2", "artifact_id": "EVD-syn2"}) + "\n" +
        json.dumps({"manifest_record_id": "rec-3", "artifact_id": "EVD-syn3"}) + "\n",
        encoding="utf-8"
    )

    return archive_root


@pytest.fixture
def synthetic_plan_and_inventory(tmp_path: Path):
    """Create synthetic plan and inventory files for authorization testing."""
    src_dir = tmp_path / "source_evidence"
    src_dir.mkdir(parents=True)

    inv_file = src_dir / "legacy-evidence-inventory.json"
    inv_data = {
        "metadata": {"total": 174},
        "inventory": [
            {"artifact_id": f"EVD-{i:03d}", "source_relative_path": f"ASM-001/EVD-{i:03d}.json"}
            for i in range(174)
        ]
    }
    inv_content = json.dumps(inv_data, indent=2)
    inv_file.write_text(inv_content, encoding="utf-8")
    inv_sha = hashlib.sha256(inv_file.read_bytes()).hexdigest()

    plan_file = tmp_path / "phase-e3b-final-migration-plan.json"
    plan_data = {
        "plan_version": "2.0.0",
        "archive_candidates_count": 173,
        "excluded_active_candidates_count": 1,
        "excluded_active_candidate": "ASM-001/EVD-3965036b.json",
    }
    plan_content = json.dumps(plan_data, indent=2)
    plan_file.write_text(plan_content, encoding="utf-8")
    plan_sha = hashlib.sha256(plan_file.read_bytes()).hexdigest()

    return {
        "src_dir": src_dir,
        "inv_file": inv_file,
        "inv_sha": inv_sha,
        "plan_file": plan_file,
        "plan_sha": plan_sha,
    }


# ============================================================================
# 1. Physical Device Independence Checks
# ============================================================================

def test_physical_device_independence_same_disk_fails_closed(synthetic_archive, tmp_path: Path):
    """Verifies that backup fails closed when target is on the same physical storage device."""
    backup_root = tmp_path / "backups"

    # Mock resolver returning the same disk identifier
    def mock_same_disk(p: Path) -> str:
        return "0:RX7_SERIAL_128GB"

    mgr = ArchiveBackupManager(archive_root=synthetic_archive, custom_disk_resolver=mock_same_disk)
    with pytest.raises(PhysicalStorageIndependenceError) as exc_info:
        mgr.create_backup(target_backup_root=backup_root, require_physical_independence=True)

    assert "resides on the same physical storage device" in str(exc_info.value)
    assert not backup_root.exists() or len(list(backup_root.glob("ABKP*"))) == 0


def test_physical_device_independence_distinct_disks_passes(synthetic_archive, tmp_path: Path):
    """Verifies that backup succeeds when target is on a distinct physical storage device."""
    backup_root = tmp_path / "backups"

    def mock_distinct_disks(p: Path) -> str:
        res = p.resolve()
        if res == synthetic_archive.resolve() or synthetic_archive.resolve() in res.parents:
            return "0:RX7_SERIAL_128GB"
        return "1:EXTERNAL_USB_512GB"

    mgr = ArchiveBackupManager(archive_root=synthetic_archive, custom_disk_resolver=mock_distinct_disks)
    manifest = mgr.create_backup(target_backup_root=backup_root, require_physical_independence=True)

    assert manifest.is_physically_independent is True
    assert manifest.source_disk_id == "0:RX7_SERIAL_128GB"
    assert manifest.target_disk_id == "1:EXTERNAL_USB_512GB"
    assert Path(manifest.target_backup_dir).exists()


# ============================================================================
# 2. Archive Backup Generation with Streaming Copy and Hash/Size Verification
# ============================================================================

def test_archive_backup_generation_streaming_and_hashes(synthetic_archive, tmp_path: Path):
    """Verifies streaming copy, cryptographic hash calculation, and byte verification."""
    backup_root = tmp_path / "backups"

    def mock_distinct_disks(p: Path) -> str:
        res = p.resolve()
        return "0:DISK_A" if (res == synthetic_archive.resolve() or synthetic_archive.resolve() in res.parents) else "1:DISK_B"

    mgr = ArchiveBackupManager(archive_root=synthetic_archive, custom_disk_resolver=mock_distinct_disks)
    manifest = mgr.create_backup(target_backup_root=backup_root, generation_id="ABKP-TEST-001")

    assert manifest.total_files == 4  # 3 json files + 1 manifest file
    assert manifest.backup_id == "ABKP-TEST-001"

    dest_dir = Path(manifest.target_backup_dir)
    assert dest_dir.exists()
    for entry in manifest.files:
        backed_up_file = dest_dir / entry.relative_path
        assert backed_up_file.exists()
        assert backed_up_file.stat().st_size == entry.byte_size
        actual_sha = hashlib.sha256(backed_up_file.read_bytes()).hexdigest()
        assert actual_sha == entry.sha256


# ============================================================================
# 3. Backup Integrity Verification (archive_backup_manifest.json)
# ============================================================================

def test_backup_integrity_manifest_structure(synthetic_archive, tmp_path: Path):
    """Verifies archive_backup_manifest.json contents, records count, and manifest sha."""
    backup_root = tmp_path / "backups"

    def mock_distinct_disks(p: Path) -> str:
        res = p.resolve()
        return "0:SRC" if (res == synthetic_archive.resolve() or synthetic_archive.resolve() in res.parents) else "1:TGT"

    mgr = ArchiveBackupManager(archive_root=synthetic_archive, custom_disk_resolver=mock_distinct_disks)
    manifest = mgr.create_backup(target_backup_root=backup_root)

    manifest_file = Path(manifest.target_backup_dir) / "archive_backup_manifest.json"
    assert manifest_file.exists()

    data = json.loads(manifest_file.read_text(encoding="utf-8"))
    assert data["backup_id"] == manifest.backup_id
    assert data["manifest_records_count"] == 3
    assert len(data["files"]) == manifest.total_files
    assert data["is_physically_independent"] is True


# ============================================================================
# 4. Archive Restore Validation in an Isolated Target Directory
# ============================================================================

def test_archive_restore_validation_in_isolated_target(synthetic_archive, tmp_path: Path):
    """Verifies that validate_and_restore successfully restores and validates byte fidelity."""
    backup_root = tmp_path / "backups"

    def mock_distinct_disks(p: Path) -> str:
        res = p.resolve()
        return "0:SRC" if (res == synthetic_archive.resolve() or synthetic_archive.resolve() in res.parents) else "1:TGT"

    mgr = ArchiveBackupManager(archive_root=synthetic_archive, custom_disk_resolver=mock_distinct_disks)
    manifest = mgr.create_backup(target_backup_root=backup_root)

    restore_target = tmp_path / "restored_archive"
    result = mgr.validate_and_restore(
        backup_dir=Path(manifest.target_backup_dir),
        target_restore_dir=restore_target,
    )

    assert result["status"] == "RESTORE_VERIFIED_SUCCESS"
    assert result["restored_files"] == manifest.total_files
    assert result["restored_bytes"] == manifest.total_bytes

    # Check restored file fidelity
    for entry in manifest.files:
        rf = restore_target / entry.relative_path
        assert rf.exists()
        assert hashlib.sha256(rf.read_bytes()).hexdigest() == entry.sha256


def test_archive_restore_fails_on_corrupted_backup(synthetic_archive, tmp_path: Path):
    """Verifies that corrupted backup files trigger ArchiveRestoreError."""
    backup_root = tmp_path / "backups"

    def mock_distinct_disks(p: Path) -> str:
        res = p.resolve()
        return "0:SRC" if (res == synthetic_archive.resolve() or synthetic_archive.resolve() in res.parents) else "1:TGT"

    mgr = ArchiveBackupManager(archive_root=synthetic_archive, custom_disk_resolver=mock_distinct_disks)
    manifest = mgr.create_backup(target_backup_root=backup_root)

    # Corrupt one file in the backup
    corrupt_file = Path(manifest.target_backup_dir) / manifest.files[0].relative_path
    corrupt_file.write_bytes(b"corrupted_bytes_here")

    restore_target = tmp_path / "restored_archive"
    with pytest.raises(ArchiveRestoreError) as exc_info:
        mgr.validate_and_restore(
            backup_dir=Path(manifest.target_backup_dir),
            target_restore_dir=restore_target,
        )
    assert "Backup corruption detected" in str(exc_info.value)


# ============================================================================
# 5. Interrupted Archive Backup Recovery (.staging cleanup)
# ============================================================================

def test_interrupted_archive_backup_recovery(synthetic_archive, tmp_path: Path):
    """Verifies that abandoned staging directories are safely cleaned up and journaled."""
    backup_root = tmp_path / "backups"
    staging_dir = backup_root / ".staging" / "ABKP-ABANDONED_12345"
    staging_dir.mkdir(parents=True)
    (staging_dir / "partial.tmp").write_bytes(b"partial content")

    mgr = ArchiveBackupManager(archive_root=synthetic_archive)
    cleaned = mgr.recover_interrupted_backup(target_backup_root=backup_root)

    assert len(cleaned) == 1
    assert not staging_dir.exists()

    # Check backup journal
    journal_file = backup_root / "archive_backup_journal.jsonl"
    assert journal_file.exists()
    entries = [json.loads(line) for line in journal_file.read_text(encoding="utf-8").strip().split("\n")]
    assert any(e["state"] == "STAGING_PURGED" for e in entries)


# ============================================================================
# 6. Authorization Bound to Exact Plan Hash
# ============================================================================

def test_authorization_bound_to_exact_plan_hash(synthetic_plan_and_inventory, tmp_path: Path):
    """Verifies that authorization successfully validates when plan and inventory hashes match."""
    dest_dir = tmp_path / "dest_runtime"
    dest_dir.mkdir()
    ledger_path = tmp_path / "auth_ledger.jsonl"
    ledger = AuthorizationLedger(ledger_path)
    gate = ProductionMigrationAuthorizationGate(ledger)

    now = datetime.now(timezone.utc)
    auth = ProductionMigrationAuthorization(
        approval_id="AUTH-001",
        approval_timestamp=now.isoformat(),
        expiration_timestamp=(now + timedelta(hours=2)).isoformat(),
        one_time_nonce=uuid.uuid4().hex,
        source_root=str(synthetic_plan_and_inventory["src_dir"]),
        destination_root=str(dest_dir),
        inventory_sha256=synthetic_plan_and_inventory["inv_sha"],
        migration_plan_sha256=synthetic_plan_and_inventory["plan_sha"],
        exact_artifact_count=173,
        excluded_active_candidate_path="ASM-001/EVD-3965036b.json",
        destination_volume_identity="VOL-GUID-TEST",
        verified_independent_backup_id="ABKP-SNAP-001",
        operator_role="Lead Security Engineer",
        operator_name="Operator Rangga",
        operator_confirmation=True,
    )

    result = gate.verify_and_consume(
        authorization=auth,
        target_data_dir=dest_dir,
        source_evidence_dir=synthetic_plan_and_inventory["src_dir"],
        inventory_file=synthetic_plan_and_inventory["inv_file"],
        plan_file=synthetic_plan_and_inventory["plan_file"],
        current_volume_id_resolver=lambda p: "VOL-GUID-TEST",
    )

    assert result["status"] == "AUTHORIZATION_VERIFIED_AND_CONSUMED"
    assert ledger.is_consumed(auth.one_time_nonce) is True


# ============================================================================
# 7. Authorization Invalidation After Plan Modification
# ============================================================================

def test_authorization_invalidated_on_plan_modification(synthetic_plan_and_inventory, tmp_path: Path):
    """Modifying even 1 byte in the migration plan fails closed with AuthorizationIntegrityError."""
    dest_dir = tmp_path / "dest_runtime"
    dest_dir.mkdir()
    ledger = AuthorizationLedger(tmp_path / "auth_ledger.jsonl")
    gate = ProductionMigrationAuthorizationGate(ledger)

    now = datetime.now(timezone.utc)
    auth = ProductionMigrationAuthorization(
        approval_id="AUTH-002",
        approval_timestamp=now.isoformat(),
        expiration_timestamp=(now + timedelta(hours=2)).isoformat(),
        one_time_nonce=uuid.uuid4().hex,
        source_root=str(synthetic_plan_and_inventory["src_dir"]),
        destination_root=str(dest_dir),
        inventory_sha256=synthetic_plan_and_inventory["inv_sha"],
        migration_plan_sha256=synthetic_plan_and_inventory["plan_sha"],
        exact_artifact_count=173,
        excluded_active_candidate_path="ASM-001/EVD-3965036b.json",
        destination_volume_identity="VOL-TEST",
        verified_independent_backup_id="ABKP-SNAP-001",
        operator_role="Lead",
        operator_name="Operator",
        operator_confirmation=True,
    )

    # Mutate plan file
    plan_file = synthetic_plan_and_inventory["plan_file"]
    plan_file.write_text(plan_file.read_text(encoding="utf-8") + " ", encoding="utf-8")

    with pytest.raises(AuthorizationIntegrityError) as exc_info:
        gate.verify_and_consume(
            authorization=auth,
            target_data_dir=dest_dir,
            source_evidence_dir=synthetic_plan_and_inventory["src_dir"],
            inventory_file=synthetic_plan_and_inventory["inv_file"],
            plan_file=plan_file,
        )
    assert "Migration plan SHA-256 mismatch" in str(exc_info.value)
    assert ledger.is_consumed(auth.one_time_nonce) is False


# ============================================================================
# 8. Authorization Invalidation After Inventory Modification
# ============================================================================

def test_authorization_invalidated_on_inventory_modification(synthetic_plan_and_inventory, tmp_path: Path):
    """Modifying inventory file fails closed with AuthorizationIntegrityError."""
    dest_dir = tmp_path / "dest_runtime"
    dest_dir.mkdir()
    ledger = AuthorizationLedger(tmp_path / "auth_ledger.jsonl")
    gate = ProductionMigrationAuthorizationGate(ledger)

    now = datetime.now(timezone.utc)
    auth = ProductionMigrationAuthorization(
        approval_id="AUTH-003",
        approval_timestamp=now.isoformat(),
        expiration_timestamp=(now + timedelta(hours=2)).isoformat(),
        one_time_nonce=uuid.uuid4().hex,
        source_root=str(synthetic_plan_and_inventory["src_dir"]),
        destination_root=str(dest_dir),
        inventory_sha256=synthetic_plan_and_inventory["inv_sha"],
        migration_plan_sha256=synthetic_plan_and_inventory["plan_sha"],
        exact_artifact_count=173,
        excluded_active_candidate_path="ASM-001/EVD-3965036b.json",
        destination_volume_identity="VOL-TEST",
        verified_independent_backup_id="ABKP-SNAP-001",
        operator_role="Lead",
        operator_name="Operator",
        operator_confirmation=True,
    )

    # Mutate inventory file
    inv_file = synthetic_plan_and_inventory["inv_file"]
    inv_file.write_text(inv_file.read_text(encoding="utf-8") + " ", encoding="utf-8")

    with pytest.raises(AuthorizationIntegrityError) as exc_info:
        gate.verify_and_consume(
            authorization=auth,
            target_data_dir=dest_dir,
            source_evidence_dir=synthetic_plan_and_inventory["src_dir"],
            inventory_file=inv_file,
            plan_file=synthetic_plan_and_inventory["plan_file"],
        )
    assert "Inventory SHA-256 mismatch" in str(exc_info.value)
    assert ledger.is_consumed(auth.one_time_nonce) is False


# ============================================================================
# 9. Destination Mismatch Rejection
# ============================================================================

def test_authorization_destination_mismatch_rejection(synthetic_plan_and_inventory, tmp_path: Path):
    """Verifies that targeting a destination different from authorization fails closed."""
    dest_dir = tmp_path / "dest_runtime"
    dest_dir.mkdir()
    other_dest = tmp_path / "other_dest"
    other_dest.mkdir()

    ledger = AuthorizationLedger(tmp_path / "auth_ledger.jsonl")
    gate = ProductionMigrationAuthorizationGate(ledger)

    now = datetime.now(timezone.utc)
    auth = ProductionMigrationAuthorization(
        approval_id="AUTH-004",
        approval_timestamp=now.isoformat(),
        expiration_timestamp=(now + timedelta(hours=2)).isoformat(),
        one_time_nonce=uuid.uuid4().hex,
        source_root=str(synthetic_plan_and_inventory["src_dir"]),
        destination_root=str(dest_dir),
        inventory_sha256=synthetic_plan_and_inventory["inv_sha"],
        migration_plan_sha256=synthetic_plan_and_inventory["plan_sha"],
        exact_artifact_count=173,
        excluded_active_candidate_path="ASM-001/EVD-3965036b.json",
        destination_volume_identity="VOL-TEST",
        verified_independent_backup_id="ABKP-SNAP-001",
        operator_role="Lead",
        operator_name="Operator",
        operator_confirmation=True,
    )

    with pytest.raises(AuthorizationDestinationError) as exc_info:
        gate.verify_and_consume(
            authorization=auth,
            target_data_dir=other_dest,
            source_evidence_dir=synthetic_plan_and_inventory["src_dir"],
            inventory_file=synthetic_plan_and_inventory["inv_file"],
            plan_file=synthetic_plan_and_inventory["plan_file"],
        )
    assert "Destination directory mismatch" in str(exc_info.value)


# ============================================================================
# 10. One-Time Authorization Nonce Consumption (Replay Fails Closed)
# ============================================================================

def test_authorization_one_time_nonce_replay_fails(synthetic_plan_and_inventory, tmp_path: Path):
    """Verifies that replay of an already-consumed nonce is immediately rejected."""
    dest_dir = tmp_path / "dest_runtime"
    dest_dir.mkdir()
    ledger = AuthorizationLedger(tmp_path / "auth_ledger.jsonl")
    gate = ProductionMigrationAuthorizationGate(ledger)

    now = datetime.now(timezone.utc)
    auth = ProductionMigrationAuthorization(
        approval_id="AUTH-005",
        approval_timestamp=now.isoformat(),
        expiration_timestamp=(now + timedelta(hours=2)).isoformat(),
        one_time_nonce="NONCE-REPLAY-TEST-123456",
        source_root=str(synthetic_plan_and_inventory["src_dir"]),
        destination_root=str(dest_dir),
        inventory_sha256=synthetic_plan_and_inventory["inv_sha"],
        migration_plan_sha256=synthetic_plan_and_inventory["plan_sha"],
        exact_artifact_count=173,
        excluded_active_candidate_path="ASM-001/EVD-3965036b.json",
        destination_volume_identity="VOL-TEST",
        verified_independent_backup_id="ABKP-SNAP-001",
        operator_role="Lead",
        operator_name="Operator",
        operator_confirmation=True,
    )

    # First attempt: succeeds
    res = gate.verify_and_consume(
        authorization=auth,
        target_data_dir=dest_dir,
        source_evidence_dir=synthetic_plan_and_inventory["src_dir"],
        inventory_file=synthetic_plan_and_inventory["inv_file"],
        plan_file=synthetic_plan_and_inventory["plan_file"],
    )
    assert res["status"] == "AUTHORIZATION_VERIFIED_AND_CONSUMED"

    # Second attempt with same nonce: fails closed
    with pytest.raises(AuthorizationConsumedError) as exc_info:
        gate.verify_and_consume(
            authorization=auth,
            target_data_dir=dest_dir,
            source_evidence_dir=synthetic_plan_and_inventory["src_dir"],
            inventory_file=synthetic_plan_and_inventory["inv_file"],
            plan_file=synthetic_plan_and_inventory["plan_file"],
        )
    assert "already been consumed" in str(exc_info.value)


# ============================================================================
# 11. Active Candidate Exclusion Guard (ASM-001/EVD-3965036b.json)
# ============================================================================

def test_authorization_active_candidate_exclusion_guard(synthetic_plan_and_inventory, tmp_path: Path):
    """Verifies that omitting the active candidate from exclusion raises AuthorizationScopeError."""
    dest_dir = tmp_path / "dest_runtime"
    dest_dir.mkdir()
    ledger = AuthorizationLedger(tmp_path / "auth_ledger.jsonl")
    gate = ProductionMigrationAuthorizationGate(ledger)

    now = datetime.now(timezone.utc)
    # Attempting to authorize with missing/wrong active candidate exclusion
    auth = ProductionMigrationAuthorization(
        approval_id="AUTH-006",
        approval_timestamp=now.isoformat(),
        expiration_timestamp=(now + timedelta(hours=2)).isoformat(),
        one_time_nonce=uuid.uuid4().hex,
        source_root=str(synthetic_plan_and_inventory["src_dir"]),
        destination_root=str(dest_dir),
        inventory_sha256=synthetic_plan_and_inventory["inv_sha"],
        migration_plan_sha256=synthetic_plan_and_inventory["plan_sha"],
        exact_artifact_count=173,
        excluded_active_candidate_path="ASM-999/SOME_OTHER_FILE.json",  # INVALID
        destination_volume_identity="VOL-TEST",
        verified_independent_backup_id="ABKP-SNAP-001",
        operator_role="Lead",
        operator_name="Operator",
        operator_confirmation=True,
    )

    with pytest.raises(AuthorizationScopeError) as exc_info:
        gate.verify_and_consume(
            authorization=auth,
            target_data_dir=dest_dir,
            source_evidence_dir=synthetic_plan_and_inventory["src_dir"],
            inventory_file=synthetic_plan_and_inventory["inv_file"],
            plan_file=synthetic_plan_and_inventory["plan_file"],
        )
    assert "EVD-3965036b.json' must be explicitly excluded" in str(exc_info.value)


# ============================================================================
# 12. Source Retention Invariant (Source Files Unmutated)
# ============================================================================

def test_source_retention_invariant(synthetic_archive, tmp_path: Path):
    """Verifies that backup operations never alter or mutate source archive files."""
    backup_root = tmp_path / "backups"

    # Snapshot source file sizes and SHA-256 before backup
    before_hashes = {}
    for p in synthetic_archive.rglob("*"):
        if p.is_file():
            before_hashes[str(p)] = (p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())

    def mock_distinct_disks(p: Path) -> str:
        res = p.resolve()
        return "0:SRC" if (res == synthetic_archive.resolve() or synthetic_archive.resolve() in res.parents) else "1:TGT"

    mgr = ArchiveBackupManager(archive_root=synthetic_archive, custom_disk_resolver=mock_distinct_disks)
    mgr.create_backup(target_backup_root=backup_root)

    # Verify identical sizes and hashes after backup
    for file_path_str, (orig_size, orig_sha) in before_hashes.items():
        p = Path(file_path_str)
        assert p.exists()
        assert p.stat().st_size == orig_size
        assert hashlib.sha256(p.read_bytes()).hexdigest() == orig_sha


# ============================================================================
# 13. No-Clobber Backup Publication
# ============================================================================

def test_no_clobber_backup_publication(synthetic_archive, tmp_path: Path):
    """Verifies that existing backup directories cannot be overwritten."""
    backup_root = tmp_path / "backups"

    def mock_distinct_disks(p: Path) -> str:
        res = p.resolve()
        return "0:SRC" if (res == synthetic_archive.resolve() or synthetic_archive.resolve() in res.parents) else "1:TGT"

    mgr = ArchiveBackupManager(archive_root=synthetic_archive, custom_disk_resolver=mock_distinct_disks)
    # First backup with explicit gen_id
    mgr.create_backup(target_backup_root=backup_root, generation_id="ABKP-COLLISION-TEST")

    # Second backup with same gen_id must fail
    with pytest.raises(ArchiveBackupCollisionError) as exc_info:
        mgr.create_backup(target_backup_root=backup_root, generation_id="ABKP-COLLISION-TEST")
    assert "already exists" in str(exc_info.value)


# ============================================================================
# 14. Maintenance Lock Enforcement on Backup and Gate Operations
# ============================================================================

def test_maintenance_lock_enforcement_on_engine_with_authorization(synthetic_plan_and_inventory, tmp_path: Path):
    """Verifies that MigrationEngine rejects instantiation without MaintenanceSession or acquired InstanceLock."""
    dest_dir = tmp_path / "dest_runtime"
    dest_dir.mkdir()
    lock_file = dest_dir / "workbench.lock"

    now = datetime.now(timezone.utc)
    auth = ProductionMigrationAuthorization(
        approval_id="AUTH-007",
        approval_timestamp=now.isoformat(),
        expiration_timestamp=(now + timedelta(hours=2)).isoformat(),
        one_time_nonce=uuid.uuid4().hex,
        source_root=str(synthetic_plan_and_inventory["src_dir"]),
        destination_root=str(dest_dir),
        inventory_sha256=synthetic_plan_and_inventory["inv_sha"],
        migration_plan_sha256=synthetic_plan_and_inventory["plan_sha"],
        exact_artifact_count=173,
        excluded_active_candidate_path="ASM-001/EVD-3965036b.json",
        destination_volume_identity="VOL-TEST",
        verified_independent_backup_id="ABKP-SNAP-001",
        operator_role="Lead",
        operator_name="Operator",
        operator_confirmation=True,
    )

    # Calling MigrationEngine without maintenance lock must raise ProcessLockError
    with pytest.raises(ProcessLockError) as exc_info:
        MigrationEngine(
            data_dir=dest_dir,
            authorization=auth,
            inventory_file=synthetic_plan_and_inventory["inv_file"],
            plan_file=synthetic_plan_and_inventory["plan_file"],
            source_evidence_dir=synthetic_plan_and_inventory["src_dir"],
        )
    assert "without exclusive maintenance lock ownership is strictly prohibited" in str(exc_info.value)

    # With acquired InstanceLock, instantiation succeeds
    lock = InstanceLock(lock_file)
    lock.acquire()
    try:
        session = MaintenanceSession(lock)
        engine = MigrationEngine(
            data_dir=dest_dir,
            maintenance_session=session,
            authorization=auth,
            inventory_file=synthetic_plan_and_inventory["inv_file"],
            plan_file=synthetic_plan_and_inventory["plan_file"],
            source_evidence_dir=synthetic_plan_and_inventory["src_dir"],
        )
        assert engine.paths.data_dir == dest_dir
    finally:
        lock.release()
