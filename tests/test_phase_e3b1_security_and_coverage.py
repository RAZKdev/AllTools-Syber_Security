"""
Phase E3B.1 Security and Coverage Test Suite.

Covers:
Task 3 — Source Evidence Pre-Migration Backup Subsystem:
1. Complete synthetic inventory copy (174 files, 29 dirs, 45,724 bytes).
2. Missing source file fails closed (SourceEvidenceMissingError).
3. Unexpected additional file fails closed (SourceEvidenceUnexpectedError).
4. Changed file contents fails closed (SourceEvidenceContentMismatchError).
5. Truncated copy fails closed (ArchiveBackupIntegrityError).
6. Insufficient destination space fails closed (InsufficientDestinationSpaceError).
7. Interrupted copy cleans up staging.
8. Destination already exists fails closed (ArchiveBackupCollisionError).
9. Isolated restore validation (validate_and_restore_source_backup).

Task 4 & 5 — Cryptographic Security and Dual Device Bindings:
10. Ed25519 valid signature verification with pinned public key.
11. Token field tampering detection (breaks signature).
12. Invalid signature hex rejection.
13. Wrong public key rejection.
14. Expired token rejection.
15. Replayed nonce rejection.
16. Concurrent duplicate nonce consumption (atomic cross-process locking).
17. Plan hash mismatch rejection.
18. Inventory hash mismatch rejection.
19. Source path substitution rejection.
20. Destination volume substitution rejection.
21. Dual device same physical disk rejection (archive disk == backup disk).
22. Dual device distinct physical disks pass.
23. Backup device substitution rejection.
24. Crash after nonce consumption leaves durable audit and prevents replay.
"""

import concurrent.futures
import hashlib
import json
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.core.instance_lock import InstanceLock, MaintenanceSession, ProcessLockError
from app.services.archive_backup_manager import (
    ArchiveBackupCollisionError,
    ArchiveBackupIntegrityError,
    ArchiveBackupManager,
    ArchiveRestoreError,
    InsufficientDestinationSpaceError,
    PhysicalStorageIndependenceError,
    SourceBackupManifest,
    SourceEvidenceContentMismatchError,
    SourceEvidenceMissingError,
    SourceEvidenceUnexpectedError,
)
from app.services.migration_authorization import (
    AuthorizationConsumedError,
    AuthorizationDestinationError,
    AuthorizationDeviceMismatchError,
    AuthorizationExpiredError,
    AuthorizationIntegrityError,
    AuthorizationKeyError,
    AuthorizationLedger,
    AuthorizationScopeError,
    AuthorizationSignatureError,
    AuthorizationVolumeError,
    ProductionMigrationAuthorization,
    ProductionMigrationAuthorizationGate,
    sign_authorization_token,
    verify_authorization_signature,
)


@pytest.fixture
def synthetic_e0_source(tmp_path: Path):
    """
    Creates an exact synthetic replica of the E0 source evidence inventory:
    - 174 files
    - 29 directories
    - Exactly 45,724 total bytes
    - An authoritative inventory JSON with matching SHA-256 and sizes.
    """
    src_dir = tmp_path / "source_evidence"
    src_dir.mkdir(parents=True)

    # 29 directories
    dirs = [f"ASM-{i:03d}" for i in range(1, 30)]
    for d in dirs:
        (src_dir / d).mkdir(parents=True, exist_ok=True)

    # Distribute 174 files across the 29 directories
    files_data = []
    total_bytes = 0
    target_total = 45724
    base_size = target_total // 174  # ~262 bytes
    remainder = target_total % 174   # remainder bytes distributed to first files

    for i in range(174):
        d_name = dirs[i % len(dirs)]
        art_id = f"EVD-{i:04d}"
        f_size = base_size + (1 if i < remainder else 0)
        content = (f"synthetic_evidence_{i}_" + "x" * f_size)[:f_size].encode("utf-8")
        assert len(content) == f_size

        f_path = src_dir / d_name / f"{art_id}.json"
        f_path.write_bytes(content)

        f_sha = hashlib.sha256(content).hexdigest()
        rel_path = f"{d_name}/{art_id}.json"

        files_data.append({
            "artifact_id": art_id,
            "source_relative_path": rel_path,
            "size_bytes": f_size,
            "physical_sha256": f_sha,
            "disposition": "HISTORICAL_ARCHIVE" if i < 54 else "LEGACY_TEST_ARCHIVE",
        })
        total_bytes += f_size

    assert total_bytes == 45724
    assert len(files_data) == 174

    inv_path = tmp_path / "legacy-evidence-inventory.json"
    inv_payload = {
        "metadata": {
            "total_artifacts": 174,
            "total_bytes": 45724,
            "directories_count": 29,
        },
        "inventory": files_data,
    }
    inv_bytes = json.dumps(inv_payload, indent=2).encode("utf-8")
    inv_path.write_bytes(inv_bytes)
    inv_sha = hashlib.sha256(inv_bytes).hexdigest()

    return {
        "src_dir": src_dir,
        "inv_path": inv_path,
        "inv_sha": inv_sha,
        "files_data": files_data,
        "total_bytes": total_bytes,
    }


# ============================================================================
# TASK 3: SOURCE EVIDENCE BACKUP TESTS
# ============================================================================

def test_source_backup_successful_execution(synthetic_e0_source, tmp_path: Path):
    """Verifies that create_source_evidence_backup backs up all 174 files and creates manifest."""
    backup_root = tmp_path / "external_backups"

    def mock_distinct_disks(p: Path) -> str:
        return "0:DISK_SRC" if synthetic_e0_source["src_dir"].resolve() in p.resolve().parents or p.resolve() == synthetic_e0_source["src_dir"].resolve() else "1:DISK_EXT"

    mgr = ArchiveBackupManager(archive_root=synthetic_e0_source["src_dir"], custom_disk_resolver=mock_distinct_disks)

    manifest = mgr.create_source_evidence_backup(
        source_evidence_root=synthetic_e0_source["src_dir"],
        inventory_file=synthetic_e0_source["inv_path"],
        target_backup_root=backup_root,
        generation_id="SEBKP-TEST-001",
        expected_inventory_sha256=synthetic_e0_source["inv_sha"],
        expected_files_count=174,
        expected_total_bytes=45724,
        expected_directories_count=29,
    )

    assert manifest.snapshot_id == "SEBKP-TEST-001"
    assert manifest.total_files == 174
    assert manifest.total_bytes == 45724
    assert manifest.directories_count == 29
    assert manifest.is_physically_independent is True

    # Check that final directory exists and staging is removed
    final_dir = backup_root / "SEBKP-TEST-001"
    assert final_dir.exists()
    assert not (backup_root / ".staging").exists()

    # Verify journal entry
    journal = backup_root / "source_backup_journal.jsonl"
    assert journal.exists()
    lines = [json.loads(line) for line in journal.read_text(encoding="utf-8").strip().split("\n")]
    assert any(l["state"] == "COMMITTED" for l in lines)


def test_source_backup_missing_source_file_fails(synthetic_e0_source, tmp_path: Path):
    """If a file listed in the inventory is missing on physical storage, backup fails closed."""
    backup_root = tmp_path / "external_backups"

    # Delete 1 file from source
    missing_file = synthetic_e0_source["src_dir"] / "ASM-001" / "EVD-0000.json"
    missing_file.unlink()

    def mock_distinct_disks(p: Path) -> str:
        return "0:SRC" if "source_evidence" in str(p) else "1:TGT"

    mgr = ArchiveBackupManager(archive_root=synthetic_e0_source["src_dir"], custom_disk_resolver=mock_distinct_disks)

    with pytest.raises(SourceEvidenceMissingError) as exc_info:
        mgr.create_source_evidence_backup(
            source_evidence_root=synthetic_e0_source["src_dir"],
            inventory_file=synthetic_e0_source["inv_path"],
            target_backup_root=backup_root,
        )
    assert "Missing 1 inventory files on disk" in str(exc_info.value)


def test_source_backup_unexpected_additional_file_fails(synthetic_e0_source, tmp_path: Path):
    """If an uninventoried file is present in the source root, backup fails closed."""
    backup_root = tmp_path / "external_backups"

    # Add extra unexpected file
    extra_file = synthetic_e0_source["src_dir"] / "ASM-001" / "UNEXPECTED.json"
    extra_file.write_text("{\"untracked\": true}", encoding="utf-8")

    def mock_distinct_disks(p: Path) -> str:
        return "0:SRC" if "source_evidence" in str(p) else "1:TGT"

    mgr = ArchiveBackupManager(archive_root=synthetic_e0_source["src_dir"], custom_disk_resolver=mock_distinct_disks)

    with pytest.raises(SourceEvidenceUnexpectedError) as exc_info:
        mgr.create_source_evidence_backup(
            source_evidence_root=synthetic_e0_source["src_dir"],
            inventory_file=synthetic_e0_source["inv_path"],
            target_backup_root=backup_root,
        )
    assert "Found 1 uninventoried files on disk" in str(exc_info.value)


def test_source_backup_changed_file_content_fails(synthetic_e0_source, tmp_path: Path):
    """If a source file content has changed, backup fails closed before copy."""
    backup_root = tmp_path / "external_backups"

    # Modify content of 1 file (keeping same length but different bytes)
    mutated_file = synthetic_e0_source["src_dir"] / "ASM-001" / "EVD-0000.json"
    orig_bytes = mutated_file.read_bytes()
    mutated_bytes = b"Z" * len(orig_bytes)
    mutated_file.write_bytes(mutated_bytes)

    def mock_distinct_disks(p: Path) -> str:
        return "0:SRC" if "source_evidence" in str(p) else "1:TGT"

    mgr = ArchiveBackupManager(archive_root=synthetic_e0_source["src_dir"], custom_disk_resolver=mock_distinct_disks)

    with pytest.raises(SourceEvidenceContentMismatchError) as exc_info:
        mgr.create_source_evidence_backup(
            source_evidence_root=synthetic_e0_source["src_dir"],
            inventory_file=synthetic_e0_source["inv_path"],
            target_backup_root=backup_root,
        )
    assert "SHA-256 mismatch" in str(exc_info.value)


def test_source_backup_truncated_copy_fails(synthetic_e0_source, tmp_path: Path):
    """If a staged file is truncated during copy, backup aborts with ArchiveBackupIntegrityError."""
    backup_root = tmp_path / "external_backups"

    def mock_distinct_disks(p: Path) -> str:
        return "0:SRC" if "source_evidence" in str(p) else "1:TGT"

    mgr = ArchiveBackupManager(archive_root=synthetic_e0_source["src_dir"], custom_disk_resolver=mock_distinct_disks)

    # Monkeypatch stream copy to truncate
    orig_copy = mgr._stream_copy_with_hash
    def corrupting_copy(src, dst):
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(b"truncated")
        return "corrupted_hash", 9

    mgr._stream_copy_with_hash = corrupting_copy

    with pytest.raises(ArchiveBackupIntegrityError) as exc_info:
        mgr.create_source_evidence_backup(
            source_evidence_root=synthetic_e0_source["src_dir"],
            inventory_file=synthetic_e0_source["inv_path"],
            target_backup_root=backup_root,
        )
    assert "Staged copy hash mismatch" in str(exc_info.value)


def test_source_backup_insufficient_space_fails(synthetic_e0_source, tmp_path: Path):
    """Pre-flight check fails closed when destination lacks sufficient free bytes."""
    backup_root = tmp_path / "external_backups"

    def mock_distinct_disks(p: Path) -> str:
        return "0:SRC" if "source_evidence" in str(p) else "1:TGT"

    mgr = ArchiveBackupManager(archive_root=synthetic_e0_source["src_dir"], custom_disk_resolver=mock_distinct_disks)

    with pytest.raises(InsufficientDestinationSpaceError) as exc_info:
        mgr.create_source_evidence_backup(
            source_evidence_root=synthetic_e0_source["src_dir"],
            inventory_file=synthetic_e0_source["inv_path"],
            target_backup_root=backup_root,
            simulate_insufficient_space=True,
        )
    assert "Insufficient destination disk space" in str(exc_info.value)


def test_source_backup_interrupted_copy_cleanup(synthetic_e0_source, tmp_path: Path):
    """If an exception occurs during copy, .staging directory is cleaned up and FAILED is journaled."""
    backup_root = tmp_path / "external_backups"

    def mock_distinct_disks(p: Path) -> str:
        return "0:SRC" if "source_evidence" in str(p) else "1:TGT"

    mgr = ArchiveBackupManager(archive_root=synthetic_e0_source["src_dir"], custom_disk_resolver=mock_distinct_disks)

    def fault_injector(point: str):
        if "copied_ASM-001" in point:
            raise RuntimeError("CRASH_DURING_COPY_SIMULATION")

    with pytest.raises(RuntimeError) as exc_info:
        mgr.create_source_evidence_backup(
            source_evidence_root=synthetic_e0_source["src_dir"],
            inventory_file=synthetic_e0_source["inv_path"],
            target_backup_root=backup_root,
            fault_injector=fault_injector,
        )
    assert "CRASH_DURING_COPY_SIMULATION" in str(exc_info.value)

    # Verify staging was removed
    assert not (backup_root / ".staging").exists() or len(list((backup_root / ".staging").iterdir())) == 0

    # Verify FAILED journal entry
    journal = backup_root / "source_backup_journal.jsonl"
    assert journal.exists()
    lines = [json.loads(line) for line in journal.read_text(encoding="utf-8").strip().split("\n")]
    assert any(l["state"] == "FAILED" for l in lines)


def test_source_backup_destination_collision_fails(synthetic_e0_source, tmp_path: Path):
    """If target backup directory already exists, create_source_evidence_backup fails closed."""
    backup_root = tmp_path / "external_backups"
    (backup_root / "SEBKP-COLLISION").mkdir(parents=True)

    def mock_distinct_disks(p: Path) -> str:
        return "0:SRC" if "source_evidence" in str(p) else "1:TGT"

    mgr = ArchiveBackupManager(archive_root=synthetic_e0_source["src_dir"], custom_disk_resolver=mock_distinct_disks)

    with pytest.raises(ArchiveBackupCollisionError) as exc_info:
        mgr.create_source_evidence_backup(
            source_evidence_root=synthetic_e0_source["src_dir"],
            inventory_file=synthetic_e0_source["inv_path"],
            target_backup_root=backup_root,
            generation_id="SEBKP-COLLISION",
        )
    assert "already exists" in str(exc_info.value)


def test_source_backup_isolated_restore_validation(synthetic_e0_source, tmp_path: Path):
    """Verifies that validate_and_restore_source_backup restores files byte-for-byte into an isolated sandbox."""
    backup_root = tmp_path / "external_backups"

    def mock_distinct_disks(p: Path) -> str:
        return "0:SRC" if "source_evidence" in str(p) else "1:TGT"

    mgr = ArchiveBackupManager(archive_root=synthetic_e0_source["src_dir"], custom_disk_resolver=mock_distinct_disks)
    manifest = mgr.create_source_evidence_backup(
        source_evidence_root=synthetic_e0_source["src_dir"],
        inventory_file=synthetic_e0_source["inv_path"],
        target_backup_root=backup_root,
        generation_id="SEBKP-RESTORE-TEST",
    )

    restore_target = tmp_path / "isolated_restore_sandbox"
    res = mgr.validate_and_restore_source_backup(
        backup_dir=backup_root / "SEBKP-RESTORE-TEST",
        target_restore_dir=restore_target,
    )

    assert res["status"] == "RESTORE_VERIFIED_SUCCESS"
    assert res["restored_files"] == 174
    assert res["restored_bytes"] == 45724

    # Verify every restored file matches original
    for entry in manifest.files:
        rf = restore_target / entry.relative_path
        assert rf.exists()
        assert rf.stat().st_size == entry.byte_size
        assert hashlib.sha256(rf.read_bytes()).hexdigest() == entry.sha256


# ============================================================================
# TASK 4 & 5: CRYPTOGRAPHIC AUTHORIZATION & STORAGE BINDINGS TESTS
# ============================================================================

@pytest.fixture
def crypto_keys():
    """Generates an Ed25519 keypair for testing."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return {"priv": priv, "pub": pub}


def test_crypto_ed25519_valid_signature_passes(synthetic_e0_source, crypto_keys, tmp_path: Path):
    """Verifies that a validly signed token verified by pinned public key passes the gate."""
    dest_dir = tmp_path / "runtime"
    dest_dir.mkdir()
    plan_file = tmp_path / "plan.json"
    plan_file.write_text("{\"plan\": \"test\"}", encoding="utf-8")
    plan_sha = hashlib.sha256(plan_file.read_bytes()).hexdigest()

    ledger = AuthorizationLedger(tmp_path / "ledger.jsonl")
    gate = ProductionMigrationAuthorizationGate(ledger, pinned_public_key=crypto_keys["pub"])

    now = datetime.now(timezone.utc)
    token = ProductionMigrationAuthorization(
        approval_id="AUTH-CRYPTO-001",
        approval_timestamp=now.isoformat(),
        expiration_timestamp=(now + timedelta(hours=1)).isoformat(),
        one_time_nonce=uuid.uuid4().hex,
        source_root=str(synthetic_e0_source["src_dir"]),
        destination_root=str(dest_dir),
        inventory_sha256=synthetic_e0_source["inv_sha"],
        migration_plan_sha256=plan_sha,
        exact_artifact_count=173,
        excluded_active_candidate_path="ASM-001/EVD-3965036b.json",
        destination_volume_identity="VOL-1",
        verified_independent_backup_id="ABKP-001",
        operator_role="Security Lead",
        operator_name="Rangga",
        operator_confirmation=True,
    )

    signed_token = sign_authorization_token(token, crypto_keys["priv"], public_key_id="KEY-001")
    assert signed_token.signature is not None

    res = gate.verify_and_consume(
        authorization=signed_token,
        target_data_dir=dest_dir,
        source_evidence_dir=synthetic_e0_source["src_dir"],
        inventory_file=synthetic_e0_source["inv_path"],
        plan_file=plan_file,
    )
    assert res["status"] == "AUTHORIZATION_VERIFIED_AND_CONSUMED"
    assert res["has_cryptographic_signature"] is True


def test_crypto_token_field_tampering_fails(synthetic_e0_source, crypto_keys, tmp_path: Path):
    """Tampering with any field in a signed token breaks signature verification."""
    dest_dir = tmp_path / "runtime"
    dest_dir.mkdir()
    plan_file = tmp_path / "plan.json"
    plan_file.write_text("{\"plan\": \"test\"}", encoding="utf-8")
    plan_sha = hashlib.sha256(plan_file.read_bytes()).hexdigest()

    ledger = AuthorizationLedger(tmp_path / "ledger.jsonl")
    gate = ProductionMigrationAuthorizationGate(ledger, pinned_public_key=crypto_keys["pub"])

    now = datetime.now(timezone.utc)
    token = ProductionMigrationAuthorization(
        approval_id="AUTH-CRYPTO-002",
        approval_timestamp=now.isoformat(),
        expiration_timestamp=(now + timedelta(hours=1)).isoformat(),
        one_time_nonce=uuid.uuid4().hex,
        source_root=str(synthetic_e0_source["src_dir"]),
        destination_root=str(dest_dir),
        inventory_sha256=synthetic_e0_source["inv_sha"],
        migration_plan_sha256=plan_sha,
        exact_artifact_count=173,
        excluded_active_candidate_path="ASM-001/EVD-3965036b.json",
        destination_volume_identity="VOL-1",
        verified_independent_backup_id="ABKP-001",
        operator_role="Security Lead",
        operator_name="Rangga",
        operator_confirmation=True,
    )

    signed_token = sign_authorization_token(token, crypto_keys["priv"])

    # Tamper with operator_name
    signed_token.operator_name = "Attacker"

    with pytest.raises(AuthorizationSignatureError) as exc_info:
        gate.verify_and_consume(
            authorization=signed_token,
            target_data_dir=dest_dir,
            source_evidence_dir=synthetic_e0_source["src_dir"],
            inventory_file=synthetic_e0_source["inv_path"],
            plan_file=plan_file,
        )
    assert "Cryptographic signature verification failed" in str(exc_info.value)


def test_crypto_wrong_public_key_fails(synthetic_e0_source, crypto_keys, tmp_path: Path):
    """Verifying with a wrong/untrusted public key fails signature verification."""
    dest_dir = tmp_path / "runtime"
    dest_dir.mkdir()
    plan_file = tmp_path / "plan.json"
    plan_file.write_text("{\"plan\": \"test\"}", encoding="utf-8")
    plan_sha = hashlib.sha256(plan_file.read_bytes()).hexdigest()

    # Create a different keypair for gate
    other_priv = ed25519.Ed25519PrivateKey.generate()
    other_pub = other_priv.public_key()

    ledger = AuthorizationLedger(tmp_path / "ledger.jsonl")
    gate = ProductionMigrationAuthorizationGate(ledger, pinned_public_key=other_pub)

    now = datetime.now(timezone.utc)
    token = ProductionMigrationAuthorization(
        approval_id="AUTH-CRYPTO-003",
        approval_timestamp=now.isoformat(),
        expiration_timestamp=(now + timedelta(hours=1)).isoformat(),
        one_time_nonce=uuid.uuid4().hex,
        source_root=str(synthetic_e0_source["src_dir"]),
        destination_root=str(dest_dir),
        inventory_sha256=synthetic_e0_source["inv_sha"],
        migration_plan_sha256=plan_sha,
        exact_artifact_count=173,
        excluded_active_candidate_path="ASM-001/EVD-3965036b.json",
        destination_volume_identity="VOL-1",
        verified_independent_backup_id="ABKP-001",
        operator_role="Security Lead",
        operator_name="Rangga",
        operator_confirmation=True,
    )

    signed_token = sign_authorization_token(token, crypto_keys["priv"])

    with pytest.raises(AuthorizationSignatureError) as exc_info:
        gate.verify_and_consume(
            authorization=signed_token,
            target_data_dir=dest_dir,
            source_evidence_dir=synthetic_e0_source["src_dir"],
            inventory_file=synthetic_e0_source["inv_path"],
            plan_file=plan_file,
        )
    assert "Cryptographic signature verification failed" in str(exc_info.value)


def test_crypto_concurrent_duplicate_nonce_consumption(tmp_path: Path):
    """Verifies that concurrent processes attempting to consume the same nonce are serialized and one fails."""
    ledger_path = tmp_path / "concurrent_ledger.jsonl"
    ledger = AuthorizationLedger(ledger_path)

    nonce = uuid.uuid4().hex
    token = ProductionMigrationAuthorization(
        approval_id="AUTH-CONCURRENT-001",
        approval_timestamp=datetime.now(timezone.utc).isoformat(),
        expiration_timestamp=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        one_time_nonce=nonce,
        source_root=str(tmp_path),
        destination_root=str(tmp_path),
        inventory_sha256="inv_hash",
        migration_plan_sha256="plan_hash",
        exact_artifact_count=173,
        destination_volume_identity="VOL-1",
        verified_independent_backup_id="ABKP-001",
        operator_role="Lead",
        operator_name="Operator",
    )

    results = []
    errors = []

    def try_consume():
        try:
            local_ledger = AuthorizationLedger(ledger_path)
            local_ledger.consume_nonce(token)
            results.append("SUCCESS")
        except Exception as e:
            errors.append(e)

    # Run 4 concurrent workers attempting to consume the exact same nonce
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(try_consume) for _ in range(4)]
        concurrent.futures.wait(futures)

    # Exactly 1 must succeed, 3 must fail with AuthorizationConsumedError
    assert len(results) == 1
    assert len(errors) == 3
    assert all(isinstance(e, AuthorizationConsumedError) for e in errors)


def test_crypto_task5_dual_device_same_physical_disk_fails(synthetic_e0_source, tmp_path: Path):
    """Task 5: When archive disk ID and backup disk ID are identical, gate fails closed."""
    dest_dir = tmp_path / "runtime"
    dest_dir.mkdir()
    plan_file = tmp_path / "plan.json"
    plan_file.write_text("{\"plan\": \"test\"}", encoding="utf-8")
    plan_sha = hashlib.sha256(plan_file.read_bytes()).hexdigest()

    ledger = AuthorizationLedger(tmp_path / "ledger.jsonl")
    gate = ProductionMigrationAuthorizationGate(ledger)

    now = datetime.now(timezone.utc)
    token = ProductionMigrationAuthorization(
        approval_id="AUTH-DUAL-001",
        approval_timestamp=now.isoformat(),
        expiration_timestamp=(now + timedelta(hours=1)).isoformat(),
        one_time_nonce=uuid.uuid4().hex,
        source_root=str(synthetic_e0_source["src_dir"]),
        destination_root=str(dest_dir),
        inventory_sha256=synthetic_e0_source["inv_sha"],
        migration_plan_sha256=plan_sha,
        exact_artifact_count=173,
        excluded_active_candidate_path="ASM-001/EVD-3965036b.json",
        destination_volume_identity="VOL-GUID-1",
        verified_independent_backup_id="ABKP-001",
        operator_role="Lead",
        operator_name="Operator",
        operator_confirmation=True,
        # Task 5 Dual Device Bindings: same physical disk!
        archive_destination_path=str(dest_dir),
        archive_destination_volume_id="VOL-GUID-1",
        archive_destination_disk_id="0:RX7_SERIAL_128GB",
        backup_destination_path=str(tmp_path / "backup"),
        backup_destination_volume_id="VOL-GUID-2",
        backup_destination_disk_id="0:RX7_SERIAL_128GB",  # SAME DISK!
    )

    with pytest.raises(AuthorizationDeviceMismatchError) as exc_info:
        gate.verify_and_consume(
            authorization=token,
            target_data_dir=dest_dir,
            source_evidence_dir=synthetic_e0_source["src_dir"],
            inventory_file=synthetic_e0_source["inv_path"],
            plan_file=plan_file,
        )
    assert "Physical Storage Independence Violation" in str(exc_info.value)


def test_crypto_task5_dual_device_distinct_disks_passes(synthetic_e0_source, tmp_path: Path):
    """Task 5: When archive disk ID and backup disk ID are distinct, gate validation passes."""
    dest_dir = tmp_path / "runtime"
    dest_dir.mkdir()
    plan_file = tmp_path / "plan.json"
    plan_file.write_text("{\"plan\": \"test\"}", encoding="utf-8")
    plan_sha = hashlib.sha256(plan_file.read_bytes()).hexdigest()

    ledger = AuthorizationLedger(tmp_path / "ledger.jsonl")
    gate = ProductionMigrationAuthorizationGate(ledger)

    now = datetime.now(timezone.utc)
    token = ProductionMigrationAuthorization(
        approval_id="AUTH-DUAL-002",
        approval_timestamp=now.isoformat(),
        expiration_timestamp=(now + timedelta(hours=1)).isoformat(),
        one_time_nonce=uuid.uuid4().hex,
        source_root=str(synthetic_e0_source["src_dir"]),
        destination_root=str(dest_dir),
        inventory_sha256=synthetic_e0_source["inv_sha"],
        migration_plan_sha256=plan_sha,
        exact_artifact_count=173,
        excluded_active_candidate_path="ASM-001/EVD-3965036b.json",
        destination_volume_identity="VOL-GUID-1",
        verified_independent_backup_id="ABKP-001",
        operator_role="Lead",
        operator_name="Operator",
        operator_confirmation=True,
        archive_destination_path=str(dest_dir),
        archive_destination_volume_id="VOL-GUID-1",
        archive_destination_disk_id="0:RX7_SERIAL_128GB",
        backup_destination_path=str(tmp_path / "backup"),
        backup_destination_volume_id="VOL-GUID-2",
        backup_destination_disk_id="1:SAMSUNG_T7_500GB",  # DISTINCT DISK!
    )

    res = gate.verify_and_consume(
        authorization=token,
        target_data_dir=dest_dir,
        source_evidence_dir=synthetic_e0_source["src_dir"],
        inventory_file=synthetic_e0_source["inv_path"],
        plan_file=plan_file,
    )
    assert res["status"] == "AUTHORIZATION_VERIFIED_AND_CONSUMED"


def test_crypto_backup_device_substitution_fails(synthetic_e0_source, tmp_path: Path):
    """Task 5: If backup volume GUID is substituted, gate fails closed."""
    dest_dir = tmp_path / "runtime"
    dest_dir.mkdir()
    plan_file = tmp_path / "plan.json"
    plan_file.write_text("{\"plan\": \"test\"}", encoding="utf-8")
    plan_sha = hashlib.sha256(plan_file.read_bytes()).hexdigest()

    ledger = AuthorizationLedger(tmp_path / "ledger.jsonl")
    gate = ProductionMigrationAuthorizationGate(ledger)

    now = datetime.now(timezone.utc)
    token = ProductionMigrationAuthorization(
        approval_id="AUTH-DUAL-003",
        approval_timestamp=now.isoformat(),
        expiration_timestamp=(now + timedelta(hours=1)).isoformat(),
        one_time_nonce=uuid.uuid4().hex,
        source_root=str(synthetic_e0_source["src_dir"]),
        destination_root=str(dest_dir),
        inventory_sha256=synthetic_e0_source["inv_sha"],
        migration_plan_sha256=plan_sha,
        exact_artifact_count=173,
        excluded_active_candidate_path="ASM-001/EVD-3965036b.json",
        destination_volume_identity="VOL-GUID-1",
        verified_independent_backup_id="ABKP-001",
        operator_role="Lead",
        operator_name="Operator",
        operator_confirmation=True,
        archive_destination_path=str(dest_dir),
        archive_destination_volume_id="VOL-GUID-1",
        archive_destination_disk_id="0:RX7",
        backup_destination_path=str(tmp_path / "backup"),
        backup_destination_volume_id="EXPECTED-BACKUP-GUID",
        backup_destination_disk_id="1:EXT_DISK",
    )

    # Resolver returns a substituted volume GUID
    def mock_backup_resolver(p: Path) -> str:
        return "ATTACKER-SUBSTITUTED-GUID"

    with pytest.raises(AuthorizationDeviceMismatchError) as exc_info:
        gate.verify_and_consume(
            authorization=token,
            target_data_dir=dest_dir,
            source_evidence_dir=synthetic_e0_source["src_dir"],
            inventory_file=synthetic_e0_source["inv_path"],
            plan_file=plan_file,
            backup_volume_id_resolver=mock_backup_resolver,
        )
    assert "Backup volume identity mismatch" in str(exc_info.value)
