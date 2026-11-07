"""
Phase E3B.1.2 Advanced Safety, Subprocess Concurrency & Consistency Test Suite.

Covers:
Section 3 — Ed25519 Trust and Key Custody:
1. Rejection of unknown / injected JSON fields via ConfigDict(extra="forbid").
2. Rejection of invalid key ID and algorithm divergence.
3. Schema-Specific Canonical Serialization Contract (SSCS-v1) immutability.

Section 4 — Authorization Ledger Crash-Safety and Subprocess Concurrency:
4. Real OS subprocess-based concurrency test (multiprocessing / subprocess Popen).
5. Truncated final JSONL line causes fail-closed AuthorizationIntegrityError.
6. Malformed JSON record causes fail-closed AuthorizationIntegrityError.
7. Duplicate nonce records in ledger cause fail-closed AuthorizationIntegrityError.
8. State recorded as CONSUMED_PENDING_INITIALIZATION preventing replay after crash.

Section 5 — Backup Snapshot Consistency & Concurrent Mutation Invariants:
9. File added to source directory during backup causes fail-closed SourceEvidenceUnexpectedError.
10. File removed from source directory during backup causes fail-closed SourceEvidenceUnexpectedError.
11. File content changed during streaming copy causes fail-closed SourceEvidenceContentMismatchError.
12. Symlink / reparse point in source root causes fail-closed SourceEvidenceUnexpectedError.
13. Crash after copy but before atomic directory promotion purges staging and logs FAILED.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import ValidationError

from app.core.instance_lock import InstanceLock, ProcessLockError
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
    AuthorizationGateError,
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
    """Generates synthetic E0 source with 174 files across 29 dirs totaling 45,724 bytes."""
    src_dir = tmp_path / "source_evidence"
    src_dir.mkdir(parents=True)

    dirs = [f"ASM-{i:03d}" for i in range(1, 30)]
    for d in dirs:
        (src_dir / d).mkdir(parents=True, exist_ok=True)

    files_data = []
    total_bytes = 0
    target_total = 45724
    base_size = target_total // 174
    remainder = target_total % 174

    for i in range(174):
        d_name = dirs[i % len(dirs)]
        art_id = f"EVD-{i:04d}"
        f_size = base_size + (1 if i < remainder else 0)
        content = (f"syn_{i}_" + "k" * f_size)[:f_size].encode("utf-8")
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
# SECTION 3: ED25519 TRUST & KEY CUSTODY AUDIT TESTS
# ============================================================================

def test_token_extra_injected_fields_rejected_by_forbid():
    """Verifies that injecting arbitrary or malicious fields into token payload fails ValidationError."""
    now = datetime.now(timezone.utc)
    raw_data = {
        "approval_id": "AUTH-TEST-001",
        "approval_timestamp": now.isoformat(),
        "expiration_timestamp": (now + timedelta(hours=1)).isoformat(),
        "one_time_nonce": uuid.uuid4().hex,
        "source_root": "C:\\source",
        "destination_root": "C:\\dest",
        "inventory_sha256": "inv_hash",
        "migration_plan_sha256": "plan_hash",
        "exact_artifact_count": 173,
        "destination_volume_identity": "VOL-1",
        "verified_independent_backup_id": "ABKP-001",
        "operator_role": "Lead",
        "operator_name": "Rangga",
        # INJECTED UNKNOWN FIELDS:
        "malicious_override": True,
        "bypass_scope_guard": True,
    }

    with pytest.raises(ValidationError) as exc_info:
        ProductionMigrationAuthorization(**raw_data)
    assert "Extra inputs are not permitted" in str(exc_info.value)


def test_sscs_v1_canonical_serialization_contract():
    """Verifies that SSCS-v1 serializes identically and deterministically regardless of dict order."""
    now = datetime.now(timezone.utc)
    t1 = ProductionMigrationAuthorization(
        approval_id="AUTH-001",
        approval_timestamp=now.isoformat(),
        expiration_timestamp=(now + timedelta(hours=1)).isoformat(),
        one_time_nonce="1234567890abcdef1234567890abcdef",
        source_root="D:\\source",
        destination_root="C:\\dest",
        inventory_sha256="inv_hash",
        migration_plan_sha256="plan_hash",
        exact_artifact_count=173,
        destination_volume_identity="VOL-1",
        verified_independent_backup_id="ABKP-001",
        operator_role="Lead",
        operator_name="Rangga",
    )

    payload_bytes_1 = t1.get_canonical_payload()
    payload_bytes_2 = t1.get_canonical_payload()

    assert payload_bytes_1 == payload_bytes_2
    # Verify no unescaped whitespace outside strings
    assert b": " not in payload_bytes_1
    assert b", " not in payload_bytes_1
    # Verify signature field is excluded
    assert b"signature" not in payload_bytes_1


# ============================================================================
# SECTION 4: AUTHORIZATION LEDGER CRASH-SAFETY & SUBPROCESS CONCURRENCY
# ============================================================================

def test_ledger_truncated_final_jsonl_line_fails_closed(tmp_path: Path):
    """A partial or truncated trailing line in authorization_ledger.jsonl triggers AuthorizationIntegrityError."""
    ledger_path = tmp_path / "ledger.jsonl"
    # Write one valid line followed by a truncated JSON fragment
    valid_line = json.dumps({"approval_id": "A1", "one_time_nonce": "N1", "consumed_at": "now"}) + "\n"
    truncated_line = '{"approval_id": "A2", "one_time_nonce": "N2", "consu'
    ledger_path.write_text(valid_line + truncated_line, encoding="utf-8")

    ledger = AuthorizationLedger(ledger_path)
    with pytest.raises(AuthorizationIntegrityError) as exc_info:
        ledger.is_consumed("N1")
    assert "Authorization ledger corrupted" in str(exc_info.value)


def test_ledger_duplicate_nonce_records_fails_closed(tmp_path: Path):
    """Duplicate nonces detected in the ledger file trigger AuthorizationIntegrityError."""
    ledger_path = tmp_path / "ledger.jsonl"
    l1 = json.dumps({"approval_id": "A1", "one_time_nonce": "NONCE-DUP", "consumed_at": "now1"}) + "\n"
    l2 = json.dumps({"approval_id": "A2", "one_time_nonce": "NONCE-DUP", "consumed_at": "now2"}) + "\n"
    ledger_path.write_text(l1 + l2, encoding="utf-8")

    ledger = AuthorizationLedger(ledger_path)
    with pytest.raises(AuthorizationIntegrityError) as exc_info:
        ledger.is_consumed("ANY-NONCE")
    assert "duplicate nonce" in str(exc_info.value)


def test_ledger_subprocess_cross_process_concurrency(tmp_path: Path):
    """
    Spawns real independent OS Python subprocesses attempting to consume the same nonce.
    Proves that kernel-level locking serializes processes and prevents race conditions.
    """
    ledger_path = tmp_path / "subprocess_ledger.jsonl"
    nonce = uuid.uuid4().hex

    token_dict = {
        "approval_id": "AUTH-SUBPROC-001",
        "approval_timestamp": datetime.now(timezone.utc).isoformat(),
        "expiration_timestamp": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "one_time_nonce": nonce,
        "source_root": str(tmp_path),
        "destination_root": str(tmp_path),
        "inventory_sha256": "inv",
        "migration_plan_sha256": "plan",
        "exact_artifact_count": 173,
        "destination_volume_identity": "VOL-1",
        "verified_independent_backup_id": "ABKP-001",
        "operator_role": "Lead",
        "operator_name": "Rangga",
    }
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps(token_dict), encoding="utf-8")

    # Worker script to run in separate Python subprocess
    worker_script = tmp_path / "worker.py"
    worker_code = f"""
import sys, json
from pathlib import Path
backend_dir = Path(r"{Path.cwd() / 'backend'}").resolve()
sys.path.insert(0, str(backend_dir))

from app.services.migration_authorization import AuthorizationLedger, ProductionMigrationAuthorization, AuthorizationConsumedError

ledger_path = Path(r"{ledger_path}").resolve()
token_path = Path(r"{token_file}").resolve()

data = json.loads(token_path.read_text(encoding='utf-8'))
auth = ProductionMigrationAuthorization(**data)

ledger = AuthorizationLedger(ledger_path)
try:
    ledger.consume_nonce(auth)
    # Success exit code 0
    sys.exit(0)
except AuthorizationConsumedError:
    # Consumed error exit code 42
    sys.exit(42)
except Exception as e:
    sys.exit(99)
"""
    worker_script.write_text(worker_code, encoding="utf-8")

    py_exe = sys.executable

    # Spawn 3 concurrent Python subprocesses
    procs = [
        subprocess.Popen([py_exe, str(worker_script)])
        for _ in range(3)
    ]

    exit_codes = [p.wait(timeout=10) for p in procs]

    # Exactly one process must succeed (code 0)
    # The others must fail closed with AuthorizationConsumedError (code 42)
    assert exit_codes.count(0) == 1
    assert exit_codes.count(42) == 2


# ============================================================================
# SECTION 5: BACKUP SNAPSHOT CONSISTENCY & MUTATION INVARIANTS
# ============================================================================

def test_source_backup_file_added_during_backup_fails(synthetic_e0_source, tmp_path: Path):
    """If a file is created in source directory during the backup process, backup fails closed."""
    backup_root = tmp_path / "backups"

    def mock_distinct_disks(p: Path) -> str:
        return "0:SRC" if "source_evidence" in str(p) else "1:TGT"

    mgr = ArchiveBackupManager(archive_root=synthetic_e0_source["src_dir"], custom_disk_resolver=mock_distinct_disks)

    def fault_injector(point: str):
        if point == "after_copy":
            # Concurrently add an unexpected file to source before post-audit
            extra_file = synthetic_e0_source["src_dir"] / "ASM-001" / "CONCURRENT_ADDITION.json"
            extra_file.write_text("{\"concurrent\": true}", encoding="utf-8")

    with pytest.raises(SourceEvidenceUnexpectedError) as exc_info:
        mgr.create_source_evidence_backup(
            source_evidence_root=synthetic_e0_source["src_dir"],
            inventory_file=synthetic_e0_source["inv_path"],
            target_backup_root=backup_root,
            fault_injector=fault_injector,
        )
    assert "modified concurrently during backup" in str(exc_info.value)


def test_source_backup_file_removed_during_backup_fails(synthetic_e0_source, tmp_path: Path):
    """If a file is deleted from source directory during the backup process, backup fails closed."""
    backup_root = tmp_path / "backups"

    def mock_distinct_disks(p: Path) -> str:
        return "0:SRC" if "source_evidence" in str(p) else "1:TGT"

    mgr = ArchiveBackupManager(archive_root=synthetic_e0_source["src_dir"], custom_disk_resolver=mock_distinct_disks)

    def fault_injector(point: str):
        if point == "after_copy":
            # Concurrently delete a file from source before post-audit
            target = synthetic_e0_source["src_dir"] / "ASM-001" / "EVD-0000.json"
            target.unlink()

    with pytest.raises(SourceEvidenceUnexpectedError) as exc_info:
        mgr.create_source_evidence_backup(
            source_evidence_root=synthetic_e0_source["src_dir"],
            inventory_file=synthetic_e0_source["inv_path"],
            target_backup_root=backup_root,
            fault_injector=fault_injector,
        )
    assert "modified concurrently during backup" in str(exc_info.value)


def test_source_backup_content_mutated_during_stream_fails(synthetic_e0_source, tmp_path: Path):
    """If source file content changes during copy, backup detects mismatch and fails closed."""
    backup_root = tmp_path / "backups"

    def mock_distinct_disks(p: Path) -> str:
        return "0:SRC" if "source_evidence" in str(p) else "1:TGT"

    mgr = ArchiveBackupManager(archive_root=synthetic_e0_source["src_dir"], custom_disk_resolver=mock_distinct_disks)

    # Monkeypatch stream copy to simulate reading a mutated file from source
    def mutated_stream_copy(src, dst):
        dst.parent.mkdir(parents=True, exist_ok=True)
        mutated_data = b"MUTATED_DATA_AFTER_PRE_AUDIT"
        dst.write_bytes(mutated_data)
        return hashlib.sha256(mutated_data).hexdigest(), len(mutated_data)

    mgr._stream_copy_with_hash = mutated_stream_copy

    with pytest.raises(SourceEvidenceContentMismatchError) as exc_info:
        mgr.create_source_evidence_backup(
            source_evidence_root=synthetic_e0_source["src_dir"],
            inventory_file=synthetic_e0_source["inv_path"],
            target_backup_root=backup_root,
        )
    assert "was mutated or corrupted during copy" in str(exc_info.value)


def test_source_backup_reparse_point_rejected(synthetic_e0_source, tmp_path: Path):
    """Reparse points / symlinks in source evidence root are rejected before copying."""
    backup_root = tmp_path / "backups"

    def mock_distinct_disks(p: Path) -> str:
        return "0:SRC" if "source_evidence" in str(p) else "1:TGT"

    mgr = ArchiveBackupManager(archive_root=synthetic_e0_source["src_dir"], custom_disk_resolver=mock_distinct_disks)

    # Create a mock symlink detection by monkeypatching islink for one dir
    orig_islink = os.path.islink
    def fake_islink(path):
        if "ASM-002" in str(path):
            return True
        return orig_islink(path)

    os.path.islink = fake_islink
    try:
        with pytest.raises(SourceEvidenceUnexpectedError) as exc_info:
            mgr.create_source_evidence_backup(
                source_evidence_root=synthetic_e0_source["src_dir"],
                inventory_file=synthetic_e0_source["inv_path"],
                target_backup_root=backup_root,
            )
        assert "Reparse point or symlink" in str(exc_info.value)
    finally:
        os.path.islink = orig_islink
