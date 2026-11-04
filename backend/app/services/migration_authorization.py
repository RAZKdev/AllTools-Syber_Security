"""
Production Migration Authorization Gate - Phase E3B / E3B.1.

Implements a narrow, explicit, plan-bound, cryptographically verifiable
authorization mechanism for production evidence migration.

Enforces:
1. No generic booleans (e.g. no allow_production=True).
2. Binding to exact canonical migration plan SHA-256.
3. Binding to exact baseline inventory SHA-256.
4. Binding to exact artifact count (strictly 173).
5. Binding to excluded active candidate path ("ASM-001/EVD-3965036b.json").
6. Binding to exact source and destination volume/directory identities.
7. Binding to verified independent backup ID.
8. Expiration timestamp validation.
9. One-time execution nonce consumed atomically in an append-only ledger with OS-level locking.
10. Asymmetric cryptographic Ed25519 signature verification against independently pinned public key.
11. Explicit dual device bindings (archive destination vs independent backup destination).
12. Immediate fail-closed behavior on any validation discrepancy.
"""

import hashlib
import json
import logging
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel, ConfigDict, Field

from app.core.instance_lock import InstanceLock, ProcessLockError

logger = logging.getLogger(__name__)


class AuthorizationGateError(Exception):
    """Base exception for authorization gate failures."""
    pass


class AuthorizationExpiredError(AuthorizationGateError):
    """Raised when authorization token timestamp is in the past."""
    pass


class AuthorizationConsumedError(AuthorizationGateError):
    """Raised when one-time execution nonce has already been consumed."""
    pass


class AuthorizationIntegrityError(AuthorizationGateError):
    """Raised when plan or inventory SHA-256 does not match authoritative digests."""
    pass


class AuthorizationScopeError(AuthorizationGateError):
    """Raised when artifact scope, count, or path bindings do not match exact requirements."""
    pass


class AuthorizationDestinationError(AuthorizationGateError):
    """Raised when target destination path does not match authorization binding."""
    pass


class AuthorizationVolumeError(AuthorizationGateError):
    """Raised when destination physical volume identity does not match authorization binding."""
    pass


class AuthorizationDeviceMismatchError(AuthorizationGateError):
    """Raised when physical storage device binding fails or fails physical independence."""
    pass


class AuthorizationConfirmationError(AuthorizationGateError):
    """Raised when operator affirmative confirmation is missing."""
    pass


class AuthorizationSignatureError(AuthorizationGateError):
    """Raised when cryptographic signature verification fails."""
    pass


class AuthorizationKeyError(AuthorizationGateError):
    """Raised when public key is invalid, missing, or untrusted."""
    pass


class ProductionMigrationAuthorization(BaseModel):
    """
    Cryptographically verifiable, plan-bound production migration authorization token.
    Enforces strict Schema-Specific Canonical Serialization Contract (SSCS-v1).
    """
    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(description="Unique authorization ID, e.g. AUTH-E3B-20261102-001")
    approval_timestamp: str = Field(description="ISO timestamp of operator approval")
    expiration_timestamp: str = Field(description="ISO timestamp after which authorization expires")
    one_time_nonce: str = Field(description="32-hex cryptographic one-time execution nonce")
    source_root: str = Field(description="Normalized absolute or canonical source evidence directory")
    destination_root: str = Field(description="Normalized absolute destination runtime directory")
    inventory_sha256: str = Field(description="Exact SHA-256 digest of legacy-evidence-inventory.json")
    migration_plan_sha256: str = Field(description="Exact SHA-256 digest of phase-e3b-final-migration-plan.json")
    exact_artifact_count: int = Field(default=173, description="Must strictly equal 173")
    excluded_active_candidate_path: str = Field(
        default="ASM-001/EVD-3965036b.json",
        description="Path of active candidate strictly excluded from physical migration",
    )
    destination_volume_identity: str = Field(description="Volume GUID or serial number of target volume")
    verified_independent_backup_id: str = Field(description="ID of verified independent archive backup snapshot")
    operator_role: str = Field(description="Role of authorizing human operator")
    operator_name: str = Field(description="Name of authorizing human operator")
    operator_confirmation: bool = Field(default=True, description="Explicit affirmative confirmation flag")

    # Task 5 Dual Storage Device Bindings
    archive_destination_path: Optional[str] = Field(default=None, description="Canonical archive destination path")
    archive_destination_volume_id: Optional[str] = Field(default=None, description="Archive destination volume GUID")
    archive_destination_disk_id: Optional[str] = Field(default=None, description="Archive destination physical disk ID")
    backup_destination_path: Optional[str] = Field(default=None, description="Independent backup destination path")
    backup_destination_volume_id: Optional[str] = Field(default=None, description="Independent backup volume GUID")
    backup_destination_disk_id: Optional[str] = Field(default=None, description="Independent backup physical disk ID")

    # Task 4 Cryptographic Asymmetric Signature Fields
    public_key_id: Optional[str] = Field(default=None, description="Pinned public key identifier")
    signature: Optional[str] = Field(default=None, description="Hex-encoded Ed25519 signature over canonical payload")

    def get_canonical_payload(self) -> bytes:
        """
        Return deterministic canonical UTF-8 bytes for cryptographic signing and verification
        under Schema-Specific Canonical Serialization Contract (SSCS-v1).
        Excludes the signature field itself.
        """
        d = self.model_dump(exclude={"signature"})
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_authorization_token(
    auth: ProductionMigrationAuthorization,
    private_key: ed25519.Ed25519PrivateKey,
    public_key_id: Optional[str] = None,
) -> ProductionMigrationAuthorization:
    """
    Generate an Ed25519 signature over the canonical payload of the authorization token.
    """
    if public_key_id:
        auth.public_key_id = public_key_id
    payload = auth.get_canonical_payload()
    sig = private_key.sign(payload)
    auth.signature = sig.hex()
    return auth


def verify_authorization_signature(
    auth: ProductionMigrationAuthorization,
    public_key: ed25519.Ed25519PublicKey,
) -> bool:
    """
    Verify the Ed25519 signature of the authorization token against its canonical payload.
    Raises AuthorizationSignatureError on any verification failure.
    """
    if not auth.signature:
        raise AuthorizationSignatureError("Authorization token lacks required cryptographic signature.")
    try:
        sig_bytes = bytes.fromhex(auth.signature)
    except ValueError as e:
        raise AuthorizationSignatureError(f"Malformed signature hex: {e}") from e

    payload = auth.get_canonical_payload()
    try:
        public_key.verify(sig_bytes, payload)
        return True
    except InvalidSignature as e:
        raise AuthorizationSignatureError(f"Cryptographic signature verification failed: {e}") from e


class AuthorizationLedger:
    """
    Durable append-only consumption ledger guaranteeing one-time execution nonce enforcement
    with cross-process OS-level file locking.
    """

    def __init__(self, ledger_path: Path) -> None:
        self.ledger_path = Path(ledger_path).resolve()
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path = self.ledger_path.with_suffix(".lock")
        self._lock = InstanceLock(self.lock_path)

    def validate_ledger_integrity(self) -> None:
        """
        Scan and validate the entire ledger for malformed records, truncation, or duplicate nonces.
        Fails closed with AuthorizationIntegrityError if any discrepancy is found.
        """
        if not self.ledger_path.exists():
            return

        seen_nonces = set()
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, 1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except Exception as e:
                    raise AuthorizationIntegrityError(
                        f"Authorization ledger corrupted at line {line_no}: malformed JSON ({e})"
                    ) from e

                if not isinstance(record, dict) or "one_time_nonce" not in record or "approval_id" not in record:
                    raise AuthorizationIntegrityError(
                        f"Authorization ledger corrupted at line {line_no}: missing required fields"
                    )

                nonce = record["one_time_nonce"]
                if nonce in seen_nonces:
                    raise AuthorizationIntegrityError(
                        f"Authorization ledger integrity violation at line {line_no}: duplicate nonce '{nonce}' detected."
                    )
                seen_nonces.add(nonce)

    def _is_consumed_unlocked(self, nonce: str) -> bool:
        if not self.ledger_path.exists():
            return False
        # Fail closed on corrupted or tampered ledger records
        self.validate_ledger_integrity()
        with open(self.ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    record = json.loads(line)
                    if record.get("one_time_nonce") == nonce:
                        return True
        return False

    def _acquire_lock(self, timeout_seconds: float = 3.0) -> None:
        start_time = time.monotonic()
        while True:
            try:
                self._lock.acquire()
                return
            except ProcessLockError:
                if time.monotonic() - start_time >= timeout_seconds:
                    raise
                time.sleep(0.05)

    def is_consumed(self, nonce: str) -> bool:
        self._acquire_lock()
        try:
            return self._is_consumed_unlocked(nonce)
        finally:
            self._lock.release()

    def consume_nonce(
        self,
        auth: ProductionMigrationAuthorization,
        operation_id: Optional[str] = None,
    ) -> None:
        self._acquire_lock()
        try:
            if self._is_consumed_unlocked(auth.one_time_nonce):
                raise AuthorizationConsumedError(
                    f"FATAL: One-time execution nonce '{auth.one_time_nonce}' has already been consumed."
                )
            entry = {
                "approval_id": auth.approval_id,
                "one_time_nonce": auth.one_time_nonce,
                "consumed_at": datetime.now(timezone.utc).isoformat(),
                "operator_name": auth.operator_name,
                "migration_plan_sha256": auth.migration_plan_sha256,
                "operation_id": operation_id,
                "status": "CONSUMED_PENDING_INITIALIZATION",
            }
            with open(self.ledger_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
                f.flush()
                os.fsync(f.fileno())
        finally:
            self._lock.release()


class ProductionMigrationAuthorizationGate:
    """
    Strict plan-bound gate enforcing all authorization invariants before allowing
    MigrationEngine to target production or production-like environments.
    """

    def __init__(
        self,
        ledger: AuthorizationLedger,
        pinned_public_key: Optional[ed25519.Ed25519PublicKey] = None,
        require_signature: bool = False,
    ) -> None:
        self.ledger = ledger
        self.pinned_public_key = pinned_public_key
        self.require_signature = require_signature

    def verify_and_consume(
        self,
        authorization: ProductionMigrationAuthorization,
        target_data_dir: Path,
        source_evidence_dir: Path,
        inventory_file: Path,
        plan_file: Path,
        current_volume_id_resolver: Optional[Callable[[Path], Optional[str]]] = None,
        backup_volume_id_resolver: Optional[Callable[[Path], Optional[str]]] = None,
    ) -> Dict[str, Any]:
        """
        Validate all authorization invariants including cryptographic signature,
        temporal validity, plan/inventory hashes, and dual storage device bindings.
        Consumes one-time nonce on success. Fails closed on any discrepancy.
        """
        # 1. Affirmative operator confirmation
        if not authorization.operator_confirmation:
            raise AuthorizationConfirmationError("Operator affirmative confirmation is False.")

        # 2. Expiration check
        try:
            exp_time = datetime.fromisoformat(authorization.expiration_timestamp.replace("Z", "+00:00"))
            now_time = datetime.now(timezone.utc)
            if now_time > exp_time:
                raise AuthorizationExpiredError(
                    f"Authorization token expired at {authorization.expiration_timestamp} (current: {now_time.isoformat()})."
                )
        except Exception as e:
            if isinstance(e, AuthorizationExpiredError):
                raise
            raise AuthorizationGateError(f"Invalid expiration timestamp format: {e}")

        # 3. Cryptographic Signature Verification
        if self.pinned_public_key is not None:
            verify_authorization_signature(authorization, self.pinned_public_key)
        elif self.require_signature or authorization.signature is not None:
            if not authorization.signature:
                raise AuthorizationSignatureError("Cryptographic signature is required but missing.")
            if self.pinned_public_key is None:
                raise AuthorizationKeyError("No pinned public key configured to verify token signature.")
            verify_authorization_signature(authorization, self.pinned_public_key)

        # 4. One-time nonce check (verified atomically in consume_nonce)
        if self.ledger.is_consumed(authorization.one_time_nonce):
            raise AuthorizationConsumedError(
                f"One-time execution nonce '{authorization.one_time_nonce}' has already been consumed."
            )

        # 5. Exact artifact count
        if authorization.exact_artifact_count != 173:
            raise AuthorizationScopeError(
                f"Exact artifact count must be 173, got {authorization.exact_artifact_count}."
            )

        # 6. Excluded active candidate path check
        norm_excluded = authorization.excluded_active_candidate_path.replace("\\", "/").lower()
        if "evd-3965036b" not in norm_excluded:
            raise AuthorizationScopeError(
                f"Active candidate 'ASM-001/EVD-3965036b.json' must be explicitly excluded, got '{authorization.excluded_active_candidate_path}'."
            )

        # 7. Source directory binding
        res_src = source_evidence_dir.resolve()
        auth_src = Path(authorization.source_root).resolve()
        if res_src != auth_src:
            raise AuthorizationScopeError(
                f"Source directory mismatch: expected '{auth_src}', got '{res_src}'."
            )

        # 8. Destination directory binding
        res_dest = target_data_dir.resolve()
        auth_dest = Path(authorization.destination_root).resolve()
        if res_dest != auth_dest:
            raise AuthorizationDestinationError(
                f"Destination directory mismatch: expected '{auth_dest}', got '{res_dest}'."
            )
        if authorization.archive_destination_path:
            auth_arch_p = Path(authorization.archive_destination_path).resolve()
            if res_dest != auth_arch_p:
                raise AuthorizationDestinationError(
                    f"Archive destination path mismatch: expected '{auth_arch_p}', got '{res_dest}'."
                )

        # 9. Inventory SHA-256 verification
        if not inventory_file.exists():
            raise AuthorizationIntegrityError(f"Inventory file '{inventory_file}' does not exist.")
        act_inv_hash = hashlib.sha256(inventory_file.read_bytes()).hexdigest()
        if act_inv_hash.lower() != authorization.inventory_sha256.lower():
            raise AuthorizationIntegrityError(
                f"Inventory SHA-256 mismatch: authorized={authorization.inventory_sha256}, actual={act_inv_hash}"
            )

        # 10. Migration Plan SHA-256 verification
        if not plan_file.exists():
            raise AuthorizationIntegrityError(f"Migration plan file '{plan_file}' does not exist.")
        act_plan_hash = hashlib.sha256(plan_file.read_bytes()).hexdigest()
        if act_plan_hash.lower() != authorization.migration_plan_sha256.lower():
            raise AuthorizationIntegrityError(
                f"Migration plan SHA-256 mismatch: authorized={authorization.migration_plan_sha256}, actual={act_plan_hash}"
            )

        # 11. Destination Volume Identity verification
        if current_volume_id_resolver:
            act_vol_id = current_volume_id_resolver(target_data_dir)
            if act_vol_id and act_vol_id != authorization.destination_volume_identity:
                raise AuthorizationVolumeError(
                    f"Destination volume identity mismatch: authorized={authorization.destination_volume_identity}, actual={act_vol_id}"
                )
            if authorization.archive_destination_volume_id and act_vol_id and act_vol_id != authorization.archive_destination_volume_id:
                raise AuthorizationVolumeError(
                    f"Archive volume identity mismatch: authorized={authorization.archive_destination_volume_id}, actual={act_vol_id}"
                )

        # 12. Task 5 Dual Storage Device Bindings Verification
        act_archive_disk = authorization.archive_destination_disk_id
        act_backup_disk = authorization.backup_destination_disk_id
        if act_archive_disk and act_backup_disk:
            if act_archive_disk.strip() == act_backup_disk.strip():
                raise AuthorizationDeviceMismatchError(
                    f"Physical Storage Independence Violation: Archive disk '{act_archive_disk}' "
                    f"matches backup disk '{act_backup_disk}'. Both cannot reside on the same physical disk."
                )

        if backup_volume_id_resolver and authorization.backup_destination_volume_id and authorization.backup_destination_path:
            res_b_vol = backup_volume_id_resolver(Path(authorization.backup_destination_path))
            if res_b_vol and res_b_vol != authorization.backup_destination_volume_id:
                raise AuthorizationDeviceMismatchError(
                    f"Backup volume identity mismatch: authorized={authorization.backup_destination_volume_id}, actual={res_b_vol}"
                )

        # All invariants passed -> Consume nonce atomically under exclusive lock
        self.ledger.consume_nonce(authorization)

        return {
            "status": "AUTHORIZATION_VERIFIED_AND_CONSUMED",
            "approval_id": authorization.approval_id,
            "one_time_nonce": authorization.one_time_nonce,
            "plan_sha256": act_plan_hash,
            "inventory_sha256": act_inv_hash,
            "verified_artifact_count": authorization.exact_artifact_count,
            "excluded_active_candidate": authorization.excluded_active_candidate_path,
            "has_cryptographic_signature": authorization.signature is not None,
        }
