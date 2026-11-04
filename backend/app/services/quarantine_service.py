import hashlib
import json
import logging
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.core.storage_paths import StoragePaths, get_storage_paths
from app.core.write_fence import WriteFence, global_write_fence
from app.repositories.interfaces import IEvidenceRepository, IQuarantineRepository
from app.repositories.sqlite_quarantine_repository import SqliteQuarantineRepository
from app.schemas.evidence import Evidence, EvidenceCreate, EvidenceType
from app.schemas.quarantine import QuarantineItem, QuarantineReason

logger = logging.getLogger(__name__)


class QuarantineError(Exception):
    """Base exception for quarantine operations."""
    pass


class QuarantineService:
    """
    Quarantine service implementing immutable ledger recording, secondary
    tamper-evident JSONL manifest with hash chaining, and secure isolation (ADR-02).
    """

    MANIFEST_FILENAME = "quarantine_manifest.jsonl"

    def __init__(
        self,
        paths: Optional[StoragePaths] = None,
        quarantine_repo: Optional[IQuarantineRepository] = None,
        write_fence: Optional[WriteFence] = None,
    ) -> None:
        self.paths = paths or get_storage_paths()
        self.quarantine_repo = quarantine_repo or SqliteQuarantineRepository(db_path=self.paths.database_file)
        self.write_fence = write_fence or global_write_fence
        self.quarantine_dir = self.paths.quarantine_dir
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_file = self.quarantine_dir / self.MANIFEST_FILENAME

    def _append_to_manifest(self, item: QuarantineItem) -> None:
        """Append an immutable audit entry to the secondary JSONL manifest."""
        entry = {
            "seq": item.seq,
            "eventId": item.eventId,
            "quarantineId": item.quarantineId,
            "originalPath": item.originalPath,
            "quarantinePath": item.quarantinePath,
            "sha256": item.sha256,
            "byteSize": item.byteSize,
            "reason": item.reason.value if hasattr(item.reason, "value") else str(item.reason),
            "details": item.details,
            "prevEntryHash": item.prevEntryHash,
            "entryHash": item.entryHash,
            "quarantinedAt": item.quarantinedAt.isoformat(),
            "recoveredAt": item.recoveredAt.isoformat() if item.recoveredAt else None,
            "recoveryTargetId": item.recoveryTargetId,
        }
        with open(self.manifest_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def quarantine_file(
        self,
        source_path: Path,
        reason: QuarantineReason,
        details: Optional[str] = None,
    ) -> QuarantineItem:
        """
        Isolate an invalid, corrupted, or unverified artifact to the quarantine directory.
        Records entry in the SQLite ledger and appends to the chained JSONL manifest.
        Guarantees single coordinated write fence lease, rollback on failure, and durable state.
        """
        with self.write_fence.acquire_write():
            if not source_path.exists() or not source_path.is_file():
                raise QuarantineError(f"Target file for quarantine does not exist: {source_path}")

            event_id = f"QEV-{uuid.uuid4().hex[:8]}"
            quarantine_id = f"QAR-{uuid.uuid4().hex[:8]}"

            # Read file bytes to calculate checksum and size
            file_bytes = source_path.read_bytes()
            sha256_digest = hashlib.sha256(file_bytes).hexdigest()
            byte_size = len(file_bytes)

            # Move to quarantine directory with unique filename
            dest_filename = f"{quarantine_id}_{sha256_digest[:8]}.quarantine"
            dest_path = self.quarantine_dir / dest_filename

            try:
                shutil.move(str(source_path), str(dest_path))
            except Exception as e:
                raise QuarantineError(f"Failed to move file to quarantine location: {e}") from e

            orig_path_str = str(source_path).replace("\\", "/")
            quar_path_str = str(dest_path).replace("\\", "/")

            reason_str = reason.value if hasattr(reason, "value") else str(reason)

            try:
                # Record in SQLite ledger with atomic hash-chaining
                item = self.quarantine_repo.record_quarantine_item(
                    event_id=event_id,
                    quarantine_id=quarantine_id,
                    original_path=orig_path_str,
                    quarantine_path=quar_path_str,
                    sha256=sha256_digest,
                    byte_size=byte_size,
                    reason=reason_str,
                    details=details,
                )
            except Exception as e:
                # Rollback file move if database insert fails
                try:
                    if dest_path.exists() and not source_path.exists():
                        shutil.move(str(dest_path), str(source_path))
                except Exception:
                    pass
                raise QuarantineError(f"Quarantine ledger recording failed: {e}") from e

            try:
                # Append to secondary JSONL manifest
                self._append_to_manifest(item)
            except Exception as e:
                logger.error("Failed to append to quarantine manifest: %s", e)
                raise QuarantineError(f"Quarantine manifest update failed: {e}") from e

            logger.warning(
                "Quarantined artifact %s -> %s (Reason: %s, Item: %s)",
                source_path, dest_path, reason_str, quarantine_id
            )
            return item

    def verify_quarantine_integrity(self) -> Tuple[bool, List[str]]:
        """
        Comprehensive cryptographic integrity verification:
        1. Validates SQLite ledger continuous sequence and hash chaining.
        2. Validates secondary JSONL manifest lines, hashes, and consistency with SQLite.
        3. Validates physical presence and checksums of quarantined artifacts.
        """
        errors: List[str] = []

        # 1. Verify SQLite ledger
        db_ok, db_errors = self.quarantine_repo.verify_ledger_integrity()
        if not db_ok:
            errors.extend([f"Database ledger error: {e}" for e in db_errors])

        db_items = self.quarantine_repo.list_quarantine_items()
        db_by_seq = {item.seq: item for item in db_items}

        # 2. Verify Manifest JSONL
        if not self.manifest_file.exists() and len(db_items) > 0:
            errors.append("Manifest file 'quarantine_manifest.jsonl' is missing while database ledger has records.")
        elif self.manifest_file.exists():
            manifest_lines = self.manifest_file.read_text(encoding="utf-8").strip().splitlines()
            if len(manifest_lines) != len(db_items):
                errors.append(
                    f"Manifest entry count mismatch: {len(manifest_lines)} lines vs {len(db_items)} database records."
                )

            for line_no, line in enumerate(manifest_lines, 1):
                try:
                    data = json.loads(line)
                    seq = data.get("seq")
                    if seq not in db_by_seq:
                        errors.append(f"Manifest line {line_no} references unknown seq {seq}")
                        continue

                    db_item = db_by_seq[seq]
                    if data.get("entryHash") != db_item.entryHash:
                        errors.append(
                            f"Manifest line {line_no} (seq {seq}) entryHash mismatch: manifest={data.get('entryHash')} vs db={db_item.entryHash}"
                        )
                    if data.get("prevEntryHash") != db_item.prevEntryHash:
                        errors.append(
                            f"Manifest line {line_no} (seq {seq}) prevEntryHash mismatch."
                        )
                except Exception as e:
                    errors.append(f"Manifest line {line_no} JSON parse error: {e}")

        # 3. Verify Physical Files
        for item in db_items:
            q_file = Path(item.quarantinePath)
            if not q_file.exists():
                errors.append(f"Quarantined artifact missing on disk: {item.quarantinePath}")
                continue
            actual_sha = hashlib.sha256(q_file.read_bytes()).hexdigest()
            if actual_sha != item.sha256:
                errors.append(
                    f"Quarantined artifact checksum mismatch for {item.quarantineId}: recorded {item.sha256}, actual {actual_sha}"
                )

        return (len(errors) == 0, errors)

    def inspect_quarantine(self, quarantine_id: str) -> Optional[QuarantineItem]:
        """Inspect quarantined artifact metadata without execution or HTTP exposure."""
        return self.quarantine_repo.get_quarantine_item(quarantine_id)

    def list_quarantined_items(self) -> List[QuarantineItem]:
        """List all quarantined entries in the ledger."""
        return self.quarantine_repo.list_quarantine_items()

    def recover_item(
        self,
        quarantine_id: str,
        target_assessment_id: str,
        evidence_repo: IEvidenceRepository,
        evidence_type: EvidenceType = EvidenceType.JSON_RESULT,
        notes: Optional[str] = None,
    ) -> Evidence:
        """
        Recover an artifact from quarantine into an active assessment after operator verification.
        Requires explicit operator destination and target assessment ID.
        Coordinated through WriteFence with transactional rollback on failure.
        """
        with self.write_fence.acquire_write():
            item = self.quarantine_repo.get_quarantine_item(quarantine_id)
            if not item:
                raise QuarantineError(f"Quarantine item '{quarantine_id}' not found.")

            q_path = Path(item.quarantinePath)
            if not q_path.exists():
                raise QuarantineError(f"Quarantine file missing at {item.quarantinePath}")

            # Destination inside evidence directory for target assessment
            dest_dir = self.paths.evidence_dir / target_assessment_id
            dest_dir.mkdir(parents=True, exist_ok=True)
            new_ev_id = f"EVD-{uuid.uuid4().hex[:8]}"
            dest_file = dest_dir / f"{new_ev_id}.json"

            # Verify checksum before recovery
            bytes_data = q_path.read_bytes()
            actual_sha = hashlib.sha256(bytes_data).hexdigest()
            if actual_sha != item.sha256:
                raise QuarantineError("Quarantine file checksum mismatch: cannot recover corrupted file.")

            # Move recovered file
            try:
                shutil.move(str(q_path), str(dest_file))
            except Exception as e:
                raise QuarantineError(f"Failed to move quarantine file to evidence destination: {e}") from e

            rel_path = str(dest_file.relative_to(self.paths.data_dir)).replace("\\", "/")

            try:
                # Record in evidence repository
                ev_create = EvidenceCreate(
                    id=new_ev_id,
                    assessmentId=target_assessment_id,
                    type=evidence_type,
                    source=f"recovered_from_quarantine:{quarantine_id}",
                    artifactPath=rel_path,
                    capturedAt=datetime.now(timezone.utc),
                    sha256=actual_sha,
                    notes=notes or f"Recovered from quarantine item {quarantine_id} (original: {item.originalPath})",
                    syncStatus="COMMITTED",
                )
                evidence = evidence_repo.create_evidence(ev_create, sync_status="COMMITTED")

                # Mark recovered in quarantine ledger
                self.quarantine_repo.mark_recovered(quarantine_id, target_assessment_id)
                item.recoveredAt = datetime.now(timezone.utc)
                item.recoveryTargetId = target_assessment_id

                # Rewrite manifest to update recovered status
                self._rewrite_manifest_after_recovery(quarantine_id, target_assessment_id, item.recoveredAt)
            except Exception as e:
                # Rollback file move if database or evidence write fails
                try:
                    if dest_file.exists() and not q_path.exists():
                        shutil.move(str(dest_file), str(q_path))
                except Exception:
                    pass
                raise QuarantineError(f"Quarantine recovery database operation failed: {e}") from e

            logger.info(
                "Recovered quarantine item %s into assessment %s as %s",
                quarantine_id, target_assessment_id, new_ev_id
            )
            return evidence

    def _rewrite_manifest_after_recovery(
        self, quarantine_id: str, target_id: str, recovered_at: datetime
    ) -> None:
        """Update recovered metadata in the secondary JSONL manifest."""
        if not self.manifest_file.exists():
            return
        lines = self.manifest_file.read_text(encoding="utf-8").strip().splitlines()
        updated_lines = []
        for line in lines:
            data = json.loads(line)
            if data.get("quarantineId") == quarantine_id:
                data["recoveredAt"] = recovered_at.isoformat()
                data["recoveryTargetId"] = target_id
            updated_lines.append(json.dumps(data, sort_keys=True))

        temp_manifest = self.quarantine_dir / f".manifest_{uuid.uuid4().hex[:6]}.tmp"
        temp_manifest.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")
        os.replace(temp_manifest, self.manifest_file)

    def reconcile_quarantine_storage(self) -> int:
        """
        Reconcile quarantine ledger, manifest, and storage after abnormal interruption:
        1. Ensures all ledger entries in SQLite are present in quarantine_manifest.jsonl.
        2. Detects unrecorded .quarantine files on disk and adopts them with audit trails.
        """
        with self.write_fence.acquire_write():
            reconciled_count = 0
            db_items = self.quarantine_repo.list_quarantine_items()

            # Check manifest sync
            manifest_seqs = set()
            if self.manifest_file.exists():
                for line in self.manifest_file.read_text(encoding="utf-8").strip().splitlines():
                    try:
                        d = json.loads(line)
                        manifest_seqs.add(d.get("seq"))
                    except Exception:
                        pass

            for item in db_items:
                if item.seq not in manifest_seqs:
                    self._append_to_manifest(item)
                    reconciled_count += 1
                    logger.info("Restored missing manifest entry for quarantine seq %d (%s)", item.seq, item.quarantineId)

            # Check unrecorded disk files
            recorded_paths = {str(Path(item.quarantinePath).resolve()) for item in db_items}
            for q_file in self.quarantine_dir.glob("*.quarantine"):
                if str(q_file.resolve()) not in recorded_paths:
                    file_bytes = q_file.read_bytes()
                    sha = hashlib.sha256(file_bytes).hexdigest()
                    size = len(file_bytes)
                    ev_id = f"QEV-RECOV-{uuid.uuid4().hex[:6]}"
                    qar_id = f"QAR-RECOV-{uuid.uuid4().hex[:6]}"
                    reason_val = QuarantineReason.ORPHAN_NO_ASSESSMENT.value
                    item = self.quarantine_repo.record_quarantine_item(
                        event_id=ev_id,
                        quarantine_id=qar_id,
                        original_path=str(q_file).replace("\\", "/"),
                        quarantine_path=str(q_file).replace("\\", "/"),
                        sha256=sha,
                        byte_size=size,
                        reason=reason_val,
                        details="Orphaned unrecorded quarantine artifact discovered and adopted during storage reconciliation",
                    )
                    self._append_to_manifest(item)
                    reconciled_count += 1
                    logger.warning("Adopted unrecorded quarantine artifact into ledger: %s as %s", q_file.name, qar_id)

            return reconciled_count
