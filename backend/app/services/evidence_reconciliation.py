import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from app.core.storage_paths import StoragePaths, get_storage_paths
from app.core.write_fence import WriteFence, global_write_fence
from app.repositories.interfaces import IEvidenceRepository
from app.repositories.sqlite_evidence_repository import SqliteEvidenceRepository
from app.schemas.quarantine import QuarantineReason
from app.services.quarantine_service import QuarantineService

logger = logging.getLogger(__name__)


@dataclass
class ReconciliationSummary:
    matched_count: int = 0
    missing_count: int = 0
    corrupted_count: int = 0
    orphaned_count: int = 0
    quarantined_count: int = 0
    details: List[str] = field(default_factory=list)

    @property
    def is_healthy(self) -> bool:
        return self.missing_count == 0 and self.corrupted_count == 0 and self.orphaned_count == 0


class EvidenceIntegrityReconciler:
    """
    Evidence Integrity Reconciler (ADR-02, ADR-03, ADR-05).
    Performs bidirectional reconciliation between SQLite evidence metadata and physical disk storage.
    Detects and handles:
    - Valid matching artifacts (confirmed)
    - Missing files (sync_status -> MISSING_FILE)
    - Checksum mismatches (sync_status -> CORRUPTED, isolate to Quarantine)
    - Orphan files on disk (never automatically adopted, isolated to Quarantine)
    """

    def __init__(
        self,
        paths: Optional[StoragePaths] = None,
        evidence_repo: Optional[IEvidenceRepository] = None,
        quarantine_service: Optional[QuarantineService] = None,
        write_fence: Optional[WriteFence] = None,
    ) -> None:
        self.paths = paths or get_storage_paths()
        self.evidence_repo = evidence_repo or SqliteEvidenceRepository(db_path=self.paths.database_file)
        self.quarantine_service = quarantine_service or QuarantineService(paths=self.paths)
        self.write_fence = write_fence or global_write_fence

    def _resolve_artifact_file(self, artifact_path: str) -> Path:
        """Resolve artifact path against data_dir or handle absolute path."""
        candidate = Path(artifact_path)
        if candidate.is_absolute():
            return candidate
        return (self.paths.data_dir / candidate).resolve()

    def reconcile(self) -> ReconciliationSummary:
        """
        Execute comprehensive bidirectional reconciliation.
        Coordinated through WriteFence to maintain snapshot consistency.
        """
        with self.write_fence.acquire_write():
            summary = ReconciliationSummary()

            # Pre-reconciliation: reconcile quarantine storage and manifest after any abnormal interruptions
            self.quarantine_service.reconcile_quarantine_storage()

            # -----------------------------------------------------------------
            # Pass 1: DB Records -> Disk Files (Missing & Hash Mismatch Checks)
            # -----------------------------------------------------------------
            records = self.evidence_repo.list_evidence(include_deleted=False)
            known_artifact_paths = set()

            for ev in records:
                if not ev.artifactPath:
                    summary.missing_count += 1
                    summary.details.append(f"Evidence {ev.id}: no artifact_path registered.")
                    self.evidence_repo.update_sync_status(ev.id, "MISSING_FILE")
                    continue

                target_file = self._resolve_artifact_file(ev.artifactPath)
                known_artifact_paths.add(str(target_file.resolve()))

                if not target_file.exists() or not target_file.is_file():
                    summary.missing_count += 1
                    summary.details.append(f"Evidence {ev.id}: physical file missing at {target_file}")
                    self.evidence_repo.update_sync_status(ev.id, "MISSING_FILE")
                    continue

                # Verify cryptographic SHA-256
                actual_sha = hashlib.sha256(target_file.read_bytes()).hexdigest()
                if actual_sha != ev.sha256:
                    summary.corrupted_count += 1
                    summary.details.append(
                        f"Evidence {ev.id}: hash mismatch! Expected {ev.sha256}, actual {actual_sha}."
                    )
                    self.evidence_repo.update_sync_status(ev.id, "CORRUPTED")

                    # Move corrupted artifact to quarantine immediately
                    try:
                        q_item = self.quarantine_service.quarantine_file(
                            source_path=target_file,
                            reason=QuarantineReason.HASH_MISMATCH,
                            details=f"Evidence {ev.id} SHA-256 mismatch (expected: {ev.sha256}, actual: {actual_sha})",
                        )
                        summary.quarantined_count += 1
                        summary.details.append(
                            f"Evidence {ev.id}: moved corrupted file to quarantine as {q_item.quarantineId}."
                        )
                    except Exception as e:
                        summary.details.append(f"Failed to quarantine corrupted file {target_file}: {e}")
                else:
                    summary.matched_count += 1
                    if ev.syncStatus != "COMMITTED":
                        self.evidence_repo.update_sync_status(ev.id, "COMMITTED")

            # Include soft-deleted records in known paths so they are not treated as orphans
            deleted_records = self.evidence_repo.list_evidence(include_deleted=True)
            for dev in deleted_records:
                if dev.isDeleted and dev.artifactPath:
                    d_file = self._resolve_artifact_file(dev.artifactPath)
                    known_artifact_paths.add(str(d_file.resolve()))

            # -----------------------------------------------------------------
            # Pass 2: Disk Files -> DB Records (Orphan Detection & Quarantine)
            # -----------------------------------------------------------------
            evidence_dir = self.paths.evidence_dir
            if evidence_dir.exists():
                for disk_file in evidence_dir.rglob("*.json"):
                    # Skip staging directory files
                    if ".staging" in disk_file.parts:
                        continue

                    resolved_disk = str(disk_file.resolve())
                    if resolved_disk not in known_artifact_paths:
                        # Unrecognized disk file with no database metadata
                        summary.orphaned_count += 1
                        summary.details.append(f"Orphan file detected on disk: {disk_file}")

                        # Quarantine orphan artifact (Strict fail-closed: do NOT auto-adopt!)
                        try:
                            q_item = self.quarantine_service.quarantine_file(
                                source_path=disk_file,
                                reason=QuarantineReason.ORPHAN_NO_ASSESSMENT,
                                details=f"Unregistered orphan artifact found at {disk_file}",
                            )
                            summary.quarantined_count += 1
                            summary.details.append(
                                f"Quarantined orphan artifact {disk_file.name} as {q_item.quarantineId}."
                            )
                        except Exception as e:
                            summary.details.append(f"Failed to quarantine orphan file {disk_file}: {e}")

            return summary
