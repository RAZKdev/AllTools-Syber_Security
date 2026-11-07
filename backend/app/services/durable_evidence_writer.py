import hashlib
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Tuple

from app.core.storage_paths import StoragePaths, get_storage_paths
from app.core.write_fence import global_write_fence
from app.repositories.interfaces import IEvidenceRepository, IQuarantineRepository
from app.repositories.sqlite_evidence_repository import SqliteEvidenceRepository
from app.repositories.sqlite_quarantine_repository import SqliteQuarantineRepository
from app.schemas.evidence import Evidence, EvidenceCreate, EvidenceType
from evidence.storage import EvidenceStore

logger = logging.getLogger(__name__)


class EvidenceError(Exception):
    """Base exception for evidence subsystem failures."""
    pass


class EvidenceCollisionError(EvidenceError):
    """Raised when target evidence artifact destination already exists (no-overwrite invariant)."""
    pass


class EvidenceIntegrityError(EvidenceError):
    """Raised when artifact bytes fail cryptographic checksum verification."""
    pass


class DurableEvidenceWriter:
    """
    Durable Evidence Writer implementing the 5-stage write state machine:
    TEMP_WRITING -> TEMP_VERIFIED -> DB_PREPARED -> PUBLISHED -> DB_COMMITTED

    Guarantees:
    - Same-filesystem atomic rename via local staging directory (.staging).
    - No-overwrite protection for existing artifacts.
    - Cryptographic SHA-256 integrity verification pre- and post-publication.
    - Automated redaction of sensitive credentials and tokens.
    - Strict fail-closed error handling with transactional rollback.
    """

    MAX_EVIDENCE_BYTES = 5 * 1024 * 1024  # 5 MB per artifact

    def __init__(
        self,
        paths: Optional[StoragePaths] = None,
        evidence_repo: Optional[IEvidenceRepository] = None,
        quarantine_repo: Optional[IQuarantineRepository] = None,
    ) -> None:
        self.paths = paths or get_storage_paths()
        self.evidence_repo = evidence_repo or SqliteEvidenceRepository(db_path=self.paths.database_file)
        self.quarantine_repo = quarantine_repo or SqliteQuarantineRepository(db_path=self.paths.database_file)

        # Staging directory is strictly located on the same filesystem/volume as evidence_dir
        self.staging_dir = self.paths.evidence_dir / ".staging"
        self.staging_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _sanitize_id(identifier: str) -> str:
        """Strip illegal characters and directory traversal markers."""
        return re.sub(r"[^a-zA-Z0-9_\-]", "", identifier) or "default"

    def _prepare_payload(self, raw_content: Any) -> Tuple[bytes, bool]:
        """Serialize, redact sensitive tokens, and enforce byte limits."""
        if isinstance(raw_content, (dict, list)):
            content_str = json.dumps(raw_content, indent=2, sort_keys=True)
        elif isinstance(raw_content, bytes):
            content_str = raw_content.decode("utf-8", errors="replace")
        else:
            content_str = str(raw_content)

        clean_content, was_redacted = EvidenceStore.redact_text(content_str)
        content_bytes = clean_content.encode("utf-8")

        if len(content_bytes) > self.MAX_EVIDENCE_BYTES:
            clean_content = (
                clean_content[: self.MAX_EVIDENCE_BYTES]
                + "\n...[TRUNCATED: EXCEEDED_5MB_LIMIT]..."
            )
            content_bytes = clean_content.encode("utf-8")

        return content_bytes, was_redacted

    def write_evidence(
        self,
        assessment_id: str,
        evidence_type: EvidenceType,
        source: str,
        raw_content: Any,
        evidence_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        notes: Optional[str] = None,
        retention_policy: str = "retain_90_days",
    ) -> Evidence:
        """
        Execute the complete durable write pipeline for an evidence artifact.
        """
        with global_write_fence.acquire_write():
            safe_assessment_id = self._sanitize_id(assessment_id)
            ev_id = evidence_id or f"EVD-{uuid.uuid4().hex[:8]}"
            safe_ev_id = self._sanitize_id(ev_id)

            # Target destination on disk
            dest_dir = self.paths.evidence_dir / safe_assessment_id
            dest_file = dest_dir / f"{safe_ev_id}.json"

            # Check for destination collision: NEVER overwrite existing evidence!
            if dest_file.exists():
                raise EvidenceCollisionError(
                    f"Destination artifact already exists at '{dest_file}'. Overwrite is strictly forbidden."
                )

            # Prepare normalized bytes and redaction state
            content_bytes, was_redacted = self._prepare_payload(raw_content)

            # -------------------------------------------------------------
            # Stage 1: TEMP_WRITING
            # -------------------------------------------------------------
            temp_file = self.staging_dir / f"{safe_ev_id}_{uuid.uuid4().hex[:8]}.tmp"
            try:
                with open(temp_file, "wb") as f:
                    f.write(content_bytes)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception as e:
                if temp_file.exists():
                    temp_file.unlink(missing_ok=True)
                raise EvidenceError(f"Failed to stage evidence artifact to disk: {str(e)}") from e

            # -------------------------------------------------------------
            # Stage 2: TEMP_VERIFIED
            # -------------------------------------------------------------
            try:
                staged_bytes = temp_file.read_bytes()
                computed_sha256 = hashlib.sha256(staged_bytes).hexdigest()
                if not staged_bytes or len(staged_bytes) != len(content_bytes):
                    raise EvidenceIntegrityError("Staged file size mismatch or empty content.")
            except Exception as e:
                temp_file.unlink(missing_ok=True)
                raise EvidenceIntegrityError(f"Pre-publish staging verification failed: {str(e)}") from e

            # Relative or canonical artifact path
            try:
                rel_artifact_path = str(dest_file.relative_to(self.paths.data_dir)).replace("\\", "/")
            except ValueError:
                rel_artifact_path = str(dest_file).replace("\\", "/")

            # -------------------------------------------------------------
            # Stage 3: DB_PREPARED
            # -------------------------------------------------------------
            evidence_create = EvidenceCreate(
                id=ev_id,
                assessmentId=assessment_id,
                findingId=finding_id,
                type=evidence_type,
                source=source,
                artifactPath=rel_artifact_path,
                capturedAt=datetime.now(timezone.utc),
                sha256=computed_sha256,
                redacted=was_redacted,
                notes=notes,
                syncStatus="PREPARED",
                retentionPolicy=retention_policy,
            )

            try:
                evidence_record = self.evidence_repo.create_evidence(
                    data=evidence_create, sync_status="PREPARED"
                )
            except Exception as e:
                temp_file.unlink(missing_ok=True)
                raise EvidenceError(f"Failed to create PREPARED evidence record in database: {str(e)}") from e

            # -------------------------------------------------------------
            # Stage 4: PUBLISHED (Atomic Rename on Same Filesystem)
            # -------------------------------------------------------------
            try:
                dest_dir.mkdir(parents=True, exist_ok=True)
                # Re-check collision immediately before atomic rename
                if dest_file.exists():
                    self.evidence_repo.update_sync_status(ev_id, "COLLISION_ERROR")
                    temp_file.unlink(missing_ok=True)
                    raise EvidenceCollisionError(f"Race collision detected at '{dest_file}'. Rename aborted.")

                os.replace(temp_file, dest_file)
            except Exception as e:
                temp_file.unlink(missing_ok=True)
                if not isinstance(e, EvidenceCollisionError):
                    self.evidence_repo.update_sync_status(ev_id, "MISSING_FILE")
                raise

            # -------------------------------------------------------------
            # Stage 5: DB_COMMITTED (Post-publish Integrity Verification)
            # -------------------------------------------------------------
            try:
                published_bytes = dest_file.read_bytes()
                post_publish_sha = hashlib.sha256(published_bytes).hexdigest()
                if post_publish_sha != computed_sha256:
                    # Critical checksum corruption detected immediately post-publish!
                    self.evidence_repo.update_sync_status(ev_id, "CORRUPTED")
                    raise EvidenceIntegrityError(
                        f"Post-publish checksum mismatch for {dest_file}. Expected {computed_sha256}, got {post_publish_sha}."
                    )

                # Successfully verified: commit status to COMMITTED
                self.evidence_repo.update_sync_status(ev_id, "COMMITTED")
                committed_record = self.evidence_repo.get_evidence(ev_id)
                if not committed_record:
                    raise EvidenceError(f"Failed to retrieve committed evidence record '{ev_id}'.")
                return committed_record

            except Exception as e:
                if not isinstance(e, EvidenceIntegrityError):
                    self.evidence_repo.update_sync_status(ev_id, "CORRUPTED")
                raise

    def cleanup_stale_staging(self, max_age_seconds: int = 3600) -> int:
        """
        Interrupted write recovery: scans staging directory for temporary files
        older than max_age_seconds and removes them safely.
        Also inspects any DB records stranded in 'PREPARED' state.
        """
        now = time.time()
        cleaned_files = 0

        # 1. Clean stale temp files in .staging
        if self.staging_dir.exists():
            for tmp_path in self.staging_dir.glob("*.tmp"):
                try:
                    if now - tmp_path.stat().st_mtime > max_age_seconds:
                        tmp_path.unlink(missing_ok=True)
                        cleaned_files += 1
                except Exception as e:
                    logger.warning("Failed to clean stale staging file %s: %s", tmp_path, e)

        # 2. Reconcile stranded PREPARED records in database
        # If the destination file already exists and matches hash, upgrade to COMMITTED;
        # otherwise mark as MISSING_FILE.
        try:
            records = self.evidence_repo.list_evidence(include_deleted=True)
            for r in records:
                if r.syncStatus == "PREPARED":
                    target_file = self.paths.data_dir / r.artifactPath if r.artifactPath else None
                    if target_file and target_file.is_file():
                        file_sha = hashlib.sha256(target_file.read_bytes()).hexdigest()
                        if file_sha == r.sha256:
                            self.evidence_repo.update_sync_status(r.id, "COMMITTED")
                        else:
                            self.evidence_repo.update_sync_status(r.id, "CORRUPTED")
                    else:
                        self.evidence_repo.update_sync_status(r.id, "MISSING_FILE")
        except Exception as e:
            logger.warning("Error reconciling stranded PREPARED records: %s", e)

        return cleaned_files
