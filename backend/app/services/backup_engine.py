import hashlib
import json
import logging
import os
import shutil
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from app.core.database import create_connection
from app.core.storage_paths import StoragePaths, get_storage_paths
from app.core.write_fence import (
    WriteFence,
    WriteFenceTimeoutError,
    global_backup_hold,
    global_write_fence,
)
from app.repositories.interfaces import IBackupRepository
from app.repositories.sqlite_backup_repository import SqliteBackupRepository
from app.schemas.backup import (
    BackupFileEntry,
    BackupManifest,
    BackupSnapshot,
    BackupStatus,
    DatabaseIntegrityInfo,
)

logger = logging.getLogger(__name__)


class BackupError(Exception):
    """Base exception for backup subsystem failures."""
    pass


class InsufficientDiskSpaceError(BackupError):
    """Raised when available free disk space is less than 2x estimated backup size (ADR-06)."""
    pass


class BackupCollisionError(BackupError):
    """Raised when target backup directory already exists."""
    pass


class BackupIntegrityError(BackupError):
    """Raised when backup artifact validation fails."""
    pass


class BackupEngine:
    """
    Hot Backup Engine implementing coordinated snapshot generation, online SQLite
    backup, atomic staging promotion, retention management, and disk safety (ADR-06).
    """

    DEFAULT_RETENTION_COUNT = 10
    STREAM_BUFFER_SIZE = 64 * 1024  # 64 KB streaming buffer

    def __init__(
        self,
        paths: Optional[StoragePaths] = None,
        backup_repo: Optional[IBackupRepository] = None,
        write_fence: Optional[WriteFence] = None,
    ) -> None:
        self.paths = paths or get_storage_paths()
        self.backup_repo = backup_repo or SqliteBackupRepository(db_path=self.paths.database_file)
        self.write_fence = write_fence or global_write_fence

        self.backups_dir = self.paths.backups_dir
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        self.staging_dir = self.backups_dir / ".staging"
        self.staging_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def _compute_file_sha256_and_size(cls, file_path: Path) -> Tuple[str, int]:
        """Compute SHA-256 and byte size using streaming chunks to minimize memory footprint."""
        hasher = hashlib.sha256()
        total_bytes = 0
        with open(file_path, "rb") as f:
            while chunk := f.read(cls.STREAM_BUFFER_SIZE):
                hasher.update(chunk)
                total_bytes += len(chunk)
        return hasher.hexdigest(), total_bytes

    @classmethod
    def _stream_copy_with_hash(cls, src_path: Path, dest_path: Path) -> Tuple[str, int]:
        """Copy a file using streaming buffer while simultaneously calculating its SHA-256 digest."""
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        hasher = hashlib.sha256()
        total_bytes = 0

        with open(src_path, "rb") as src, open(dest_path, "wb") as dst:
            while chunk := src.read(cls.STREAM_BUFFER_SIZE):
                hasher.update(chunk)
                dst.write(chunk)
                total_bytes += len(chunk)
            dst.flush()
            os.fsync(dst.fileno())

        return hasher.hexdigest(), total_bytes

    def _estimate_source_size(self) -> int:
        """Estimate the total uncompressed source size across database and disk artifacts."""
        total = 0
        if self.paths.database_file.exists():
            total += self.paths.database_file.stat().st_size

        if self.paths.evidence_dir.exists():
            for p in self.paths.evidence_dir.rglob("*.json"):
                if ".staging" not in p.parts:
                    total += p.stat().st_size

        if self.paths.quarantine_dir.exists():
            for p in self.paths.quarantine_dir.rglob("*"):
                if p.is_file():
                    total += p.stat().st_size

        # Add 1 MB buffer for SQLite pages and manifest overhead
        return total + 1024 * 1024

    def _preflight_disk_space_check(self) -> Tuple[int, int]:
        """
        Verify available disk space on the volume hosting backups_dir.
        Enforces ADR-06 requirement: available free space >= 2x estimated backup size.
        """
        usage = shutil.disk_usage(self.backups_dir)
        free_bytes = usage.free
        estimated_size = self._estimate_source_size()
        required_bytes = 2 * estimated_size

        if free_bytes < required_bytes:
            free_mb = free_bytes / (1024 * 1024)
            est_mb = estimated_size / (1024 * 1024)
            req_mb = required_bytes / (1024 * 1024)
            raise InsufficientDiskSpaceError(
                f"Insufficient disk space for backup: available {free_mb:.1f} MB is less than "
                f"required 2x estimated backup size {req_mb:.1f} MB (estimated: {est_mb:.1f} MB)."
            )
        return free_bytes, estimated_size

    def create_backup(
        self,
        generation_id: Optional[str] = None,
        retention_limit: int = DEFAULT_RETENTION_COUNT,
    ) -> BackupManifest:
        """
        Execute full coordinated hot backup through the atomic state machine:
        STAGING -> SNAPSHOT_COMPLETE -> VERIFIED -> PROMOTED
        """
        # 1. Preflight disk space verification
        free_bytes, estimated_size = self._preflight_disk_space_check()

        # 2. Generation Identifier & Staging Setup
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        gen_id = generation_id or f"BKP-{timestamp_str}-{uuid.uuid4().hex[:6]}"

        final_backup_dir = self.backups_dir / gen_id
        if final_backup_dir.exists():
            raise BackupCollisionError(f"Backup directory already exists: '{final_backup_dir}'")

        snapshot_staging = self.staging_dir / f"{gen_id}_{uuid.uuid4().hex[:8]}.tmp"
        try:
            snapshot_staging.mkdir(parents=True, exist_ok=True)
            staged_db_dir = snapshot_staging / "database"
            staged_db_dir.mkdir(parents=True, exist_ok=True)
            staged_db_file = staged_db_dir / "workbench.db"

            staged_ev_dir = snapshot_staging / "evidence"
            staged_ev_dir.mkdir(parents=True, exist_ok=True)

            staged_quar_dir = snapshot_staging / "quarantine"
            staged_quar_dir.mkdir(parents=True, exist_ok=True)

            # Record backup initiation in repository
            self.backup_repo.record_backup_started(gen_id, sqlite_data_version=0)
        except Exception as e:
            shutil.rmtree(snapshot_staging, ignore_errors=True)
            raise

        # -------------------------------------------------------------
        # Phase 1: Write-Fence Coordination Barrier (< 500 ms target)
        # -------------------------------------------------------------
        active_evidence_records = []
        quarantine_records = []
        protected_artifact_paths: Set[str] = set()
        db_integrity = None
        coordination_duration_ms = 0

        try:
            with self.write_fence.fence_writes(timeout_ms=500) as fence_info:
                # Open active database connection
                src_conn = create_connection(self.paths.database_file)
                try:
                    # Query data version & schema version
                    data_version = src_conn.execute("PRAGMA data_version;").fetchone()[0]
                    v_row = src_conn.execute("SELECT MAX(version) FROM schema_version;").fetchone()
                    schema_version = int(v_row[0]) if (v_row and v_row[0] is not None) else 1
                    page_count = src_conn.execute("PRAGMA page_count;").fetchone()[0]

                    # Execute SQLite Online Backup API to create point-in-time database snapshot
                    dest_conn = sqlite3.connect(str(staged_db_file))
                    src_conn.backup(dest_conn)
                    dest_conn.close()

                    # Query consistent snapshot of active evidence and quarantine items
                    ev_rows = src_conn.execute(
                        "SELECT id, assessment_id, artifact_path, sha256 FROM evidence WHERE is_deleted = 0;"
                    ).fetchall()
                    for r in ev_rows:
                        active_evidence_records.append(dict(r))
                        if r["artifact_path"]:
                            protected_artifact_paths.add(r["artifact_path"])

                    q_rows = src_conn.execute(
                        "SELECT quarantine_id, quarantine_path, sha256 FROM quarantine_items;"
                    ).fetchall()
                    for qr in q_rows:
                        quarantine_records.append(dict(qr))

                    # Protect artifacts from concurrent purge during background file copy
                    global_backup_hold.hold_paths(protected_artifact_paths)

                finally:
                    src_conn.close()

                coordination_duration_ms = fence_info.get("coordination_duration_ms", 0)

        except Exception as e:
            self.backup_repo.record_backup_failed(gen_id)
            shutil.rmtree(snapshot_staging, ignore_errors=True)
            raise BackupError(f"Snapshot coordination failed: {e}") from e

        # -------------------------------------------------------------
        # Phase 2: Background File Copying (Non-blocking)
        # -------------------------------------------------------------
        manifest_files: List[BackupFileEntry] = []
        total_copied_bytes = 0

        try:
            # 1. Hash and record SQLite snapshot database
            db_sha, db_size = self._compute_file_sha256_and_size(staged_db_file)
            manifest_files.append(
                BackupFileEntry(path="database/workbench.db", byteSize=db_size, sha256=db_sha)
            )
            total_copied_bytes += db_size

            # Check database integrity on the backup copy
            verify_conn = sqlite3.connect(str(staged_db_file))
            try:
                quick_check = verify_conn.execute("PRAGMA quick_check;").fetchone()[0]
                if quick_check != "ok":
                    raise BackupIntegrityError(f"Snapshot database quick_check failed: {quick_check}")
                db_integrity = DatabaseIntegrityInfo(
                    quickCheck=quick_check,
                    pageCount=page_count,
                    dataVersion=data_version,
                    schemaVersion=schema_version,
                )
            finally:
                verify_conn.close()

            # 2. Copy snapshot-referenced evidence files
            for ev in active_evidence_records:
                art_path_str = ev.get("artifact_path")
                if not art_path_str:
                    continue

                src_ev_file = self.paths.data_dir / art_path_str
                if src_ev_file.exists() and src_ev_file.is_file():
                    # Destination inside staging / evidence / <assessment_id> / <filename>
                    dest_ev_file = snapshot_staging / art_path_str
                    copied_sha, copied_size = self._stream_copy_with_hash(src_ev_file, dest_ev_file)
                    rel_p = str(dest_ev_file.relative_to(snapshot_staging)).replace("\\", "/")
                    manifest_files.append(
                        BackupFileEntry(path=rel_p, byteSize=copied_size, sha256=copied_sha)
                    )
                    total_copied_bytes += copied_size

            # 3. Copy quarantine artifacts and manifest
            quar_manifest_src = self.paths.quarantine_dir / "quarantine_manifest.jsonl"
            if quar_manifest_src.exists():
                dest_qm = staged_quar_dir / "quarantine_manifest.jsonl"
                qm_sha, qm_size = self._stream_copy_with_hash(quar_manifest_src, dest_qm)
                manifest_files.append(
                    BackupFileEntry(path="quarantine/quarantine_manifest.jsonl", byteSize=qm_size, sha256=qm_sha)
                )
                total_copied_bytes += qm_size

            for q_item in quarantine_records:
                q_path_str = q_item.get("quarantine_path")
                if not q_path_str:
                    continue
                src_q_file = Path(q_path_str)
                if src_q_file.exists() and src_q_file.is_file():
                    dest_q_file = staged_quar_dir / src_q_file.name
                    q_sha, q_size = self._stream_copy_with_hash(src_q_file, dest_q_file)
                    rel_qp = str(dest_q_file.relative_to(snapshot_staging)).replace("\\", "/")
                    manifest_files.append(
                        BackupFileEntry(path=rel_qp, byteSize=q_size, sha256=q_sha)
                    )
                    total_copied_bytes += q_size

        finally:
            # Release hold on artifacts
            global_backup_hold.release_paths(protected_artifact_paths)

        # -------------------------------------------------------------
        # Phase 3: Manifest Generation & Verification
        # -------------------------------------------------------------
        manifest_obj = BackupManifest(
            generationId=gen_id,
            backupFormatVersion="1.0",
            createdAt=datetime.now(timezone.utc),
            schemaVersion=schema_version,
            coordinationDurationMs=coordination_duration_ms,
            databaseIntegrity=db_integrity,  # type: ignore
            files=manifest_files,
            totalBytes=total_copied_bytes,
        )

        # Serialize manifest to staging
        manifest_path = snapshot_staging / "backup_manifest.json"
        manifest_json_str = manifest_obj.model_dump_json(indent=2)
        manifest_sha = hashlib.sha256(manifest_json_str.encode("utf-8")).hexdigest()
        manifest_obj.manifestSha256 = manifest_sha

        # Write final manifest
        manifest_path.write_text(manifest_obj.model_dump_json(indent=2), encoding="utf-8")

        # -------------------------------------------------------------
        # Phase 4: Atomic Promotion (VERIFIED -> PROMOTED)
        # -------------------------------------------------------------
        try:
            # Re-verify every file in staging against manifest before promoting
            for f_entry in manifest_files:
                target_f = snapshot_staging / f_entry.path
                if not target_f.exists():
                    raise BackupIntegrityError(f"Staged file missing prior to promotion: {f_entry.path}")
                real_sha, real_size = self._compute_file_sha256_and_size(target_f)
                if real_sha != f_entry.sha256 or real_size != f_entry.byteSize:
                    raise BackupIntegrityError(f"Pre-promotion verification checksum mismatch for {f_entry.path}")

            # Atomic rename on same filesystem
            if final_backup_dir.exists():
                raise BackupCollisionError(f"Backup directory collision at '{final_backup_dir}'")
            os.replace(snapshot_staging, final_backup_dir)
        except Exception as e:
            self.backup_repo.record_backup_failed(gen_id)
            shutil.rmtree(snapshot_staging, ignore_errors=True)
            raise

        # Update SQLite repository to COMPLETED
        self.backup_repo.record_backup_completed(
            generation_id=gen_id,
            manifest_sha256=manifest_sha,
            byte_size=total_copied_bytes,
            evidence_count=len(active_evidence_records),
            quarantine_count=len(quarantine_records),
        )

        # -------------------------------------------------------------
        # Phase 5: Retention Enforcement (Prune Oldest > 10)
        # -------------------------------------------------------------
        self._enforce_retention(retention_limit=retention_limit)

        logger.info(
            "Successfully created and promoted hot backup '%s' (%d bytes, %d files)",
            gen_id, total_copied_bytes, len(manifest_files)
        )
        return manifest_obj

    def _enforce_retention(self, retention_limit: int = DEFAULT_RETENTION_COUNT) -> int:
        """
        Enforce retention rules (ADR-06):
        - Maximum N successfully completed and verified snapshots (default 10).
        - Failed backups do not count.
        - Never prune before a replacement passes verification and promotion.
        - NEVER remove the last known-good backup.
        """
        completed_backups = self.backup_repo.list_backups(status=BackupStatus.COMPLETED)
        if retention_limit > 0 and len(completed_backups) <= retention_limit:
            return 0

        # Sort oldest first (created_at ASC)
        completed_backups_sorted = sorted(completed_backups, key=lambda b: b.createdAt)
        if retention_limit > 0:
            prune_candidates = completed_backups_sorted[:-retention_limit]
        else:
            prune_candidates = completed_backups_sorted

        pruned_count = 0
        for candidate in prune_candidates:
            # Invariant: Never delete if it is the only remaining backup
            remaining = self.backup_repo.list_backups(status=BackupStatus.COMPLETED)
            if len(remaining) <= 1:
                break

            target_dir = self.backups_dir / candidate.id
            if target_dir.exists():
                shutil.rmtree(target_dir, ignore_errors=True)
            self.backup_repo.delete_backup_record(candidate.id)
            pruned_count += 1
            logger.info("Pruned old backup snapshot '%s' under retention policy.", candidate.id)

        return pruned_count

    def cleanup_stale_staging(self, max_age_seconds: int = 3600) -> int:
        """
        Interrupted backup recovery (ADR-06, F-03):
        - Scans .staging directory for abandoned temp folders older than max_age_seconds and removes them safely.
        - Reconciles stranded IN_PROGRESS records in the database, ONLY marking records as FAILED if their
          creation timestamp is older than max_age_seconds (or if max_age_seconds == 0 on application startup).
        - Actively running IN_PROGRESS backups younger than max_age_seconds are preserved.
        """
        now = time.time()
        now_dt = datetime.now(timezone.utc)
        cleaned_dirs = 0

        if self.staging_dir.exists():
            for tmp_dir in self.staging_dir.glob("*.tmp"):
                try:
                    if max_age_seconds == 0 or (now - tmp_dir.stat().st_mtime > max_age_seconds):
                        shutil.rmtree(tmp_dir, ignore_errors=True)
                        cleaned_dirs += 1
                        logger.info("Cleaned stale staging directory %s", tmp_dir.name)
                except Exception as e:
                    logger.warning("Failed to clean stale staging directory %s: %s", tmp_dir, e)

        # Reconcile stranded IN_PROGRESS records in database with age threshold
        try:
            records = self.backup_repo.list_backups(status=BackupStatus.IN_PROGRESS)
            for r in records:
                age_seconds = (now_dt - r.createdAt).total_seconds()
                if max_age_seconds == 0 or age_seconds > max_age_seconds:
                    self.backup_repo.record_backup_failed(r.id)
                    logger.info("Reconciled abandoned IN_PROGRESS backup record '%s' (age %.1fs > %ds) to FAILED.", r.id, age_seconds, max_age_seconds)
                else:
                    logger.debug("Preserving active IN_PROGRESS backup record '%s' (age %.1fs <= %ds).", r.id, age_seconds, max_age_seconds)
        except Exception as e:
            logger.warning("Error reconciling stranded IN_PROGRESS backup records: %s", e)

        return cleaned_dirs
