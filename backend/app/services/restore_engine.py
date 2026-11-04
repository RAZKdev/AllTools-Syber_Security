import hashlib
import json
import logging
import os
import shutil
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from app.core.storage_paths import StoragePaths, get_storage_paths
from app.repositories.sqlite_quarantine_repository import SqliteQuarantineRepository
from app.schemas.backup import BackupFileEntry, BackupManifest

logger = logging.getLogger(__name__)


class RestoreError(Exception):
    """Base exception for restore engine failures."""
    pass


class RestoreValidationError(RestoreError):
    """Raised when backup snapshot validation fails prior to restore."""
    pass


class MaintenanceLockError(RestoreError):
    """Raised when application is running or maintenance lock cannot be acquired."""
    pass


class ProductionCutoverError(RestoreError):
    """Raised when controlled production cutover fails and triggers rollback."""
    pass


class ProductionCutoverDisabledError(RestoreError):
    """
    Raised when an attempt is made to replace or cut over into the active production data directory.
    Safety containment (ADR-06, F-02): Production restore cutover is disabled fail-closed pending
    durable write-ahead restore journaling and automatic startup crash-recovery implementation.
    """
    pass


@dataclass
class RestoreSummary:
    generation_id: str
    restored_files_count: int
    total_bytes: int
    database_verified: bool
    manifest_verified: bool
    quarantine_verified: bool


class RestoreEngine:
    """
    Restore Engine implementing isolated destination pre-flight validation,
    cryptographic manifest re-hashing, SQLite integrity checking, quarantine hash-chain
    validation, path traversal protection, and production overwrite guardrails.
    """

    STREAM_BUFFER_SIZE = 64 * 1024

    def __init__(self, paths: Optional[StoragePaths] = None) -> None:
        self.paths = paths or get_storage_paths()

    @classmethod
    def _compute_file_sha256_and_size(cls, file_path: Path) -> Tuple[str, int]:
        hasher = hashlib.sha256()
        total_bytes = 0
        with open(file_path, "rb") as f:
            while chunk := f.read(cls.STREAM_BUFFER_SIZE):
                hasher.update(chunk)
                total_bytes += len(chunk)
        return hasher.hexdigest(), total_bytes

    @classmethod
    def _stream_copy(cls, src_path: Path, dest_path: Path) -> None:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(src_path, "rb") as src, open(dest_path, "wb") as dst:
            while chunk := src.read(cls.STREAM_BUFFER_SIZE):
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())

    def validate_backup(
        self, backup_dir: Path
    ) -> Tuple[bool, List[str], Optional[BackupManifest]]:
        """
        Deep pre-flight validation of a backup directory:
        - Manifest presence, schema, and checksums.
        - Path traversal & symlink/reparse-point escape checks.
        - Physical file presence, byte size, and SHA-256 verification.
        - SQLite database integrity_check and foreign_key_check.
        - Quarantine manifest cryptographic hash chain verification.
        """
        errors: List[str] = []
        manifest: Optional[BackupManifest] = None

        if not backup_dir.exists() or not backup_dir.is_dir():
            return False, [f"Backup directory does not exist or is not a directory: {backup_dir}"], None

        resolved_backup_dir = backup_dir.resolve()

        # 1. Manifest presence & parsing
        manifest_file = backup_dir / "backup_manifest.json"
        if not manifest_file.exists():
            return False, [f"Manifest file missing: {manifest_file}"], None

        try:
            manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
            manifest = BackupManifest(**manifest_data)
        except Exception as e:
            return False, [f"Failed to parse backup_manifest.json: {e}"], None

        # 2. Path Traversal & File Integrity Checks
        for entry in manifest.files:
            rel_p = entry.path

            # Strict path traversal checks
            if rel_p.startswith("/") or rel_p.startswith("\\") or ".." in rel_p.split("/") or ".." in rel_p.split("\\"):
                errors.append(f"Illegal path traversal detected in manifest path: '{rel_p}'")
                continue

            target_file = backup_dir / rel_p
            try:
                resolved_target = target_file.resolve()
                if not str(resolved_target).startswith(str(resolved_backup_dir)):
                    errors.append(f"Symlink or path escape detected for: '{rel_p}'")
                    continue
            except Exception as e:
                errors.append(f"Error resolving path '{rel_p}': {e}")
                continue

            if not target_file.exists() or not target_file.is_file():
                errors.append(f"Manifest references missing file: '{rel_p}'")
                continue

            # Compute and verify SHA-256 and size
            real_sha, real_size = self._compute_file_sha256_and_size(target_file)
            if real_size != entry.byteSize:
                errors.append(f"File size mismatch for '{rel_p}': expected {entry.byteSize}, actual {real_size}")
            if real_sha != entry.sha256:
                errors.append(f"Checksum mismatch for '{rel_p}': expected {entry.sha256}, actual {real_sha}")

        # 3. SQLite Database Integrity Validation
        db_file = backup_dir / "database" / "workbench.db"
        if not db_file.exists():
            errors.append(f"Database snapshot missing at {db_file}")
        else:
            try:
                conn = sqlite3.connect(str(db_file))
                try:
                    integrity = conn.execute("PRAGMA integrity_check;").fetchall()
                    if len(integrity) != 1 or integrity[0][0] != "ok":
                        errors.append(f"SQLite integrity_check failed on backup database: {integrity}")

                    fk_violations = conn.execute("PRAGMA foreign_key_check;").fetchall()
                    if fk_violations:
                        errors.append(f"Foreign key violations found in backup database: {fk_violations}")

                    # Check schema_version table
                    v_row = conn.execute("SELECT MAX(version) FROM schema_version;").fetchone()
                    if not v_row or v_row[0] is None:
                        errors.append("Restored database lacks schema_version table or records.")
                finally:
                    conn.close()
            except Exception as e:
                errors.append(f"Failed to inspect backup SQLite database: {e}")

        # 4. Quarantine Manifest Chain Validation (if present)
        qm_file = backup_dir / "quarantine" / "quarantine_manifest.jsonl"
        if qm_file.exists():
            try:
                lines = qm_file.read_text(encoding="utf-8").strip().splitlines()
                expected_seq = 1
                expected_prev_hash = SqliteQuarantineRepository.GENESIS_PREV_HASH
                for line_idx, line in enumerate(lines, 1):
                    entry_dict = json.loads(line)
                    seq = entry_dict.get("seq")
                    prev_hash = entry_dict.get("prevEntryHash")
                    entry_hash = entry_dict.get("entryHash")

                    if seq != expected_seq:
                        errors.append(f"Quarantine manifest line {line_idx} seq break: expected {expected_seq}, got {seq}")
                    if prev_hash != expected_prev_hash:
                        errors.append(f"Quarantine manifest line {line_idx} hash chain break: expected {expected_prev_hash}, got {prev_hash}")

                    recomputed = SqliteQuarantineRepository.compute_entry_hash(
                        seq=seq,
                        prev_entry_hash=prev_hash,
                        event_id=entry_dict["eventId"],
                        quarantine_id=entry_dict["quarantineId"],
                        sha256=entry_dict["sha256"],
                        byte_size=entry_dict["byteSize"],
                        reason=entry_dict["reason"],
                        quarantined_at_str=entry_dict["quarantinedAt"],
                    )
                    if entry_hash != recomputed:
                        errors.append(f"Quarantine manifest line {line_idx} entryHash mismatch.")

                    expected_seq += 1
                    expected_prev_hash = entry_hash
            except Exception as e:
                errors.append(f"Quarantine manifest verification error: {e}")

        return (len(errors) == 0, errors, manifest)

    def stage_restore(
        self, backup_dir: Path, staging_dir: Path
    ) -> Tuple[RestoreSummary, BackupManifest]:
        """
        Stage a verified backup snapshot into an isolated staging directory and run
        full post-restore cryptographic and SQLite integrity validation.
        """
        is_valid, errors, manifest = self.validate_backup(backup_dir)
        if not is_valid or manifest is None:
            raise RestoreValidationError(
                f"Backup validation failed with {len(errors)} error(s): {'; '.join(errors)}"
            )

        staging_dir.mkdir(parents=True, exist_ok=True)
        restored_count = 0
        total_restored_bytes = 0

        # Database staging
        src_db = backup_dir / "database" / "workbench.db"
        dest_db = staging_dir / "workbench.db"
        self._stream_copy(src_db, dest_db)
        restored_count += 1
        total_restored_bytes += dest_db.stat().st_size

        # Evidence & quarantine staging
        for entry in manifest.files:
            if entry.path.startswith("evidence/") or entry.path.startswith("quarantine/"):
                src_f = backup_dir / entry.path
                dest_f = staging_dir / entry.path
                self._stream_copy(src_f, dest_f)
                restored_count += 1
                total_restored_bytes += dest_f.stat().st_size

        # Verify staged files
        for entry in manifest.files:
            if entry.path == "database/workbench.db":
                check_f = staging_dir / "workbench.db"
            else:
                check_f = staging_dir / entry.path

            if not check_f.exists():
                raise RestoreError(f"Staged file missing prior to promotion: {check_f}")
            actual_sha, actual_size = self._compute_file_sha256_and_size(check_f)
            if actual_sha != entry.sha256 or actual_size != entry.byteSize:
                raise RestoreError(f"Staged file checksum mismatch for {check_f}")

        # Post-restore SQLite check on staged DB
        conn = sqlite3.connect(str(dest_db))
        try:
            ic = conn.execute("PRAGMA quick_check;").fetchone()[0]
            if ic != "ok":
                raise RestoreError(f"Staged database failed quick_check: {ic}")
            fk_violations = conn.execute("PRAGMA foreign_key_check;").fetchall()
            if fk_violations:
                raise RestoreError(f"Staged database has foreign key violations: {fk_violations}")
        finally:
            conn.close()

        summary = RestoreSummary(
            generation_id=manifest.generationId,
            restored_files_count=restored_count,
            total_bytes=total_restored_bytes,
            database_verified=True,
            manifest_verified=True,
            quarantine_verified=True,
        )
        return summary, manifest

    def _is_production_or_descendant(self, target: Path) -> bool:
        """
        Robust boundary check to determine if target path is equal to or a descendant of
        the active production data directory.
        Fails closed (returns True) on any resolution error or ambiguity.
        """
        try:
            prod = self.paths.data_dir
            p_res = prod.resolve()
            t_res = target.resolve()
        except Exception as e:
            logger.warning("Path resolution error during production boundary check for '%s': %s. Failing closed.", target, e)
            return True

        # Check 1: Filesystem inode / file-index equivalence (handles junctions, symlinks, 8.3 aliases)
        if t_res.exists() and p_res.exists():
            try:
                if os.path.samefile(t_res, p_res):
                    return True
            except Exception:
                pass

        # Check 2: Ancestor inode check (walk existing ancestors of target to catch parent links)
        curr = t_res
        while curr != curr.parent:
            curr = curr.parent
            if curr.exists() and p_res.exists():
                try:
                    if os.path.samefile(curr, p_res):
                        return True
                except Exception:
                    pass

        # Check 3: Pathlib lexical comparison (handles standard hierarchy)
        if t_res == p_res or p_res in t_res.parents:
            return True

        # Check 4: OS-level normcase comparison (handles Windows case-folding and slash direction for existing & non-existing paths)
        try:
            norm_p = os.path.normcase(os.path.abspath(str(p_res))).rstrip(os.sep)
            norm_t = os.path.normcase(os.path.abspath(str(t_res))).rstrip(os.sep)
            if norm_t == norm_p or norm_t.startswith(norm_p + os.sep):
                return True
        except Exception:
            return True

        return False

    def restore_backup(
        self,
        backup_dir: Path,
        target_dir: Path,
        confirm_production_overwrite: bool = False,
    ) -> RestoreSummary:
        """
        Restore a verified backup into a target destination directory.
        Fails closed if validation fails.
        Enforces isolated staging, safety backups, and maintenance locks.
        """
        if self._is_production_or_descendant(target_dir):
            return self.execute_production_restore(
                backup_dir=backup_dir,
                confirm_production_overwrite=confirm_production_overwrite,
            )

        # Isolated directory restore: stage into a temporary folder inside target_dir first
        target_dir.mkdir(parents=True, exist_ok=True)
        staging_dir = target_dir / f".staging_restore_{uuid.uuid4().hex[:6]}"
        try:
            summary, manifest = self.stage_restore(backup_dir, staging_dir)
            # Promote staged files into target_dir
            dest_db = target_dir / "workbench.db"
            if (staging_dir / "workbench.db").exists():
                if dest_db.exists():
                    dest_db.unlink()
                shutil.move(str(staging_dir / "workbench.db"), str(dest_db))

            if (staging_dir / "evidence").exists():
                dest_ev = target_dir / "evidence"
                if dest_ev.exists():
                    shutil.rmtree(dest_ev, ignore_errors=True)
                shutil.move(str(staging_dir / "evidence"), str(dest_ev))

            if (staging_dir / "quarantine").exists():
                dest_q = target_dir / "quarantine"
                if dest_q.exists():
                    shutil.rmtree(dest_q, ignore_errors=True)
                shutil.move(str(staging_dir / "quarantine"), str(dest_q))

            logger.info(
                "Successfully restored backup '%s' to '%s' (%d files, %d bytes)",
                manifest.generationId, target_dir, summary.restored_files_count, summary.total_bytes
            )
            return summary
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)

    def execute_production_restore(
        self,
        backup_dir: Path,
        confirm_production_overwrite: bool = False,
        safety_backup: bool = True,
    ) -> RestoreSummary:
        """
        Execute controlled production restore.

        SAFETY CONTAINMENT (ADR-06, F-02):
        Direct in-place production restore cutover is DISABLED fail-closed.
        In-place replacement of the active production data directory is prohibited
        pending durable write-ahead restore journaling and automatic startup crash-recovery.

        To inspect or restore data, operators must restore into an isolated destination
        directory (e.g. restore_backup(backup_dir, target_dir=<isolated_directory>)).
        Production recovery requires a separately approved offline maintenance procedure.
        """
        raise ProductionCutoverDisabledError(
            "Production restore cutover is currently disabled: "
            "In-place replacement of the active production data directory is prohibited "
            "pending durable write-ahead restore journaling and automatic crash-recovery implementation. "
            "To inspect or recover backup data, restore into an isolated destination directory "
            "(e.g., restore_backup(backup_dir, target_dir=<isolated_directory>)). "
            "Production recovery requires a separately approved offline maintenance procedure."
        )

    def _execute_production_cutover_unsupported(
        self,
        backup_dir: Path,
        confirm_production_overwrite: bool = False,
        safety_backup: bool = True,
    ) -> RestoreSummary:
        """
        Decommissioned legacy cutover routine (ADR-06, F-02).
        SAFETY CONTAINMENT: Executable cutover code removed.
        Fails closed unconditionally with ProductionCutoverDisabledError regardless of flags.
        """
        raise ProductionCutoverDisabledError(
            "Production restore cutover is disabled across all public and internal methods. "
            "The historical unjournaled cutover implementation has been decommissioned fail-closed. "
            "Direct invocation of internal cutover routines is prohibited."
        )
