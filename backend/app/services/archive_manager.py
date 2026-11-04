"""
Archive Manager & Manifest Writer - Phase E3A Final Hardening.

Manages creation of archive destination directory structures and records durable,
append-only cryptographic manifest records for non-active evidence archives
(historical evidence, test fixtures, and malformed artifacts).
Enforces:
- Shared process-local writer serialization across instances (threading.RLock).
- Strict OS-level MaintenanceSession ownership verification.
- Physical target integrity checks (regular file, reparse point rejection, archive boundary containment, SHA-256/size equality).
- Stable deterministic record identity and strict conflict detection.
- Non-destructive JSONL recovery (byte preservation, anomaly tracking, newline normalization).
- Authoritative SQLite journal backfill with post-write verification.
"""

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from app.core.instance_lock import InstanceLock, MaintenanceSession, ProcessLockError
from app.services.migration_models import (
    DEFAULT_IDENTITY_VERSION,
    DEFAULT_SOURCE_NAMESPACE,
    ArchiveManifestEntry,
    MigrationIntegrityError,
    MigrationRecoveryError,
    extract_source_relative_path,
    generate_manifest_record_id,
    generate_manifest_record_id_v1,
    generate_manifest_record_id_v2,
)

logger = logging.getLogger(__name__)


def is_reparse_point_or_symlink(path: Path) -> bool:
    """Detects symlinks, directory junctions, and reparse points on POSIX and Windows."""
    if path.is_symlink():
        return True
    if os.name == "nt":
        try:
            import ctypes
            GetFileAttributesW = ctypes.windll.kernel32.GetFileAttributesW
            FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
            INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
            attrs = GetFileAttributesW(str(path))
            if attrs != INVALID_FILE_ATTRIBUTES and bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT):
                return True
        except Exception:
            pass
    return False


class ArchiveManager:
    """
    Manages archive target paths and appends durable audit records to archive_manifest.jsonl.
    Enforces exclusive maintenance lock ownership, process-local concurrency serialization,
    physical target validation, and non-destructive recovery.
    """

    # Global process-local registry sharing locks across instances pointing to the same canonical manifest
    _PATH_LOCKS: Dict[Path, threading.RLock] = {}
    _REGISTRY_LOCK = threading.Lock()

    @classmethod
    def _get_path_lock(cls, manifest_path: Path) -> threading.RLock:
        """Retrieves or creates a shared RLock for a canonical manifest file path."""
        resolved = manifest_path.resolve()
        with cls._REGISTRY_LOCK:
            if resolved not in cls._PATH_LOCKS:
                cls._PATH_LOCKS[resolved] = threading.RLock()
            return cls._PATH_LOCKS[resolved]

    def __init__(
        self,
        data_dir: Path,
        maintenance_session: Optional[MaintenanceSession] = None,
        maintenance_lock: Optional[InstanceLock] = None,
    ) -> None:
        self.data_dir = Path(data_dir).resolve()
        self.archive_root = (self.data_dir / "archive").resolve()
        self.historical_archive_dir = (self.archive_root / "evidence").resolve()
        self.test_archive_dir = (self.archive_root / "tests").resolve()
        self.malformed_archive_dir = (self.test_archive_dir / "malformed").resolve()
        self.manifest_file = (self.archive_root / "archive_manifest.jsonl").resolve()

        # Shared canonical file lock for thread synchronization
        self._lock = self._get_path_lock(self.manifest_file)

        if maintenance_session is not None:
            self.session: Optional[MaintenanceSession] = maintenance_session
        elif maintenance_lock is not None:
            if not maintenance_lock.is_acquired:
                raise ProcessLockError(
                    f"Provided InstanceLock on '{maintenance_lock.lock_path}' is not acquired."
                )
            self.session = MaintenanceSession(maintenance_lock)
        else:
            self.session = None

    def _assert_maintenance_ownership(self) -> None:
        """Asserts that an active exclusive maintenance lock session is held before mutation."""
        if self.session is None or not self.session.is_active:
            raise ProcessLockError(
                "Direct ArchiveManager publication without an active exclusive maintenance lock is strictly prohibited."
            )

    @staticmethod
    def _sanitize_segment(segment: str) -> str:
        """Sanitize directory and file path components."""
        return re.sub(r"[^a-zA-Z0-9_\-.]", "_", segment) or "default"

    def get_target_path(
        self,
        primary_disposition: str,
        parent_folder: str,
        filename: str,
    ) -> Path:
        """
        Compute canonical target destination path in the archive structure.
        """
        safe_folder = self._sanitize_segment(parent_folder)
        safe_filename = self._sanitize_segment(filename)

        if primary_disposition == "HISTORICAL_ARCHIVE":
            return self.historical_archive_dir / safe_folder / safe_filename
        elif primary_disposition == "MALFORMED_PRESERVE":
            return self.malformed_archive_dir / safe_folder / safe_filename
        else:
            # Default: LEGACY_TEST_ARCHIVE
            return self.test_archive_dir / safe_folder / safe_filename

    def verify_physical_target(
        self,
        target_path: Path,
        expected_sha256: str,
        expected_size: int,
        operation_id: Optional[str] = None,
        artifact_id: Optional[str] = None,
    ) -> None:
        """
        Strictly verify the physical archive destination file on disk.
        Fails closed with MigrationIntegrityError if any check fails:
        1. Target must exist.
        2. Target must be a regular file.
        3. Target must not be a symlink or Windows reparse point.
        4. Resolved path must reside within the approved archive root.
        5. File size must equal expected size.
        6. Physical SHA-256 must match expected digest.
        """
        target_p = Path(target_path)

        # 1. Existence check
        if not target_p.exists():
            raise MigrationIntegrityError(
                f"Physical archive target missing at '{target_p}' for artifact '{artifact_id or target_p.name}'"
            )

        # 2. Regular file check
        if not target_p.is_file():
            raise MigrationIntegrityError(
                f"Physical archive target '{target_p}' is not a regular file."
            )

        # 3. Symlink / Reparse point check
        if is_reparse_point_or_symlink(target_p):
            raise MigrationIntegrityError(
                f"Physical archive target '{target_p}' is a symlink or reparse point, which is strictly prohibited."
            )

        # 4. Containment within archive root
        try:
            resolved_target = target_p.resolve()
            resolved_root = self.archive_root.resolve()
            if not (resolved_target == resolved_root or resolved_target.is_relative_to(resolved_root)):
                raise MigrationIntegrityError(
                    f"Physical archive target '{resolved_target}' escapes approved archive root '{resolved_root}'."
                )
        except Exception as e:
            raise MigrationIntegrityError(f"Target containment check failed for '{target_p}': {e}") from e

        # 5. File size check
        actual_size = target_p.stat().st_size
        if actual_size != expected_size:
            raise MigrationIntegrityError(
                f"Physical size mismatch for '{target_p}': expected {expected_size} bytes, got {actual_size} bytes."
            )

        # 6. Physical SHA-256 digest check
        hasher = hashlib.sha256()
        with open(target_p, "rb") as f:
            while chunk := f.read(64 * 1024):
                hasher.update(chunk)
        actual_sha = hasher.hexdigest()

        if actual_sha != expected_sha256:
            raise MigrationIntegrityError(
                f"Physical SHA-256 mismatch for '{target_p}': expected {expected_sha256}, computed {actual_sha}."
            )

    def scan_existing_records(self) -> Tuple[Dict[str, ArchiveManifestEntry], Optional[Dict[str, Any]]]:
        """
        Scan existing archive_manifest.jsonl non-destructively under process-local serialization.
        Returns:
            - Dict of seen ArchiveManifestEntry keyed by manifest_record_id.
            - Malformed tail diagnostic dict if incomplete/malformed bytes exist at EOF, else None.
        """
        with self._lock:
            seen_records: Dict[str, ArchiveManifestEntry] = {}
            tail_diagnostic: Optional[Dict[str, Any]] = None

            if not self.manifest_file.exists():
                return seen_records, None

            with open(self.manifest_file, "rb") as f:
                raw_data = f.read()

            if not raw_data:
                return seen_records, None

            lines = raw_data.split(b"\n")
            ends_with_newline = raw_data.endswith(b"\n")
            complete_lines = lines[:-1] if not ends_with_newline else lines
            trailing_fragment = lines[-1] if not ends_with_newline else b""

            for idx, line_bytes in enumerate(complete_lines, 1):
                stripped = line_bytes.strip()
                if not stripped:
                    continue
                try:
                    rec_dict = json.loads(stripped.decode("utf-8"))
                    entry = ArchiveManifestEntry.model_validate(rec_dict)
                    seen_records[entry.manifest_record_id] = entry
                except Exception as e:
                    logger.warning("Invalid JSON at line %d in %s: %s", idx, self.manifest_file, e)

            if trailing_fragment:
                stripped_frag = trailing_fragment.strip()
                is_valid_json = False
                try:
                    rec_dict = json.loads(stripped_frag.decode("utf-8"))
                    entry = ArchiveManifestEntry.model_validate(rec_dict)
                    seen_records[entry.manifest_record_id] = entry
                    is_valid_json = True
                except Exception:
                    pass

                tail_diagnostic = {
                    "byte_offset": len(raw_data) - len(trailing_fragment),
                    "length": len(trailing_fragment),
                    "sha256": hashlib.sha256(trailing_fragment).hexdigest(),
                    "is_valid_json_without_newline": is_valid_json,
                    "raw_bytes_preview": str(trailing_fragment[:50]),
                }
                logger.info("Non-newline trailing bytes detected in %s: %s", self.manifest_file, tail_diagnostic)

            return seen_records, tail_diagnostic

    def _sync_existing_file(self) -> None:
        """Issue durable OS fsync on the manifest file if it exists."""
        if self.manifest_file.exists():
            with open(self.manifest_file, "a+b") as f:
                f.flush()
                os.fsync(f.fileno())

    def append_manifest_entry(
        self,
        source_path: str,
        target_path: str,
        sha256: str,
        byte_size: int,
        filename: str,
        classification: str,
        operation_id: str,
        artifact_id: Optional[str] = None,
        committed_timestamp: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
        verify_physical_file: bool = True,
    ) -> ArchiveManifestEntry:
        """
        Serialized append of a verified archive record to archive_manifest.jsonl.
        Guarantees:
        - Process-local serialization (threading.RLock).
        - Exclusive maintenance lock ownership enforcement.
        - Strict physical target verification on disk.
        - Idempotent deduplication (matching provenance returns existing record).
        - Conflict detection (differing metadata raises MigrationIntegrityError).
        - Non-destructive malformed tail preservation with newline delimiter insertion.
        - Immediate durable flush and os.fsync.
        - Post-write verification.
        """
        self._assert_maintenance_ownership()

        with self._lock:
            self.archive_root.mkdir(parents=True, exist_ok=True)

            now_iso = committed_timestamp or datetime.now(timezone.utc).isoformat()
            src_p = Path(source_path)
            tgt_p = Path(target_path)
            art_id = artifact_id or src_p.stem

            # Verify physical file on disk before writing manifest record
            if verify_physical_file:
                self.verify_physical_target(
                    target_path=tgt_p,
                    expected_sha256=sha256,
                    expected_size=byte_size,
                    operation_id=operation_id,
                    artifact_id=art_id,
                )

            # Destination relative path calculation
            try:
                dest_rel = str(tgt_p.resolve().relative_to(self.data_dir.resolve())).replace("\\", "/")
            except ValueError:
                dest_rel = str(tgt_p).replace("\\", "/")

            src_rel = extract_source_relative_path(source_path)

            manifest_record_id = generate_manifest_record_id_v2(
                source_relative_path=src_rel,
                artifact_id=art_id,
            )

            # Scan existing records to check for duplicates or conflicts
            seen_records, tail_diag = self.scan_existing_records()

            # Prevent destination collisions with differing identities
            for seen_rec in seen_records.values():
                if seen_rec.destination_relative_path == dest_rel and seen_rec.manifest_record_id != manifest_record_id:
                    raise MigrationIntegrityError(
                        f"Destination collision: '{dest_rel}' is already registered under different manifest record '{seen_rec.manifest_record_id}'."
                    )

            if manifest_record_id in seen_records:
                existing = seen_records[manifest_record_id]

                # Check identity versioning: preserve V1 records, never silently reinterpret as V2
                if getattr(existing, "identity_version", 2) == 1:
                    raise MigrationIntegrityError(
                        f"Existing committed manifest record for artifact '{art_id}' uses legacy identity_version 1 ('{existing.manifest_record_id}'). "
                        "Silently reinterpreting or replacing V1 identity is prohibited; requires explicit operator review."
                    )

                # Different physical hash: fail closed
                if existing.physical_sha256 != sha256:
                    raise MigrationIntegrityError(
                        f"Physical SHA-256 mismatch for existing record '{manifest_record_id}': "
                        f"existing='{existing.physical_sha256}', attempted='{sha256}'."
                    )

                # Different destination path: fail closed and require explicit operator review
                if existing.destination_relative_path != dest_rel:
                    raise MigrationIntegrityError(
                        f"Different destination path for existing identity '{manifest_record_id}': "
                        f"existing='{existing.destination_relative_path}', attempted='{dest_rel}'. "
                        "Requires explicit operator review."
                    )

                # Different disposition: fail closed and require explicit reclassification review
                if existing.disposition != classification:
                    raise MigrationIntegrityError(
                        f"Different disposition for existing identity '{manifest_record_id}': "
                        f"existing='{existing.disposition}', attempted='{classification}'. "
                        "Requires explicit reclassification review."
                    )

                # Matching provenance and hash: idempotent no-op
                # Different operation_id with otherwise identical committed artifact: do not create duplicate
                if existing.operation_id == operation_id:
                    logger.info("Manifest record %s already present with exact matching metadata; idempotent no-op.", manifest_record_id)
                else:
                    logger.info(
                        "Manifest record %s already present under previous operation '%s' (current: '%s'); skipping duplicate creation.",
                        manifest_record_id,
                        existing.operation_id,
                        operation_id,
                    )
                self._sync_existing_file()
                return existing

            entry = ArchiveManifestEntry(
                manifest_record_id=manifest_record_id,
                identity_version=DEFAULT_IDENTITY_VERSION,
                source_namespace=DEFAULT_SOURCE_NAMESPACE,
                operation_id=operation_id,
                artifact_id=art_id,
                source_relative_path=src_rel,
                destination_relative_path=dest_rel,
                physical_sha256=sha256,
                size_bytes=byte_size,
                disposition=classification,
                committed_timestamp=now_iso,
                provenance=provenance or {},
                source_path=str(source_path),
                target_path=str(target_path),
                sha256=sha256,
                byte_size=byte_size,
                filename=filename,
                classification=classification,
                migrated_at=now_iso,
            )

            json_line = (entry.model_dump_json() + "\n").encode("utf-8")

            # Non-destructive handling: if trailing fragment existed without newline, prepend newline delimiter
            prefix = b""
            if self.manifest_file.exists() and self.manifest_file.stat().st_size > 0:
                with open(self.manifest_file, "rb") as f:
                    f.seek(max(0, self.manifest_file.stat().st_size - 1))
                    if f.read(1) != b"\n":
                        prefix = b"\n"

            # Serialized append, flush, and fsync
            with open(self.manifest_file, "ab") as f:
                if prefix:
                    f.write(prefix)
                f.write(json_line)
                f.flush()
                os.fsync(f.fileno())

            # Post-write verification: ensure newly appended record is recognized
            post_seen, _ = self.scan_existing_records()
            if manifest_record_id not in post_seen:
                raise MigrationRecoveryError(
                    f"Post-write verification failed: newly appended record '{manifest_record_id}' not found in '{self.manifest_file}'."
                )

            return entry

    def read_manifest_entries(self) -> List[ArchiveManifestEntry]:
        """Read and parse all valid entries from archive_manifest.jsonl under shared lock."""
        with self._lock:
            if not self.manifest_file.exists():
                return []

            entries: List[ArchiveManifestEntry] = []
            with open(self.manifest_file, "r", encoding="utf-8") as f:
                for idx, line in enumerate(f, 1):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        entries.append(ArchiveManifestEntry.model_validate_json(stripped))
                    except Exception as e:
                        logger.warning(
                            "Skipping invalid manifest record at line %d in %s: %s",
                            idx,
                            self.manifest_file,
                            e,
                        )
            return entries

    def backfill_from_committed_journal(
        self, conn: sqlite3.Connection, operation_id: Optional[str] = None
    ) -> List[ArchiveManifestEntry]:
        """
        Reconcile and backfill missing archive_manifest.jsonl entries from authoritative
        committed migration journal records.
        Enforces strict ownership, physical destination validation, and serialized post-write verification.
        """
        self._assert_maintenance_ownership()

        with self._lock:
            cursor = conn.cursor()

            # Query authoritative committed journal records
            if operation_id:
                cursor.execute(
                    """
                    SELECT id, operation_id, artifact_id, parent_folder, source_path,
                           target_path, sha256, byte_size, updated_at
                    FROM migration_journal
                    WHERE state = 'COMMITTED' AND operation_id = ?
                    ORDER BY sequence ASC;
                    """,
                    (operation_id,),
                )
            else:
                cursor.execute(
                    """
                    SELECT id, operation_id, artifact_id, parent_folder, source_path,
                           target_path, sha256, byte_size, updated_at
                    FROM migration_journal
                    WHERE state = 'COMMITTED'
                    ORDER BY sequence ASC;
                    """
                )

            rows = cursor.fetchall()
            seen_records, _ = self.scan_existing_records()
            backfilled: List[ArchiveManifestEntry] = []

            for row in rows:
                (
                    j_id,
                    op_id,
                    art_id,
                    p_folder,
                    src_path,
                    tgt_path,
                    sha,
                    size,
                    upd_at,
                ) = row

                target_p = Path(tgt_path)

                # Only archive records belong in archive_manifest.jsonl
                try:
                    target_p.resolve().relative_to(self.archive_root.resolve())
                except ValueError:
                    # Not in archive/ directory (e.g. active evidence in evidence/) -> skip
                    continue

                src_rel = extract_source_relative_path(src_path, parent_folder=p_folder)

                expected_rec_id = generate_manifest_record_id_v2(
                    source_relative_path=src_rel,
                    artifact_id=art_id,
                )

                # If record already exists in manifest, verify its physical target and metadata
                if expected_rec_id in seen_records:
                    existing = seen_records[expected_rec_id]
                    self.verify_physical_target(
                        target_path=target_p,
                        expected_sha256=sha,
                        expected_size=size,
                        operation_id=op_id,
                        artifact_id=art_id,
                    )
                    continue

                # Strict ownership & physical verification before backfill
                self.verify_physical_target(
                    target_path=target_p,
                    expected_sha256=sha,
                    expected_size=size,
                    operation_id=op_id,
                    artifact_id=art_id,
                )

                # Infer disposition based on target path
                if "malformed" in str(target_p):
                    disp = "MALFORMED_PRESERVE"
                elif "evidence" in str(target_p):
                    disp = "HISTORICAL_ARCHIVE"
                else:
                    disp = "LEGACY_TEST_ARCHIVE"

                entry = self.append_manifest_entry(
                    source_path=src_path,
                    target_path=tgt_path,
                    sha256=sha,
                    byte_size=size,
                    filename=target_p.name,
                    classification=disp,
                    operation_id=op_id,
                    artifact_id=art_id,
                    committed_timestamp=upd_at,
                    verify_physical_file=False,  # Already verified above
                )
                seen_records[entry.manifest_record_id] = entry
                backfilled.append(entry)

            return backfilled
