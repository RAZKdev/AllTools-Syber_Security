"""
Archive Backup Manager - Phase E3B.

Provides independent, cryptographically verified, non-destructive backup
and restore validation for the AllTools-CyberSec archive subsystem.
Backs up:
- archive/evidence/
- archive/tests/
- archive/tests/malformed/
- archive_manifest.jsonl
- provenance metadata

Enforces:
1. Physical storage independence verification (fails closed if on same physical SSD).
2. Streaming copy with bounded memory (64 KB buffer).
3. Simultaneous SHA-256 and byte-size verification.
4. Atomic staging and no-clobber publication.
5. Backup snapshot manifest and operation journal.
6. Interrupted backup recovery.
7. Restore validation in isolated temporary targets.
8. Strict source preservation (read-only access).
"""

import hashlib
import json
import logging
import os
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

STREAM_CHUNK_SIZE = 64 * 1024  # 64 KB streaming buffer


class ArchiveBackupError(Exception):
    """Base exception for archive backup subsystem errors."""
    pass


class PhysicalStorageIndependenceError(ArchiveBackupError):
    """Raised when backup target resides on the same physical storage device as the source."""
    pass


class ArchiveBackupCollisionError(ArchiveBackupError):
    """Raised when backup directory already exists."""
    pass


class ArchiveBackupIntegrityError(ArchiveBackupError):
    """Raised when backup artifact validation fails."""
    pass


class ArchiveRestoreError(ArchiveBackupError):
    """Raised when archive restore validation fails."""
    pass


class SourceEvidenceBackupError(ArchiveBackupError):
    """Base exception for source evidence pre-migration backup failures."""
    pass


class SourceEvidenceMissingError(SourceEvidenceBackupError):
    """Raised when an inventory file is missing on physical storage."""
    pass


class SourceEvidenceUnexpectedError(SourceEvidenceBackupError):
    """Raised when uninventoried files are detected in source storage."""
    pass


class SourceEvidenceContentMismatchError(SourceEvidenceBackupError, ArchiveBackupIntegrityError):
    """Raised when source file hash or size diverges from inventory or staged copy."""
    pass


class InsufficientDestinationSpaceError(SourceEvidenceBackupError):
    """Raised when destination device lacks sufficient free bytes."""
    pass


class ArchiveBackupFileEntry(BaseModel):
    """Metadata record for a backed-up archive file."""
    relative_path: str
    byte_size: int
    sha256: str
    source_disposition: Optional[str] = None


class ArchiveBackupManifest(BaseModel):
    """Immutable snapshot manifest for an archive backup."""
    backup_id: str
    created_at: str
    source_archive_root: str
    target_backup_dir: str
    source_disk_id: Optional[str] = None
    target_disk_id: Optional[str] = None
    is_physically_independent: bool
    total_files: int
    total_bytes: int
    manifest_records_count: int
    manifest_file_sha256: str
    files: List[ArchiveBackupFileEntry] = Field(default_factory=list)


class SourceBackupManifest(BaseModel):
    """Immutable snapshot manifest for pre-migration source evidence backup."""
    snapshot_id: str
    created_at: str
    source_evidence_root: str
    target_backup_dir: str
    source_disk_id: Optional[str] = None
    target_disk_id: Optional[str] = None
    is_physically_independent: bool
    inventory_sha256: str
    expected_files_count: int = 174
    total_files: int = 174
    total_bytes: int = 45724
    directories_count: int = 29
    files: List[ArchiveBackupFileEntry] = Field(default_factory=list)


def get_windows_volume_disk_id(drive_path: Path) -> Optional[str]:
    """
    Query the physical disk identifier (Disk Number and Serial Number)
    for a given Windows path using read-only PowerShell commands.
    """
    resolved = drive_path.resolve()
    drive_letter = resolved.drive.replace(":", "") if resolved.drive else ""
    if not drive_letter or os.name != "nt":
        return None

    try:
        cmd = f"(Get-Partition -DriveLetter '{drive_letter}' | Get-Disk | Select-Object -First 1 | ForEach-Object {{ \"$($_.Number):$($_.SerialNumber.Trim())\" }})"
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception as e:
        logger.warning("Could not query disk identity for drive %s: %s", drive_letter, e)
    return None


def verify_physical_device_independence(
    source_path: Path,
    target_path: Path,
    custom_disk_resolver: Optional[Callable[[Path], Optional[str]]] = None,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Verify whether source_path and target_path reside on physically independent storage devices.
    Returns (is_independent, source_disk_id, target_disk_id).
    """
    resolver = custom_disk_resolver or get_windows_volume_disk_id
    src_id = resolver(source_path)
    tgt_id = resolver(target_path)

    if src_id is None or tgt_id is None:
        # If we cannot resolve physical disk identities, default to conservative dependent
        return False, src_id, tgt_id

    is_independent = (src_id != tgt_id)
    return is_independent, src_id, tgt_id


class ArchiveBackupManager:
    """
    Dedicated manager for independent archive backup, journal tracking,
    interrupted backup recovery, and isolated restore validation.
    """

    def __init__(
        self,
        archive_root: Path,
        custom_disk_resolver: Optional[Callable[[Path], Optional[str]]] = None,
    ) -> None:
        self.archive_root = Path(archive_root).resolve()
        self.manifest_file = self.archive_root / "archive_manifest.jsonl"
        self.custom_disk_resolver = custom_disk_resolver

    @staticmethod
    def _compute_sha256_and_size(file_path: Path) -> Tuple[str, int]:
        hasher = hashlib.sha256()
        total_bytes = 0
        with open(file_path, "rb") as f:
            while chunk := f.read(STREAM_CHUNK_SIZE):
                hasher.update(chunk)
                total_bytes += len(chunk)
        return hasher.hexdigest(), total_bytes

    @classmethod
    def _stream_copy_with_hash(cls, src_path: Path, dest_path: Path) -> Tuple[str, int]:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        hasher = hashlib.sha256()
        total_bytes = 0
        with open(src_path, "rb") as src, open(dest_path, "wb") as dst:
            while chunk := src.read(STREAM_CHUNK_SIZE):
                hasher.update(chunk)
                dst.write(chunk)
                total_bytes += len(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        return hasher.hexdigest(), total_bytes

    def create_backup(
        self,
        target_backup_root: Path,
        generation_id: Optional[str] = None,
        require_physical_independence: bool = True,
    ) -> ArchiveBackupManifest:
        """
        Create a durable, verified, independent archive backup snapshot.
        Enforces physical device independence, bounded memory streaming copy,
        cryptographic hash verification, and atomic promotion.
        """
        if not self.archive_root.exists():
            raise ArchiveBackupError(f"Source archive directory '{self.archive_root}' does not exist.")

        target_root = Path(target_backup_root).resolve()
        target_root.mkdir(parents=True, exist_ok=True)

        # 1. Physical Device Independence Verification
        is_indep, src_disk, tgt_disk = verify_physical_device_independence(
            self.archive_root, target_root, self.custom_disk_resolver
        )
        if require_physical_independence and not is_indep:
            raise PhysicalStorageIndependenceError(
                f"NO-GO: Backup target '{target_root}' (Disk {tgt_disk}) resides on the same physical storage device "
                f"as the source archive '{self.archive_root}' (Disk {src_disk}). An independent physical storage device is required."
            )

        # 2. Generation Identifier & Staging Setup
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        gen_id = generation_id or f"ABKP-{timestamp_str}-{uuid.uuid4().hex[:6]}"
        final_backup_dir = target_root / gen_id

        if final_backup_dir.exists():
            raise ArchiveBackupCollisionError(f"Archive backup directory already exists: '{final_backup_dir}'")

        staging_dir = target_root / ".staging" / f"{gen_id}_{uuid.uuid4().hex[:8]}"
        staging_dir.mkdir(parents=True, exist_ok=True)

        journal_file = target_root / "archive_backup_journal.jsonl"

        # Record INITIATED in operation journal
        self._append_journal_entry(journal_file, gen_id, "INITIATED", {
            "source": str(self.archive_root),
            "target": str(final_backup_dir),
            "is_physically_independent": is_indep,
        })

        try:
            # 3. Discover all archive files
            archive_files = []
            for root, _, filenames in os.walk(self.archive_root):
                for fn in sorted(filenames):
                    p = Path(root) / fn
                    if ".staging" not in p.parts:
                        archive_files.append(p)

            backed_up_entries: List[ArchiveBackupFileEntry] = []
            total_copied_bytes = 0

            # 4. Stream-copy and verify each file into staging
            for src_p in archive_files:
                rel_p = src_p.relative_to(self.archive_root).as_posix()
                staged_dest = staging_dir / rel_p

                # Compute source hash and size
                src_sha, src_size = self._compute_sha256_and_size(src_p)

                # Stream copy with hash computation
                dst_sha, dst_size = self._stream_copy_with_hash(src_p, staged_dest)

                # Cryptographic and size verification
                if src_sha != dst_sha or src_size != dst_size:
                    raise ArchiveBackupIntegrityError(
                        f"Integrity check failed for '{rel_p}': src={src_sha} ({src_size}B), dst={dst_sha} ({dst_size}B)"
                    )

                backed_up_entries.append(ArchiveBackupFileEntry(
                    relative_path=rel_p,
                    byte_size=dst_size,
                    sha256=dst_sha,
                ))
                total_copied_bytes += dst_size

            # 5. Manifest file verification
            manifest_records_count = 0
            manifest_sha256 = ""
            if self.manifest_file.exists():
                manifest_sha256, _ = self._compute_sha256_and_size(self.manifest_file)
                # Count valid jsonl lines
                with open(self.manifest_file, "r", encoding="utf-8") as mf:
                    for line in mf:
                        if line.strip():
                            manifest_records_count += 1

            # 6. Generate and write ArchiveBackupManifest
            backup_manifest = ArchiveBackupManifest(
                backup_id=gen_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                source_archive_root=str(self.archive_root),
                target_backup_dir=str(final_backup_dir),
                source_disk_id=src_disk,
                target_disk_id=tgt_disk,
                is_physically_independent=is_indep,
                total_files=len(backed_up_entries),
                total_bytes=total_copied_bytes,
                manifest_records_count=manifest_records_count,
                manifest_file_sha256=manifest_sha256,
                files=backed_up_entries,
            )

            manifest_out = staging_dir / "archive_backup_manifest.json"
            manifest_json = backup_manifest.model_dump_json(indent=2)
            manifest_out.write_text(manifest_json, encoding="utf-8")

            # 7. Atomic Promotion to final directory
            os.replace(str(staging_dir), str(final_backup_dir))

            # Record COMMITTED in journal
            self._append_journal_entry(journal_file, gen_id, "COMMITTED", {
                "total_files": len(backed_up_entries),
                "total_bytes": total_copied_bytes,
            })

            return backup_manifest

        except Exception as e:
            # Clean up staging directory on failure
            shutil.rmtree(staging_dir, ignore_errors=True)
            self._append_journal_entry(journal_file, gen_id, "FAILED", {"error": str(e)})
            raise

    def recover_interrupted_backup(self, target_backup_root: Path) -> List[Path]:
        """
        Recover from interrupted backups by removing abandoned .staging directories
        and logging recovery events to the backup journal.
        """
        target_root = Path(target_backup_root).resolve()
        staging_root = target_root / ".staging"
        cleaned: List[Path] = []
        if staging_root.exists():
            for item in staging_root.iterdir():
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                    cleaned.append(item)
        if cleaned:
            journal_file = target_root / "archive_backup_journal.jsonl"
            self._append_journal_entry(journal_file, "RECOVERY", "STAGING_PURGED", {
                "cleaned_directories": [str(c) for c in cleaned]
            })
        return cleaned

    @staticmethod
    def _resolve_manifest_member(base_dir: Path, relative_path: str) -> Path:
        """
        Resolve a manifest relative_path inside base_dir and reject traversal.

        Manifests are untrusted input during restore. Absolute paths, drive
        prefixes, dot-only components, and any resolved path outside base_dir
        are rejected before reading or writing anything.
        """
        normalized = str(relative_path).replace("\\", "/")
        if not normalized:
            raise ArchiveRestoreError("Unsafe manifest relative path: empty path is prohibited.")

        pure = PurePosixPath(normalized)
        if pure.is_absolute() or pure.anchor:
            raise ArchiveRestoreError(
                f"Unsafe manifest relative path '{relative_path}': absolute paths are prohibited."
            )
        if len(pure.parts) > 0 and len(pure.parts[0]) == 2 and pure.parts[0][1] == ":":
            raise ArchiveRestoreError(
                f"Unsafe manifest relative path '{relative_path}': drive prefixes are prohibited."
            )
        if any(part in ("", ".", "..") for part in pure.parts):
            raise ArchiveRestoreError(
                f"Unsafe manifest relative path '{relative_path}': path traversal is prohibited."
            )

        resolved_base = Path(base_dir).resolve()
        candidate = (resolved_base / normalized).resolve()
        if candidate == resolved_base:
            raise ArchiveRestoreError(
                f"Unsafe manifest relative path '{relative_path}': path must name a file."
            )
        try:
            candidate.relative_to(resolved_base)
        except ValueError as exc:
            raise ArchiveRestoreError(
                f"Unsafe manifest relative path '{relative_path}': path escapes '{resolved_base}'."
            ) from exc
        return candidate

    def validate_and_restore(
        self,
        backup_dir: Path,
        target_restore_dir: Path,
    ) -> Dict[str, Any]:
        """
        Validate an archive backup against its manifest and restore all files
        into an isolated target directory, verifying byte-for-byte fidelity.
        """
        b_dir = Path(backup_dir).resolve()
        manifest_p = b_dir / "archive_backup_manifest.json"
        if not manifest_p.exists():
            raise ArchiveRestoreError(f"Missing archive_backup_manifest.json in '{b_dir}'.")

        manifest_data = json.loads(manifest_p.read_text(encoding="utf-8"))
        manifest = ArchiveBackupManifest.model_validate(manifest_data)

        dest_restore = Path(target_restore_dir).resolve()
        dest_restore.mkdir(parents=True, exist_ok=True)

        verified_files = 0
        restored_files = 0
        restored_bytes = 0

        # Validate every manifest member against both roots before touching files.
        validated_members = [
            (
                entry,
                self._resolve_manifest_member(b_dir, entry.relative_path),
                self._resolve_manifest_member(dest_restore, entry.relative_path),
            )
            for entry in manifest.files
        ]

        # Step 1: Pre-restore verification of backup files
        for entry, b_file, _ in validated_members:
            if not b_file.exists():
                raise ArchiveRestoreError(f"Backup file missing: '{entry.relative_path}'")
            actual_sha, actual_size = self._compute_sha256_and_size(b_file)
            if actual_sha != entry.sha256 or actual_size != entry.byte_size:
                raise ArchiveRestoreError(
                    f"Backup corruption detected for '{entry.relative_path}': expected {entry.sha256}, got {actual_sha}"
                )
            verified_files += 1

        # Step 2: Restore files into destination
        for entry, b_file, r_file in validated_members:
            r_file.parent.mkdir(parents=True, exist_ok=True)

            dst_sha, dst_size = self._stream_copy_with_hash(b_file, r_file)
            if dst_sha != entry.sha256 or dst_size != entry.byte_size:
                raise ArchiveRestoreError(
                    f"Restore verification failed for '{entry.relative_path}': hash mismatch"
                )
            restored_files += 1
            restored_bytes += dst_size

        return {
            "backup_id": manifest.backup_id,
            "verified_files": verified_files,
            "restored_files": restored_files,
            "restored_bytes": restored_bytes,
            "restore_destination": str(dest_restore),
            "status": "RESTORE_VERIFIED_SUCCESS",
        }

    def create_source_evidence_backup(
        self,
        source_evidence_root: Path,
        inventory_file: Path,
        target_backup_root: Path,
        generation_id: Optional[str] = None,
        require_physical_independence: bool = True,
        expected_inventory_sha256: Optional[str] = None,
        expected_files_count: int = 174,
        expected_total_bytes: Optional[int] = 45724,
        expected_directories_count: Optional[int] = 29,
        min_free_bytes_margin: int = 10 * 1024 * 1024,
        simulate_insufficient_space: bool = False,
        fault_injector: Optional[Callable[[str], None]] = None,
    ) -> SourceBackupManifest:
        """
        Create a durable, verified pre-migration backup of the source evidence directory.
        Protects the entire baseline inventory (174 files, 29 directories, 45,724 bytes)
        with physical independence checks, bounded streaming copy, hash verification,
        and atomic promotion.
        """
        src_root = Path(source_evidence_root).resolve()
        if not src_root.exists():
            raise SourceEvidenceMissingError(f"Source evidence directory '{src_root}' does not exist.")

        inv_path = Path(inventory_file).resolve()
        if not inv_path.exists():
            raise SourceEvidenceMissingError(f"Inventory file '{inv_path}' does not exist.")

        target_root = Path(target_backup_root).resolve()
        target_root.mkdir(parents=True, exist_ok=True)

        # 1. Physical Device Independence Verification
        is_indep, src_disk, tgt_disk = verify_physical_device_independence(
            src_root, target_root, self.custom_disk_resolver
        )
        if require_physical_independence and not is_indep:
            raise PhysicalStorageIndependenceError(
                f"NO-GO: Backup target '{target_root}' (Disk {tgt_disk}) resides on the same physical storage device "
                f"as the source evidence root '{src_root}' (Disk {src_disk}). An independent physical storage device is required."
            )

        # 2. Inventory Hash Verification
        inv_bytes = inv_path.read_bytes()
        actual_inv_sha = hashlib.sha256(inv_bytes).hexdigest()
        if expected_inventory_sha256 and actual_inv_sha.lower() != expected_inventory_sha256.lower():
            raise SourceEvidenceContentMismatchError(
                f"Inventory SHA-256 mismatch: expected {expected_inventory_sha256}, got {actual_inv_sha}"
            )

        try:
            inv_data = json.loads(inv_bytes.decode("utf-8"))
        except Exception as e:
            raise SourceEvidenceContentMismatchError(f"Invalid inventory JSON: {e}")

        items = inv_data.get("inventory") if isinstance(inv_data, dict) else None
        if items is None and isinstance(inv_data, list):
            items = inv_data
        if items is None:
            raise SourceEvidenceContentMismatchError("Inventory format unrecognized: missing 'inventory' list.")

        if len(items) != expected_files_count:
            raise SourceEvidenceMissingError(
                f"Inventory items count mismatch: expected {expected_files_count}, found {len(items)}"
            )

        # 3. Source Filesystem Audit against Inventory and Reparse-Point Guard
        actual_files_map: Dict[str, Path] = {}
        dirs_set = set()
        for root, dirs, files in os.walk(src_root):
            for d in dirs:
                d_p = Path(root) / d
                if os.path.islink(d_p) or d_p.is_symlink():
                    raise SourceEvidenceUnexpectedError(f"Reparse point or symlink directory rejected: '{d_p}'")
                dirs_set.add(d_p.resolve())
            for f in files:
                p = (Path(root) / f).resolve()
                if os.path.islink(p) or p.is_symlink():
                    raise SourceEvidenceUnexpectedError(f"Reparse point or symlink file rejected: '{p}'")
                if p.name == "legacy-evidence-inventory.json":
                    continue
                rel = p.relative_to(src_root).as_posix()
                actual_files_map[rel] = p

        if expected_directories_count is not None and len(dirs_set) != expected_directories_count:
            logger.warning("Discovered %d directories, expected %d", len(dirs_set), expected_directories_count)

        inv_map = {}
        for item in items:
            rel = (item.get("source_relative_path") or item.get("rel_path") or "").replace("\\", "/")
            inv_map[rel] = item

        missing = set(inv_map.keys()) - set(actual_files_map.keys())
        if missing:
            raise SourceEvidenceMissingError(f"Missing {len(missing)} inventory files on disk: {sorted(list(missing))[:3]}")

        unexpected = set(actual_files_map.keys()) - set(inv_map.keys())
        if unexpected:
            raise SourceEvidenceUnexpectedError(f"Found {len(unexpected)} uninventoried files on disk: {sorted(list(unexpected))[:3]}")

        total_src_bytes = 0
        for rel, item in inv_map.items():
            act_p = actual_files_map[rel]
            act_size = act_p.stat().st_size
            exp_size = item.get("byte_size") if "byte_size" in item else item.get("size_bytes")
            if exp_size is not None and act_size != exp_size:
                raise SourceEvidenceContentMismatchError(
                    f"File size mismatch for '{rel}': expected {exp_size}, got {act_size}"
                )
            act_sha, _ = self._compute_sha256_and_size(act_p)
            exp_sha = item.get("sha256") if "sha256" in item else item.get("physical_sha256")
            if exp_sha is not None and act_sha.lower() != exp_sha.lower():
                raise SourceEvidenceContentMismatchError(
                    f"File SHA-256 mismatch for '{rel}': expected {exp_sha}, got {act_sha}"
                )
            total_src_bytes += act_size

        if expected_total_bytes is not None and total_src_bytes != expected_total_bytes:
            raise SourceEvidenceContentMismatchError(
                f"Total source bytes mismatch: expected {expected_total_bytes}, got {total_src_bytes}"
            )

        # 4. Pre-flight Disk Space Verification
        try:
            usage = shutil.disk_usage(target_root)
            free_bytes = usage.free
        except Exception:
            free_bytes = 100 * 1024 * 1024

        required_bytes = total_src_bytes + min_free_bytes_margin
        if simulate_insufficient_space or free_bytes < required_bytes:
            raise InsufficientDestinationSpaceError(
                f"Insufficient destination disk space: required {required_bytes} bytes (including margin), free {free_bytes} bytes."
            )

        # 5. Staging Setup & Journal
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        gen_id = generation_id or f"SEBKP-{timestamp_str}-{uuid.uuid4().hex[:6]}"
        final_backup_dir = target_root / gen_id

        if final_backup_dir.exists():
            raise ArchiveBackupCollisionError(f"Source evidence backup directory already exists: '{final_backup_dir}'")

        staging_dir = target_root / ".staging" / f"{gen_id}_{uuid.uuid4().hex[:8]}"
        staging_dir.mkdir(parents=True, exist_ok=True)
        journal_file = target_root / "source_backup_journal.jsonl"

        self._append_journal_entry(journal_file, gen_id, "INITIATED", {
            "source_evidence_root": str(src_root),
            "target": str(final_backup_dir),
            "inventory_sha256": actual_inv_sha,
            "total_files": len(inv_map),
            "total_bytes": total_src_bytes,
        })

        try:
            if fault_injector:
                fault_injector("before_copy")

            backed_up_entries: List[ArchiveBackupFileEntry] = []
            copied_bytes = 0

            # 6. Stream Copy with Dual Hashing
            for rel, item in sorted(inv_map.items()):
                src_p = actual_files_map[rel]
                staged_dest = staging_dir / rel

                dst_sha, dst_size = self._stream_copy_with_hash(src_p, staged_dest)

                exp_sha = item.get("sha256") if "sha256" in item else item.get("physical_sha256")
                if exp_sha and dst_sha.lower() != exp_sha.lower():
                    raise SourceEvidenceContentMismatchError(
                        f"Staged copy hash mismatch: source file '{rel}' was mutated or corrupted during copy! Expected {exp_sha}, got {dst_sha}"
                    )
                exp_size = item.get("byte_size") if "byte_size" in item else item.get("size_bytes")
                if exp_size is not None and dst_size != exp_size:
                    raise SourceEvidenceContentMismatchError(
                        f"Staged copy size mismatch: source file '{rel}' size changed during copy! Expected {exp_size}, got {dst_size}"
                    )

                backed_up_entries.append(ArchiveBackupFileEntry(
                    relative_path=rel,
                    byte_size=dst_size,
                    sha256=dst_sha,
                    source_disposition=item.get("disposition"),
                ))
                copied_bytes += dst_size

                if fault_injector:
                    fault_injector(f"copied_{rel}")

            if fault_injector:
                fault_injector("after_copy")

            # Post-copy source audit: verify no files added or removed during copy
            post_files = []
            for root, _, files in os.walk(src_root):
                for f in files:
                    if f != "legacy-evidence-inventory.json":
                        post_files.append((Path(root) / f).relative_to(src_root).as_posix())
            if len(post_files) != len(inv_map) or set(post_files) != set(inv_map.keys()):
                raise SourceEvidenceUnexpectedError("Source filesystem was modified concurrently during backup!")

            # 7. Write SourceBackupManifest
            manifest = SourceBackupManifest(
                snapshot_id=gen_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                source_evidence_root=str(src_root),
                target_backup_dir=str(final_backup_dir),
                source_disk_id=src_disk,
                target_disk_id=tgt_disk,
                is_physically_independent=is_indep,
                inventory_sha256=actual_inv_sha,
                expected_files_count=expected_files_count,
                total_files=len(backed_up_entries),
                total_bytes=copied_bytes,
                directories_count=len(dirs_set),
                files=backed_up_entries,
            )

            manifest_out = staging_dir / "source_backup_manifest.json"
            manifest_out.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")

            if fault_injector:
                fault_injector("before_promotion")

            # 8. Atomic Directory Promotion
            os.replace(str(staging_dir), str(final_backup_dir))

            # Clean up empty .staging directory if no other staging tasks remain
            try:
                staging_parent = target_root / ".staging"
                if staging_parent.exists() and not any(staging_parent.iterdir()):
                    staging_parent.rmdir()
            except Exception:
                pass

            self._append_journal_entry(journal_file, gen_id, "COMMITTED", {
                "total_files": len(backed_up_entries),
                "total_bytes": copied_bytes,
                "snapshot_id": gen_id,
            })

            return manifest

        except Exception as e:
            shutil.rmtree(staging_dir, ignore_errors=True)
            self._append_journal_entry(journal_file, gen_id, "FAILED", {"error": str(e)})
            raise

    def validate_and_restore_source_backup(
        self,
        backup_dir: Path,
        target_restore_dir: Path,
    ) -> Dict[str, Any]:
        """
        Validate a pre-migration source backup against source_backup_manifest.json
        and restore all files into an isolated directory, verifying byte-for-byte fidelity.
        """
        b_dir = Path(backup_dir).resolve()
        manifest_p = b_dir / "source_backup_manifest.json"
        if not manifest_p.exists():
            raise ArchiveRestoreError(f"Missing source_backup_manifest.json in '{b_dir}'.")

        manifest_data = json.loads(manifest_p.read_text(encoding="utf-8"))
        manifest = SourceBackupManifest.model_validate(manifest_data)

        dest_restore = Path(target_restore_dir).resolve()
        dest_restore.mkdir(parents=True, exist_ok=True)

        verified_files = 0
        restored_files = 0
        restored_bytes = 0

        # Validate every manifest member against both roots before touching files.
        validated_members = [
            (
                entry,
                self._resolve_manifest_member(b_dir, entry.relative_path),
                self._resolve_manifest_member(dest_restore, entry.relative_path),
            )
            for entry in manifest.files
        ]

        # Pre-restore verification
        for entry, b_file, _ in validated_members:
            if not b_file.exists():
                raise ArchiveRestoreError(f"Backup file missing: '{entry.relative_path}'")
            act_sha, act_size = self._compute_sha256_and_size(b_file)
            if act_sha != entry.sha256 or act_size != entry.byte_size:
                raise ArchiveRestoreError(
                    f"Backup corruption detected for '{entry.relative_path}': expected {entry.sha256}, got {act_sha}"
                )
            verified_files += 1

        # Restore
        for entry, b_file, r_file in validated_members:
            r_file.parent.mkdir(parents=True, exist_ok=True)
            dst_sha, dst_size = self._stream_copy_with_hash(b_file, r_file)
            if dst_sha != entry.sha256 or dst_size != entry.byte_size:
                raise ArchiveRestoreError(f"Restore verification failed for '{entry.relative_path}'")
            restored_files += 1
            restored_bytes += dst_size

        return {
            "snapshot_id": manifest.snapshot_id,
            "inventory_sha256": manifest.inventory_sha256,
            "verified_files": verified_files,
            "restored_files": restored_files,
            "restored_bytes": restored_bytes,
            "restore_destination": str(dest_restore),
            "status": "RESTORE_VERIFIED_SUCCESS",
        }

    @staticmethod
    def _append_journal_entry(
        journal_file: Path,
        backup_id: str,
        state: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        journal_file.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "backup_id": backup_id,
            "state": state,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
        }
        with open(journal_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
