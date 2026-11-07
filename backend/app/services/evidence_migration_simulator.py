"""
Evidence Migration Simulator - Phase E2 Read-Only Simulation Engine.

Strictly read-only: performs zero filesystem writes, copies, moves, deletions,
renames, or database mutations. Evaluates all legacy evidence files against
baseline inventory, validates physical file integrity, checks SQLite relational
constraints, computes proposed destination paths, identifies collisions,
and calculates volume capacity requirements.
"""

import ctypes
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from app.services.evidence_migration_models import (
    ArtifactSimulationResult,
    CollisionStatus,
    DatabaseValidationResult,
    DestinationStatus,
    PrimaryDisposition,
    SimulationDecision,
    SimulationSummaryReport,
    VolumeCapacityAnalysis,
)

logger = logging.getLogger(__name__)

CHUNK_SIZE = 64 * 1024  # 64 KB streaming buffer for bounded memory hashing
MINIMUM_SAFETY_BUFFER_BYTES = 500 * 1024 * 1024  # 500 MB minimum buffer


class SimulationSafetyError(Exception):
    """Raised when an operation would violate read-only safety invariants."""
    pass


class EvidenceMigrationSimulator:
    """
    Read-only evidence migration simulator.
    Evaluates 100% of legacy evidence artifacts with zero production mutation.
    """

    def __init__(
        self,
        source_evidence_dir: Path,
        inventory_file: Path,
        dest_data_dir: Path,
        db_path: Path,
        expected_artifact_count: int = 174,
    ) -> None:
        self.source_evidence_dir = source_evidence_dir.resolve()
        self.inventory_file = inventory_file.resolve()
        self.dest_data_dir = dest_data_dir.resolve()
        self.db_path = db_path.resolve()
        self.expected_artifact_count = expected_artifact_count

        if not self.source_evidence_dir.exists():
            raise FileNotFoundError(f"Source evidence directory does not exist: {self.source_evidence_dir}")
        if not self.inventory_file.exists():
            raise FileNotFoundError(f"Inventory file does not exist: {self.inventory_file}")

    @staticmethod
    def _sanitize_path_segment(segment: str) -> str:
        """Strip illegal path traversal tokens and dangerous characters."""
        cleaned = re.sub(r"[^a-zA-Z0-9_\-.]", "_", segment)
        return cleaned or "unknown"

    @staticmethod
    def normalize_rel_path(p: str) -> str:
        """Normalize path separators to forward slashes for deterministic comparison."""
        return p.replace("\\", "/").strip("/")

    @staticmethod
    def is_reparse_point_or_symlink(path: Path) -> bool:
        """Check if path is a symlink or Windows reparse point."""
        if path.is_symlink():
            return True
        try:
            st = path.lstat()
            file_attrs = getattr(st, "st_file_attributes", 0)
            if file_attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                return True
        except Exception:
            pass
        return False

    def validate_inventory(self) -> Tuple[List[Dict[str, Any]], str]:
        """
        Load and validate immutable baseline inventory JSON.
        Computes SHA-256 of the inventory file itself and asserts schema integrity.
        """
        with open(self.inventory_file, "rb") as f:
            raw_bytes = f.read()

        inventory_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        try:
            records = json.loads(raw_bytes.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Failed to parse inventory JSON at '{self.inventory_file}': {str(e)}") from e

        if not isinstance(records, list):
            if isinstance(records, dict) and "artifacts" in records:
                records = records["artifacts"]
            else:
                raise ValueError(f"Inventory JSON root must be a list of artifact records, got {type(records)}")

        if len(records) != self.expected_artifact_count:
            raise ValueError(
                f"Inventory count mismatch: expected {self.expected_artifact_count}, found {len(records)}"
            )

        seen_paths: Set[str] = set()
        for rec in records:
            rel_p = self.normalize_rel_path(rec.get("rel_path", ""))
            if not rel_p:
                raise ValueError("Inventory artifact record missing rel_path")
            norm_key = rel_p.lower()
            if norm_key in seen_paths:
                raise ValueError(f"Duplicate relative path detected in inventory: {rel_p}")
            seen_paths.add(norm_key)

            if "primary_disposition" not in rec:
                raise ValueError(f"Artifact '{rel_p}' missing primary_disposition")
            if "sha256" not in rec:
                raise ValueError(f"Artifact '{rel_p}' missing sha256")
            if "byte_size" not in rec:
                raise ValueError(f"Artifact '{rel_p}' missing byte_size")

        return records, inventory_sha256

    def scan_source_filesystem(self) -> Tuple[Dict[str, Path], List[str]]:
        """
        Recursively scan source evidence directory rejecting reparse points and traversal.
        Returns a dict of normalized relative path -> canonical Path and a list of path traversal rejections.
        """
        found_files: Dict[str, Path] = {}
        traversal_errors: List[str] = []

        for root, dirs, files in os.walk(self.source_evidence_dir, followlinks=False):
            root_path = Path(root)
            if self.is_reparse_point_or_symlink(root_path):
                traversal_errors.append(f"Skipping reparse point / symlink directory: {root_path}")
                dirs.clear()
                continue

            for file_name in files:
                file_path = root_path / file_name
                if self.is_reparse_point_or_symlink(file_path):
                    traversal_errors.append(f"Skipping reparse point / symlink file: {file_path}")
                    continue

                try:
                    canonical_file = file_path.resolve()
                    # Ensure path does not escape source root
                    if not str(canonical_file).startswith(str(self.source_evidence_dir)):
                        traversal_errors.append(f"Path traversal detected: {canonical_file}")
                        continue

                    rel_p = self.normalize_rel_path(str(canonical_file.relative_to(self.source_evidence_dir)))
                    norm_key = rel_p.lower()
                    if norm_key in found_files:
                        traversal_errors.append(f"Case-insensitive duplicate physical file detected: {rel_p}")
                    found_files[norm_key] = canonical_file
                except Exception as e:
                    traversal_errors.append(f"Error resolving file '{file_path}': {str(e)}")

        return found_files, traversal_errors

    def hash_and_verify_physical_file(
        self, file_path: Path
    ) -> Tuple[int, str, bool, str, Dict[str, Any]]:
        """
        Stream file content in 64 KB chunks to compute SHA-256 with pre/post mtime stability checks.
        Parses JSON if possible and returns (size, sha256, is_stable, mtime_iso, json_info).
        """
        pre_stat = file_path.stat()
        pre_mtime_ns = pre_stat.st_mtime_ns
        pre_size = pre_stat.st_size

        hasher = hashlib.sha256()
        total_read = 0

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
                total_read += len(chunk)

        post_stat = file_path.stat()
        post_mtime_ns = post_stat.st_mtime_ns
        post_size = post_stat.st_size

        is_stable = (pre_mtime_ns == post_mtime_ns) and (pre_size == post_size) and (total_read == pre_size)
        file_sha256 = hasher.hexdigest()
        mtime_iso = datetime.fromtimestamp(post_stat.st_mtime, tz=timezone.utc).isoformat()

        # Parse JSON structure
        json_info: Dict[str, Any] = {
            "is_valid_json": False,
            "is_evidence_schema": False,
            "embedded_id": None,
            "assessment_id": None,
            "finding_id": None,
            "parse_error": None,
        }

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = json.load(f)
            json_info["is_valid_json"] = True
            if isinstance(content, dict):
                json_info["embedded_id"] = content.get("id")
                json_info["assessment_id"] = content.get("assessmentId") or content.get("assessment_id")
                json_info["finding_id"] = content.get("findingId") or content.get("finding_id")
                # Minimal evidence schema heuristic
                if "type" in content and "source" in content and "capturedAt" in content:
                    json_info["is_evidence_schema"] = True
            else:
                json_info["parse_error"] = f"JSON root is {type(content).__name__}, expected object"
        except Exception as e:
            json_info["parse_error"] = str(e)

        return total_read, file_sha256, is_stable, mtime_iso, json_info

    def validate_sqlite_database(
        self,
        candidate_assessment_id: str = "ASM-001",
        candidate_finding_id: str = "FND-ff03d7e4",
    ) -> DatabaseValidationResult:
        """
        Perform strictly read-only validation of the production SQLite database.
        Uses URI mode=ro and PRAGMA query_only = ON.
        """
        if not self.db_path.exists():
            return DatabaseValidationResult(
                db_path=str(self.db_path),
                db_size_bytes=0,
                db_sha256="FILE_NOT_FOUND",
                user_version=-1,
                schema_version_count=0,
                engagements_count=0,
                assessments_count=0,
                findings_count=0,
                check_executions_count=0,
                evidence_count=0,
                quarantine_items_count=0,
                migration_journal_exists=False,
                active_candidate_parents_exist=False,
                missing_parent_details={"error": "Database file does not exist"},
            )

        with open(self.db_path, "rb") as f:
            db_bytes = f.read()
        db_sha256 = hashlib.sha256(db_bytes).hexdigest()
        db_size = len(db_bytes)

        # Open in read-only mode via URI
        uri = f"file:{self.db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA query_only = ON;")
            cursor.execute("PRAGMA user_version;")
            user_version = cursor.fetchone()[0]

            def get_count(table_name: str) -> int:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table_name};")
                    return cursor.fetchone()[0]
                except sqlite3.OperationalError:
                    return 0

            schema_version_count = get_count("schema_version")
            engagements_count = get_count("engagements")
            assessments_count = get_count("assessments")
            findings_count = get_count("findings")
            check_executions_count = get_count("check_executions")
            evidence_count = get_count("evidence")
            quarantine_items_count = get_count("quarantine_items")

            # Check migration_journal table
            cursor.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='migration_journal';"
            )
            migration_journal_exists = cursor.fetchone()[0] > 0

            # Active candidate parent check
            cursor.execute("SELECT COUNT(*) FROM assessments WHERE id = ?;", (candidate_assessment_id,))
            asm_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM findings WHERE id = ?;", (candidate_finding_id,))
            fnd_count = cursor.fetchone()[0]

            active_candidate_parents_exist = (
                (asm_count > 0) and (fnd_count > 0) and (engagements_count > 0)
            )

            missing_parent_details = {
                "assessment_id": candidate_assessment_id,
                "assessment_exists": asm_count > 0,
                "finding_id": candidate_finding_id,
                "finding_exists": fnd_count > 0,
                "engagements_count": engagements_count,
            }

            return DatabaseValidationResult(
                db_path=str(self.db_path),
                db_size_bytes=db_size,
                db_sha256=db_sha256,
                user_version=user_version,
                schema_version_count=schema_version_count,
                engagements_count=engagements_count,
                assessments_count=assessments_count,
                findings_count=findings_count,
                check_executions_count=check_executions_count,
                evidence_count=evidence_count,
                quarantine_items_count=quarantine_items_count,
                migration_journal_exists=migration_journal_exists,
                active_candidate_parents_exist=active_candidate_parents_exist,
                missing_parent_details=missing_parent_details,
            )
        finally:
            conn.close()

    def simulate_destination_and_collision(
        self, inv_record: Dict[str, Any], source_sha256: str
    ) -> Tuple[Path, DestinationStatus, CollisionStatus]:
        """
        Simulate target destination path and evaluate collision status without mutating filesystem.
        """
        rel_p = self.normalize_rel_path(inv_record["rel_path"])
        primary_disp = inv_record.get("primary_disposition", "")
        parts = rel_p.split("/")
        filename = parts[-1]
        folder = parts[0] if len(parts) > 1 else ""

        safe_filename = self._sanitize_path_segment(filename)
        safe_folder = self._sanitize_path_segment(folder)

        if primary_disp == PrimaryDisposition.ACTIVE_MIGRATION_CANDIDATE.value:
            # Active candidate maps to evidence/<safe_assessment_id>/<safe_filename>
            assessment_id = self._sanitize_path_segment(inv_record.get("assessment_id") or safe_folder)
            dest_path = self.dest_data_dir / "evidence" / assessment_id / safe_filename
        elif primary_disp == PrimaryDisposition.HISTORICAL_ARCHIVE.value:
            dest_path = self.dest_data_dir / "archive" / "evidence" / safe_folder / safe_filename
        elif primary_disp == PrimaryDisposition.MALFORMED_PRESERVE.value:
            dest_path = self.dest_data_dir / "archive" / "tests" / "malformed" / safe_folder / safe_filename
        else:
            # LEGACY_TEST_ARCHIVE
            dest_path = self.dest_data_dir / "archive" / "tests" / safe_folder / safe_filename

        # Strictly read-only inspection of destination existence
        if not dest_path.exists():
            return dest_path, DestinationStatus.DESTINATION_ABSENT, CollisionStatus.NO_COLLISION

        # If it exists on disk, check whether it is a collision
        try:
            with open(dest_path, "rb") as df:
                dest_bytes = df.read()
            dest_sha = hashlib.sha256(dest_bytes).hexdigest()
            if dest_sha == source_sha256:
                return (
                    dest_path,
                    DestinationStatus.EXISTING_IDENTICAL_UNOWNED,
                    CollisionStatus.IDENTICAL_HASH_COLLISION,
                )
            else:
                return (
                    dest_path,
                    DestinationStatus.EXISTING_DIFFERENT_HASH,
                    CollisionStatus.HASH_MISMATCH_COLLISION,
                )
        except Exception:
            return (
                dest_path,
                DestinationStatus.DESTINATION_PATH_UNVERIFIABLE,
                CollisionStatus.NO_COLLISION,
            )

    def analyze_volume_and_capacity(
        self, total_source_bytes: int, category_bytes: Dict[str, int]
    ) -> VolumeCapacityAnalysis:
        """
        Analyze volume identity and free capacity using read-only Windows APIs.
        """
        def get_vol_info(p: Path) -> Tuple[str, Optional[str]]:
            drive = os.path.splitdrive(str(p.resolve()))[0] + "\\"
            vol_name_buf = ctypes.create_unicode_buffer(1024)
            fs_name_buf = ctypes.create_unicode_buffer(1024)
            serial_number = ctypes.c_ulong()
            max_comp_len = ctypes.c_ulong()
            file_system_flags = ctypes.c_ulong()

            try:
                success = ctypes.windll.kernel32.GetVolumeInformationW(
                    ctypes.c_wchar_p(drive),
                    vol_name_buf,
                    ctypes.sizeof(vol_name_buf),
                    ctypes.byref(serial_number),
                    ctypes.byref(max_comp_len),
                    ctypes.byref(file_system_flags),
                    fs_name_buf,
                    ctypes.sizeof(fs_name_buf),
                )
                if success:
                    return drive, hex(serial_number.value)
            except Exception:
                pass
            return drive, None

        src_drive, src_serial = get_vol_info(self.source_evidence_dir)
        dest_drive, dest_serial = get_vol_info(self.dest_data_dir)

        cross_volume = (src_drive.lower() != dest_drive.lower()) or (
            src_serial and dest_serial and (src_serial.lower() != dest_serial.lower())
        )

        # Dest volume disk usage
        try:
            usage = shutil.disk_usage(str(self.dest_data_dir))
            dest_free_bytes = usage.free
            dest_total_bytes = usage.total
        except Exception:
            dest_free_bytes = 0
            dest_total_bytes = 0

        # Formula: total_source_bytes * 2.5 + 500 MB minimum buffer
        required_safety_buffer = int(total_source_bytes * 2.5) + MINIMUM_SAFETY_BUFFER_BYTES
        capacity_sufficient = dest_free_bytes >= required_safety_buffer
        margin_ratio = (
            round(dest_free_bytes / required_safety_buffer, 2) if required_safety_buffer > 0 else 0.0
        )

        hist_bytes = category_bytes.get(PrimaryDisposition.HISTORICAL_ARCHIVE.value, 0)
        test_bytes = category_bytes.get(PrimaryDisposition.LEGACY_TEST_ARCHIVE.value, 0)
        mal_bytes = category_bytes.get(PrimaryDisposition.MALFORMED_PRESERVE.value, 0)
        act_bytes = category_bytes.get(PrimaryDisposition.ACTIVE_MIGRATION_CANDIDATE.value, 0)

        estimated_archive = hist_bytes + test_bytes + mal_bytes
        # Staging requirement for migration: peak batch staging equals total migration bytes or single largest file
        estimated_staging = total_source_bytes

        return VolumeCapacityAnalysis(
            source_volume_drive=src_drive,
            source_volume_serial=src_serial,
            dest_volume_drive=dest_drive,
            dest_volume_serial=dest_serial,
            cross_volume=cross_volume,
            staging_volume_same_as_dest=True,  # Staging directory is strictly inside dest_data_dir / evidence / .staging
            dest_free_bytes=dest_free_bytes,
            dest_total_bytes=dest_total_bytes,
            total_source_bytes=total_source_bytes,
            historical_archive_bytes=hist_bytes,
            legacy_test_archive_bytes=test_bytes,
            malformed_bytes=mal_bytes,
            blocked_candidate_bytes=act_bytes,
            estimated_archive_bytes=estimated_archive,
            estimated_staging_bytes=estimated_staging,
            required_safety_buffer_bytes=required_safety_buffer,
            capacity_sufficient=capacity_sufficient,
            margin_ratio=margin_ratio,
        )

    def run_simulation(self) -> SimulationSummaryReport:
        """
        Execute full read-only simulation pipeline across all artifacts.
        """
        inventory_records, inventory_sha256 = self.validate_inventory()
        physical_files, traversal_errors = self.scan_source_filesystem()

        # Identify candidate assessment and finding IDs
        cand_asm = "ASM-001"
        cand_fnd = "FND-ff03d7e4"
        for rec in inventory_records:
            if rec.get("primary_disposition") == PrimaryDisposition.ACTIVE_MIGRATION_CANDIDATE.value:
                cand_asm = rec.get("assessment_id") or cand_asm
                cand_fnd = rec.get("finding_id") or cand_fnd
                break

        db_validation = self.validate_sqlite_database(
            candidate_assessment_id=cand_asm,
            candidate_finding_id=cand_fnd,
        )

        artifact_results: List[ArtifactSimulationResult] = []
        category_bytes: Dict[str, int] = {}
        total_source_bytes = 0
        hash_to_paths: Dict[str, List[str]] = {}
        disposition_counts: Dict[str, int] = {}
        decision_counts: Dict[str, int] = {}

        for rec in inventory_records:
            rel_p = self.normalize_rel_path(rec["rel_path"])
            norm_key = rel_p.lower()
            primary_disp = rec.get("primary_disposition", "UNKNOWN")
            disposition_counts[primary_disp] = disposition_counts.get(primary_disp, 0) + 1

            if norm_key not in physical_files:
                # Missing file
                res = ArtifactSimulationResult(
                    source_relative_path=rel_p,
                    source_size_bytes=0,
                    source_sha256="FILE_NOT_FOUND",
                    inventory_sha256=rec.get("sha256", ""),
                    primary_disposition=primary_disp,
                    migration_status="BLOCKED_MISSING_FILE",
                    canonical_filename_id=Path(rel_p).stem,
                    embedded_legacy_id=None,
                    json_validation_result="FILE_NOT_FOUND",
                    relational_validation_result="NOT_EVALUATED",
                    proposed_destination="UNRESOLVED",
                    destination_status=DestinationStatus.DESTINATION_PATH_UNVERIFIABLE.value,
                    collision_status=CollisionStatus.NO_COLLISION.value,
                    source_stability="FILE_NOT_FOUND",
                    decision=SimulationDecision.BLOCKED_PATH_VALIDATION.value,
                    reason=f"Physical file missing on disk at '{rel_p}'",
                    id_discrepancy=False,
                )
                artifact_results.append(res)
                decision_counts[res.decision] = decision_counts.get(res.decision, 0) + 1
                continue

            phys_path = physical_files[norm_key]
            size_b, file_sha, is_stable, mtime_iso, json_info = self.hash_and_verify_physical_file(phys_path)
            total_source_bytes += size_b
            category_bytes[primary_disp] = category_bytes.get(primary_disp, 0) + size_b

            # Track duplicate content groups
            hash_to_paths.setdefault(file_sha, []).append(rel_p)

            # Integrity check
            expected_sha = rec.get("sha256", "")
            expected_size = rec.get("byte_size", 0)
            integrity_match = (file_sha == expected_sha) and (size_b == expected_size)

            # JSON validation string
            if json_info["is_valid_json"]:
                if json_info["is_evidence_schema"]:
                    json_res = "VALID_EVIDENCE_SCHEMA"
                else:
                    json_res = f"VALID_JSON_NON_EVIDENCE_SCHEMA ({json_info.get('parse_error') or 'non-standard structure'})"
            else:
                json_res = f"MALFORMED_JSON_SCHEMA ({json_info.get('parse_error')})"

            # Filename vs embedded ID
            canonical_filename_id = Path(rel_p).stem
            embedded_id = json_info.get("embedded_id")
            id_discrepancy = bool(embedded_id and embedded_id != canonical_filename_id)

            # Proposed destination & collision
            dest_p, dest_status, collision_status = self.simulate_destination_and_collision(rec, file_sha)

            # Relational validation
            relational_res = "NOT_APPLICABLE_ARCHIVE"
            if primary_disp == PrimaryDisposition.ACTIVE_MIGRATION_CANDIDATE.value:
                if not db_validation.active_candidate_parents_exist:
                    missing_parts = []
                    if not db_validation.missing_parent_details.get("assessment_exists"):
                        missing_parts.append(f"assessment '{cand_asm}' missing")
                    if not db_validation.missing_parent_details.get("finding_exists"):
                        missing_parts.append(f"finding '{cand_fnd}' missing")
                    if db_validation.engagements_count == 0:
                        missing_parts.append("zero engagements in SQLite")
                    relational_res = f"BLOCKED: {', '.join(missing_parts)}"
                else:
                    relational_res = "RELATIONAL_PARENTS_VERIFIED"

            # Decision logic
            source_stability = "SOURCE_STABLE" if is_stable else "SOURCE_UNSTABLE"
            if not is_stable:
                decision = SimulationDecision.BLOCKED_SOURCE_UNSTABLE.value
                reason = "File modified during scanning; pre-hash and post-hash metadata diverged"
            elif not integrity_match:
                decision = SimulationDecision.BLOCKED_SOURCE_INTEGRITY.value
                reason = f"SHA-256 or size mismatch: actual {file_sha[:12]} ({size_b}B) vs inventory {expected_sha[:12]} ({expected_size}B)"
            elif collision_status != CollisionStatus.NO_COLLISION.value:
                decision = SimulationDecision.BLOCKED_DESTINATION_COLLISION.value
                reason = f"Destination collision detected: status {dest_status.value}"
            elif primary_disp == PrimaryDisposition.ACTIVE_MIGRATION_CANDIDATE.value:
                if not db_validation.active_candidate_parents_exist:
                    decision = SimulationDecision.BLOCKED_MISSING_PARENT.value
                    reason = (
                        f"Parent engagement, assessment ({cand_asm}), or finding ({cand_fnd}) does not exist "
                        "in SQLite database. Relational constraints require parent existence prior to active publication."
                    )
                else:
                    decision = SimulationDecision.REQUIRES_OPERATOR_REVIEW.value
                    reason = (
                        f"Parent relational entities ({cand_asm}, {cand_fnd}) verified in SQLite database. "
                        "Operator review required before physical migration authorization."
                    )
            elif primary_disp == PrimaryDisposition.HISTORICAL_ARCHIVE.value:
                decision = SimulationDecision.WOULD_ARCHIVE.value
                reason = "Valid historical evidence artifact proposed for read-only archival under archive/evidence/."
            elif primary_disp == PrimaryDisposition.LEGACY_TEST_ARCHIVE.value:
                decision = SimulationDecision.WOULD_PRESERVE_AS_TEST_ARCHIVE.value
                reason = "Development or lifecycle test artifact proposed for isolated archival under archive/tests/."
            elif primary_disp == PrimaryDisposition.MALFORMED_PRESERVE.value:
                decision = SimulationDecision.WOULD_PRESERVE_AS_TEST_ARCHIVE.value
                reason = (
                    "Malformed test probe preserved read-only under archive/tests/malformed/ "
                    "without creating operational quarantine records."
                )
            else:
                decision = SimulationDecision.REQUIRES_OPERATOR_REVIEW.value
                reason = f"Unrecognized disposition '{primary_disp}' requires manual review"

            decision_counts[decision] = decision_counts.get(decision, 0) + 1

            sim_record = ArtifactSimulationResult(
                source_relative_path=rel_p,
                source_size_bytes=size_b,
                source_sha256=file_sha,
                inventory_sha256=expected_sha,
                primary_disposition=primary_disp,
                migration_status=rec.get("migration_status", "UNKNOWN"),
                canonical_filename_id=canonical_filename_id,
                embedded_legacy_id=embedded_id,
                json_validation_result=json_res,
                relational_validation_result=relational_res,
                proposed_destination=str(dest_p),
                destination_status=dest_status.value,
                collision_status=collision_status.value,
                source_stability=source_stability,
                decision=decision,
                reason=reason,
                id_discrepancy=id_discrepancy,
                mtime=mtime_iso,
            )
            artifact_results.append(sim_record)

        # Volume capacity
        vol_analysis = self.analyze_volume_and_capacity(total_source_bytes, category_bytes)

        # Duplicate content groups
        duplicate_content_groups = [
            {"sha256": h, "count": len(paths), "artifacts": paths}
            for h, paths in hash_to_paths.items()
            if len(paths) > 1
        ]
        duplicate_content_groups.sort(key=lambda x: x["count"], reverse=True)

        # Counts
        integrity_verified = sum(
            1 for a in artifact_results if a.source_sha256 == a.inventory_sha256 and a.source_stability == "SOURCE_STABLE"
        )
        relational_blocked = sum(
            1 for a in artifact_results if a.decision == SimulationDecision.BLOCKED_MISSING_PARENT.value
        )
        collisions_count = sum(
            1 for a in artifact_results if a.collision_status != CollisionStatus.NO_COLLISION.value
        )

        overall_verdict = "SIMULATION_SUCCESS_ALL_GATES_PASSED"
        if len(artifact_results) != self.expected_artifact_count:
            overall_verdict = "FAIL_ARTIFACT_COUNT_MISMATCH"
        elif integrity_verified != self.expected_artifact_count:
            overall_verdict = "FAIL_INTEGRITY_MISMATCH"
        elif not vol_analysis.capacity_sufficient:
            overall_verdict = "FAIL_INSUFFICIENT_DISK_CAPACITY"

        report = SimulationSummaryReport(
            simulation_timestamp=datetime.now(timezone.utc).isoformat(),
            source_root=str(self.source_evidence_dir),
            dest_data_dir=str(self.dest_data_dir),
            inventory_file=str(self.inventory_file),
            inventory_sha256=inventory_sha256,
            total_artifacts=len(artifact_results),
            disposition_counts=disposition_counts,
            decision_counts=decision_counts,
            duplicate_content_groups=duplicate_content_groups,
            integrity_verified_count=integrity_verified,
            relational_blocked_count=relational_blocked,
            collisions_count=collisions_count,
            volume_analysis=vol_analysis,
            database_validation=db_validation,
            artifacts=artifact_results,
            overall_verdict=overall_verdict,
        )

        return report


def validate_safe_output_dir(
    output_dir: Path,
    repo_root: Path,
    source_evidence_dir: Path,
    data_dir: Path,
    db_path: Path,
) -> Path:
    """
    Ensure the report output directory is safely located OUTSIDE:
    - Project repository
    - Legacy evidence directory
    - Runtime data directory
    - Production database directory
    Fails closed if output path intersects any prohibited location.
    """
    resolved_out = output_dir.resolve()
    # Order from most specific to broader parent directories
    prohibited_roots = [
        ("source_evidence_dir", source_evidence_dir.resolve()),
        ("runtime_data_dir", data_dir.resolve()),
        ("production_db_dir", db_path.resolve().parent),
        ("repository_root", repo_root.resolve()),
    ]

    for name, prohibited in prohibited_roots:
        if resolved_out == prohibited or str(resolved_out).startswith(str(prohibited) + os.sep):
            raise SimulationSafetyError(
                f"Unsafe output directory: '{resolved_out}' is located inside prohibited path '{name}' ({prohibited})"
            )

    return resolved_out
