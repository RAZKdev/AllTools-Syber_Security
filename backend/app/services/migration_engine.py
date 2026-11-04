"""
Migration Engine - Phase E3A.

Core engine implementing the 7-stage evidence migration state machine,
no-clobber same-volume publication, atomic SQLite journal updates,
and deterministic crash-interruption simulation.
"""

import hashlib
import json
import logging
import os
import shutil
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.core.instance_lock import InstanceLock, MaintenanceSession, ProcessLockError
from app.core.storage_paths import StoragePaths, get_storage_paths
from app.services.archive_manager import ArchiveManager
from app.services.jsonl_audit_outbox import JSONLAuditOutbox
from app.services.migration_authorization import (
    AuthorizationGateError,
    AuthorizationLedger,
    ProductionMigrationAuthorization,
    ProductionMigrationAuthorizationGate,
)
from app.services.migration_journal import MigrationJournal
from app.services.migration_models import (
    ArchiveManifestEntry,
    MigrationBatchPlan,
    MigrationBatchResult,
    MigrationCollisionError,
    MigrationError,
    MigrationIntegrityError,
    MigrationJournalEntry,
    MigrationRecoveryError,
    MigrationSafetyError,
    MigrationState,
)
from app.services.migration_recovery_service import MigrationRecoveryService

logger = logging.getLogger(__name__)

CHUNK_SIZE = 64 * 1024  # 64 KB streaming buffer


class MigrationEngine:
    """
    Evidence Migration Engine.
    Executes the 7-stage state machine:
    DISCOVERED -> VALIDATED -> STAGED -> VERIFIED -> PROMOTION_INTENT_RECORDED -> PROMOTED -> COMMITTED.
    """

    def __init__(
        self,
        paths: Optional[StoragePaths] = None,
        data_dir: Optional[Path] = None,
        db_path: Optional[Path] = None,
        maintenance_session: Optional[MaintenanceSession] = None,
        maintenance_lock: Optional[InstanceLock] = None,
        fault_injector: Optional[Callable[[str], None]] = None,
        authorization: Optional[ProductionMigrationAuthorization] = None,
        authorization_ledger_path: Optional[Path] = None,
        inventory_file: Optional[Path] = None,
        plan_file: Optional[Path] = None,
        source_evidence_dir: Optional[Path] = None,
        current_volume_id_resolver: Optional[Callable[[Path], Optional[str]]] = None,
    ) -> None:
        if paths is not None:
            self.paths = paths
        else:
            d_dir = data_dir or get_storage_paths().data_dir
            db_file = db_path or (d_dir / "workbench.db")
            self.paths = StoragePaths(
                data_dir=d_dir,
                database_file=db_file,
                evidence_dir=d_dir / "evidence",
                quarantine_dir=d_dir / "quarantine",
                backups_dir=d_dir / "backups",
                lock_file=d_dir / "workbench.lock",
            )

        self.fault_injector = fault_injector

        # Enforce exclusive maintenance lock ownership first
        if maintenance_session is not None:
            maintenance_session.assert_active()
            self.session: MaintenanceSession = maintenance_session
        elif maintenance_lock is not None:
            if not maintenance_lock.is_acquired:
                raise ProcessLockError(
                    f"Provided InstanceLock on '{maintenance_lock.lock_path}' is not acquired."
                )
            self.session = MaintenanceSession(maintenance_lock)
        else:
            raise ProcessLockError(
                f"Direct MigrationEngine invocation without exclusive maintenance lock ownership is strictly prohibited. "
                f"An active MaintenanceSession or acquired InstanceLock on '{self.paths.lock_file}' is required."
            )

        # ABSOLUTE SAFETY GUARD (P0): Production execution strictly requires verified authorization gate.
        self._assert_safe_sandbox(
            target_data_dir=self.paths.data_dir,
            authorization=authorization,
            authorization_ledger_path=authorization_ledger_path,
            inventory_file=inventory_file,
            plan_file=plan_file,
            source_evidence_dir=source_evidence_dir,
            current_volume_id_resolver=current_volume_id_resolver,
        )

        self.archive_mgr = ArchiveManager(data_dir=self.paths.data_dir, maintenance_session=self.session)
        self.outbox = JSONLAuditOutbox(outbox_path=self.paths.data_dir / "migration_journal.jsonl")

    @staticmethod
    def _assert_safe_sandbox(
        target_data_dir: Path,
        authorization: Optional[ProductionMigrationAuthorization] = None,
        authorization_ledger_path: Optional[Path] = None,
        inventory_file: Optional[Path] = None,
        plan_file: Optional[Path] = None,
        source_evidence_dir: Optional[Path] = None,
        current_volume_id_resolver: Optional[Callable[[Path], Optional[str]]] = None,
    ) -> None:
        """
        Verify target data directory is NOT production storage unless an explicit,
        cryptographically verifiable ProductionMigrationAuthorization token is provided
        and validated through ProductionMigrationAuthorizationGate.
        Fails closed on any discrepancy or missing authorization.
        """
        resolved_target = target_data_dir.resolve()

        # Check against Windows LOCALAPPDATA default
        local_app = os.environ.get("LOCALAPPDATA")
        is_production = False
        if local_app:
            prod_dir = (Path(local_app) / "AllTools-CyberSec").resolve()
            if resolved_target == prod_dir or str(resolved_target).startswith(str(prod_dir) + os.sep):
                is_production = True

        if is_production:
            if authorization is None:
                raise MigrationSafetyError(
                    f"FATAL SAFETY VIOLATION: Execution against production data directory '{resolved_target}' "
                    "is strictly prohibited without a valid, verified ProductionMigrationAuthorization token."
                )

            ledger_path = authorization_ledger_path or (target_data_dir / "authorization_ledger.jsonl")
            ledger = AuthorizationLedger(ledger_path=ledger_path)
            gate = ProductionMigrationAuthorizationGate(ledger)

            src_dir = source_evidence_dir or (Path.cwd() / "database" / "evidence")
            inv_file = inventory_file or (src_dir / "legacy-evidence-inventory.json")

            if plan_file is None:
                cand_plan = Path.cwd() / "phase-e3b-final-migration-plan.json"
                if not cand_plan.exists():
                    cand_plan = Path(r"C:\Users\Rangga\.gemini\antigravity\brain\72d04d7a-59e5-45ea-b077-8c9e8e67ef4e\phase-e3b-final-migration-plan.json")
                plan_file = cand_plan

            try:
                gate.verify_and_consume(
                    authorization=authorization,
                    target_data_dir=resolved_target,
                    source_evidence_dir=src_dir,
                    inventory_file=inv_file,
                    plan_file=plan_file,
                    current_volume_id_resolver=current_volume_id_resolver,
                )
                logger.info("Production migration authorization verified and consumed for %s", authorization.approval_id)
            except Exception as e:
                raise MigrationSafetyError(
                    f"FATAL SAFETY VIOLATION: Production authorization gate verification failed: {e}"
                ) from e
        elif authorization is not None:
            # Synthetic/test sandbox with explicit authorization token provided for verification
            ledger_path = authorization_ledger_path or (target_data_dir / "authorization_ledger.jsonl")
            ledger = AuthorizationLedger(ledger_path=ledger_path)
            gate = ProductionMigrationAuthorizationGate(ledger)
            src_dir = source_evidence_dir or (Path.cwd() / "database" / "evidence")
            inv_file = inventory_file or (src_dir / "legacy-evidence-inventory.json")
            if plan_file is None:
                cand_plan = Path.cwd() / "phase-e3b-final-migration-plan.json"
                if not cand_plan.exists():
                    cand_plan = Path(r"C:\Users\Rangga\.gemini\antigravity\brain\72d04d7a-59e5-45ea-b077-8c9e8e67ef4e\phase-e3b-final-migration-plan.json")
                plan_file = cand_plan
            try:
                gate.verify_and_consume(
                    authorization=authorization,
                    target_data_dir=resolved_target,
                    source_evidence_dir=src_dir,
                    inventory_file=inv_file,
                    plan_file=plan_file,
                    current_volume_id_resolver=current_volume_id_resolver,
                )
            except Exception as e:
                raise MigrationSafetyError(
                    f"FATAL SAFETY VIOLATION: Authorization gate verification failed: {e}"
                ) from e

    def connect_database(self) -> sqlite3.Connection:
        """
        Open a dedicated migration connection to SQLite with full durability and foreign key enforcement.
        Enforces WAL mode, PRAGMA synchronous=FULL, and PRAGMA foreign_keys=ON.
        """
        self.paths.database_file.parent.mkdir(parents=True, exist_ok=True)
        # Isolation level None allows manual transaction boundaries with BEGIN IMMEDIATE
        conn = sqlite3.connect(str(self.paths.database_file), isolation_level=None)
        cursor = conn.cursor()

        # 1. WAL mode
        cursor.execute("PRAGMA journal_mode = WAL;")

        # 2. Synchronous = FULL
        cursor.execute("PRAGMA synchronous = FULL;")
        sync_mode = cursor.execute("PRAGMA synchronous;").fetchone()[0]
        if sync_mode != 2:
            raise MigrationError(f"PRAGMA synchronous verification failed: expected 2 (FULL), got {sync_mode}")

        # 3. Foreign Keys = ON
        cursor.execute("PRAGMA foreign_keys = ON;")
        fk_mode = cursor.execute("PRAGMA foreign_keys;").fetchone()[0]
        if fk_mode != 1:
            raise MigrationError(f"PRAGMA foreign_keys verification failed: expected 1 (ON), got {fk_mode}")

        # Ensure journal schema exists
        MigrationJournal.ensure_schema(conn)
        return conn

    @staticmethod
    def _stream_copy_with_hashes(src_path: Path, dst_path: Path) -> Tuple[int, str, str]:
        """
        Copy src to dst in 64 KB chunks while simultaneously calculating
        source and destination SHA-256 digests. Flushes and fsyncs destination.
        """
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        src_hasher = hashlib.sha256()
        dst_hasher = hashlib.sha256()
        total_bytes = 0

        with open(src_path, "rb") as sf, open(dst_path, "wb") as df:
            while chunk := sf.read(CHUNK_SIZE):
                src_hasher.update(chunk)
                dst_hasher.update(chunk)
                df.write(chunk)
                total_bytes += len(chunk)
            df.flush()
            os.fsync(df.fileno())

        return total_bytes, src_hasher.hexdigest(), dst_hasher.hexdigest()

    def migrate_single_artifact(
        self,
        conn: sqlite3.Connection,
        operation_id: str,
        artifact_record: Dict[str, Any],
        sequence: int,
    ) -> MigrationJournalEntry:
        """
        Execute the 7-stage state machine for a single evidence artifact.
        """
        self.session.assert_active()
        source_p = Path(artifact_record["source_path"]).resolve()
        parent_folder = artifact_record.get("parent_folder", "unknown")
        artifact_id = artifact_record.get("artifact_id") or source_p.stem
        primary_disp = artifact_record.get("primary_disposition", "HISTORICAL_ARCHIVE")
        expected_sha = artifact_record.get("sha256", "")
        expected_size = artifact_record.get("byte_size", 0)

        # Proposed target path computation
        if primary_disp == "ACTIVE_MIGRATION_CANDIDATE":
            asm_id = artifact_record.get("assessment_id", parent_folder)
            target_p = self.paths.evidence_dir / asm_id / source_p.name
        else:
            target_p = self.archive_mgr.get_target_path(
                primary_disposition=primary_disp,
                parent_folder=parent_folder,
                filename=source_p.name,
            )

        # Staging path setup (strictly on same filesystem as target)
        staging_dir = self.paths.data_dir / ".staging" / operation_id
        staging_dir.mkdir(parents=True, exist_ok=True)
        staged_p = staging_dir / f"{artifact_id}_{uuid.uuid4().hex[:6]}.tmp"

        # -------------------------------------------------------------
        # Stage 1: DISCOVERED
        # -------------------------------------------------------------
        if self.fault_injector:
            self.fault_injector("before_source_hashing")

        entry = MigrationJournal.record_discovered(
            conn=conn,
            operation_id=operation_id,
            artifact_id=artifact_id,
            parent_folder=parent_folder,
            source_path=str(source_p),
            staged_path=str(staged_p),
            target_path=str(target_p),
            sha256=expected_sha,
            byte_size=expected_size,
            sequence=sequence,
        )

        # -------------------------------------------------------------
        # Stage 2: VALIDATED
        # -------------------------------------------------------------
        if not source_p.exists() or not source_p.is_file():
            MigrationJournal.transition_state(
                conn, entry.id, MigrationState.DISCOVERED, MigrationState.FAILED_IO,
                error_detail=f"Source file missing or not regular file: {source_p}"
            )
            raise MigrationError(f"Source file missing: {source_p}")

        # Collision detection (no-clobber invariant)
        if target_p.exists():
            MigrationJournal.transition_state(
                conn, entry.id, MigrationState.DISCOVERED, MigrationState.BLOCKED_COLLISION,
                error_detail=f"Target file already exists at '{target_p}'. Overwrite forbidden."
            )
            raise MigrationCollisionError(f"Target already exists at '{target_p}'")

        # Relational check for active candidates
        if primary_disp == "ACTIVE_MIGRATION_CANDIDATE":
            cur = conn.cursor()
            asm_id = artifact_record.get("assessment_id")
            fnd_id = artifact_record.get("finding_id")
            cur.execute("SELECT COUNT(*) FROM assessments WHERE id = ?;", (asm_id,))
            asm_ok = cur.fetchone()[0] > 0
            fnd_ok = True
            if fnd_id:
                cur.execute("SELECT COUNT(*) FROM findings WHERE id = ?;", (fnd_id,))
                fnd_ok = cur.fetchone()[0] > 0
            cur.execute("SELECT COUNT(*) FROM engagements;")
            eng_ok = cur.fetchone()[0] > 0

            if not (asm_ok and fnd_ok and eng_ok):
                reason = f"Missing parent entities (asm_ok={asm_ok}, fnd_ok={fnd_ok}, eng_ok={eng_ok})"
                updated = MigrationJournal.transition_state(
                    conn, entry.id, MigrationState.DISCOVERED, MigrationState.BLOCKED_MISSING_PARENT,
                    error_detail=reason
                )
                logger.info("Artifact %s blocked by missing parent entities", artifact_id)
                return updated

        entry = MigrationJournal.transition_state(
            conn, entry.id, MigrationState.DISCOVERED, MigrationState.VALIDATED
        )

        # -------------------------------------------------------------
        # Stage 3: STAGED
        # -------------------------------------------------------------
        if self.fault_injector:
            self.fault_injector("during_staging_copy")

        copied_bytes, src_sha, stg_sha = self._stream_copy_with_hashes(source_p, staged_p)

        if self.fault_injector:
            self.fault_injector("after_staging_fsync")

        entry = MigrationJournal.transition_state(
            conn, entry.id, MigrationState.VALIDATED, MigrationState.STAGED,
            sha256=stg_sha
        )

        # -------------------------------------------------------------
        # Stage 4: VERIFIED
        # -------------------------------------------------------------
        # Re-verify staged file from disk
        if not staged_p.exists():
            MigrationJournal.transition_state(
                conn, entry.id, MigrationState.STAGED, MigrationState.FAILED_IO,
                error_detail="Staging file missing immediately after copy."
            )
            raise MigrationError("Staging file disappeared after copy.")

        # Cryptographic check
        if src_sha != stg_sha or (expected_sha and stg_sha != expected_sha):
            MigrationJournal.transition_state(
                conn, entry.id, MigrationState.STAGED, MigrationState.FAILED_INTEGRITY,
                error_detail=f"Checksum mismatch: expected {expected_sha}, computed {stg_sha}"
            )
            raise MigrationIntegrityError(f"Checksum mismatch for '{artifact_id}'")

        entry = MigrationJournal.transition_state(
            conn, entry.id, MigrationState.STAGED, MigrationState.VERIFIED
        )

        if self.fault_injector:
            self.fault_injector("after_sha256_verification")

        # -------------------------------------------------------------
        # Stage 5: PROMOTION_INTENT_RECORDED
        # -------------------------------------------------------------
        entry = MigrationJournal.transition_state(
            conn, entry.id, MigrationState.VERIFIED, MigrationState.PROMOTION_INTENT_RECORDED
        )

        if self.fault_injector:
            self.fault_injector("after_promotion_intent_recorded")

        # -------------------------------------------------------------
        # Stage 6: PROMOTED (Same-volume hard-link publication)
        # -------------------------------------------------------------
        target_p.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(str(staged_p), str(target_p))
        except Exception as e:
            MigrationJournal.transition_state(
                conn, entry.id, MigrationState.PROMOTION_INTENT_RECORDED, MigrationState.FAILED_IO,
                error_detail=f"Hard-link publication failed: {e}"
            )
            raise MigrationError(f"Hard-link failed: {e}") from e

        if self.fault_injector:
            self.fault_injector("after_hard_link_publication")

        # Verify samefile
        if not os.path.samefile(staged_p, target_p):
            MigrationJournal.transition_state(
                conn, entry.id, MigrationState.PROMOTION_INTENT_RECORDED, MigrationState.FAILED_INTEGRITY,
                error_detail="Target file does not match staged inode."
            )
            raise MigrationIntegrityError("Target file failed samefile() verification.")

        if self.fault_injector:
            self.fault_injector("after_samefile_verification")

        entry = MigrationJournal.transition_state(
            conn, entry.id, MigrationState.PROMOTION_INTENT_RECORDED, MigrationState.PROMOTED
        )

        if self.fault_injector:
            self.fault_injector("after_promoted_journal_commit")

        # -------------------------------------------------------------
        # Stage 7: COMMITTED
        # -------------------------------------------------------------
        conn.execute("BEGIN IMMEDIATE;")
        try:
            if self.fault_injector:
                self.fault_injector("during_evidence_insert_transaction")

            if primary_disp == "ACTIVE_MIGRATION_CANDIDATE":
                # Atomic insert into evidence table
                evidence_dict = {
                    "id": artifact_id,
                    "assessment_id": artifact_record["assessment_id"],
                    "finding_id": artifact_record.get("finding_id"),
                    "type": artifact_record.get("type", "other"),
                    "source": artifact_record.get("source", "migration"),
                    "artifact_path": str(target_p.relative_to(self.paths.data_dir)).replace("\\", "/"),
                    "captured_at": artifact_record.get("captured_at", datetime.now(timezone.utc).isoformat()),
                    "sha256": stg_sha,
                    "redacted": artifact_record.get("redacted", False),
                    "notes": artifact_record.get("notes"),
                    "retention_policy": artifact_record.get("retention_policy", "retain_90_days"),
                }
                entry = MigrationJournal.commit_active_evidence_atomic(conn, entry.id, evidence_dict)
            else:
                # Archive artifact commit: advance journal state in SQLite
                now_iso = datetime.now(timezone.utc).isoformat()
                c = conn.execute(
                    """
                    UPDATE migration_journal
                    SET state = 'COMMITTED', updated_at = ?
                    WHERE id = ? AND state = 'PROMOTED';
                    """,
                    (now_iso, entry.id),
                )
                if c.rowcount != 1:
                    raise MigrationError(f"Rowcount was {c.rowcount} on archive commit for {entry.id}")
                entry.state = MigrationState.COMMITTED
                entry.updated_at = now_iso

            conn.execute("COMMIT;")
        except Exception as e:
            conn.execute("ROLLBACK;")
            logger.error("Transaction rolled back for %s: %s", artifact_id, e)
            raise

        if self.fault_injector:
            self.fault_injector("after_database_commit_before_staging_cleanup")

        # Now that DB committed, remove the staging reference
        staged_p.unlink(missing_ok=True)

        # Record in archive manifest for non-active evidence
        if primary_disp != "ACTIVE_MIGRATION_CANDIDATE":
            self.archive_mgr.append_manifest_entry(
                source_path=str(source_p),
                target_path=str(target_p),
                sha256=stg_sha,
                byte_size=copied_bytes,
                filename=source_p.name,
                classification=primary_disp,
                operation_id=operation_id,
                artifact_id=artifact_id,
                provenance=artifact_record.get("provenance", {}),
            )

        # Deliver to JSONL Audit Outbox with durable fsync
        if self.fault_injector:
            self.fault_injector("during_jsonl_append")

        self.outbox.append_event(entry)

        if self.fault_injector:
            self.fault_injector("after_jsonl_fsync_before_delivered_at_update")

        now_deliv = datetime.now(timezone.utc).isoformat()
        MigrationJournal.mark_jsonl_delivered(conn, entry.id, now_deliv)
        entry.jsonl_delivered_at = now_deliv

        return entry

    def execute_batch(
        self,
        batch_plan: MigrationBatchPlan,
    ) -> MigrationBatchResult:
        """
        Execute migration for a planned batch of artifacts.
        """
        self.session.assert_active()
        conn = self.connect_database()
        try:
            entries: List[MigrationJournalEntry] = []
            succeeded = 0
            blocked = 0
            failed = 0
            total_bytes = 0

            for idx, item in enumerate(batch_plan.items, 1):
                try:
                    res = self.migrate_single_artifact(
                        conn=conn,
                        operation_id=batch_plan.operation_id,
                        artifact_record=item,
                        sequence=idx,
                    )
                    entries.append(res)
                    if res.state == MigrationState.COMMITTED:
                        succeeded += 1
                        total_bytes += res.byte_size
                    elif res.state in (MigrationState.BLOCKED_COLLISION, MigrationState.BLOCKED_MISSING_PARENT):
                        blocked += 1
                except Exception as e:
                    logger.error("Failed migrating item %s: %s", item.get("source_path"), e)
                    failed += 1

            is_fully_committed = (succeeded == len(batch_plan.items))
            return MigrationBatchResult(
                operation_id=batch_plan.operation_id,
                batch_index=batch_plan.batch_index,
                total_items=len(batch_plan.items),
                succeeded_items=succeeded,
                blocked_items=blocked,
                failed_items=failed,
                total_bytes=total_bytes,
                journal_entries=entries,
                is_fully_committed=is_fully_committed,
            )
        finally:
            conn.close()
