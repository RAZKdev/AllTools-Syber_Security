"""
Migration Recovery Service - Phase E3A.

Provides deterministic crash recovery for interrupted migration batches based
on durable SQLite migration_journal state and physical filesystem inspection.
"""

import hashlib
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.core.instance_lock import InstanceLock, MaintenanceSession, ProcessLockError
from app.services.archive_manager import ArchiveManager
from app.services.jsonl_audit_outbox import JSONLAuditOutbox
from app.services.migration_journal import MigrationJournal
from app.services.migration_models import (
    MigrationError,
    MigrationJournalEntry,
    MigrationRecoveryError,
    MigrationState,
)

logger = logging.getLogger(__name__)


class MigrationRecoveryService:
    """
    Reconciles in-flight or interrupted migration operations.
    Follows approved E1 recovery protocol:
    - Enforces active OS-level MaintenanceSession ownership.
    - SQLite remains the authoritative ledger.
    - Never deletes source evidence or unowned destination files.
    - Reconciles hard-linked target and staging files.
    - Unlinks staging references only after durable commit.
    - Ensures JSONL delivery with fsync.
    - Reconciles and backfills archive_manifest.jsonl parity.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        outbox: JSONLAuditOutbox,
        archive_mgr: ArchiveManager,
        maintenance_session: Optional[MaintenanceSession] = None,
        maintenance_lock: Optional[InstanceLock] = None,
    ) -> None:
        self.conn = conn
        self.outbox = outbox
        self.archive_mgr = archive_mgr

        if maintenance_session is not None:
            maintenance_session.assert_active()
            self.session = maintenance_session
        elif maintenance_lock is not None:
            if not maintenance_lock.is_acquired:
                raise ProcessLockError(
                    f"Provided InstanceLock on '{maintenance_lock.lock_path}' is not acquired."
                )
            self.session = MaintenanceSession(maintenance_lock)
        else:
            raise ProcessLockError(
                "Direct MigrationRecoveryService invocation without exclusive maintenance lock ownership is strictly prohibited."
            )

        # Propagate maintenance session to archive_mgr if needed
        if self.archive_mgr.session is None:
            self.archive_mgr.session = self.session

    @staticmethod
    def _compute_sha256(path: Path) -> str:
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(64 * 1024):
                hasher.update(chunk)
        return hasher.hexdigest()

    def recover_entry(self, entry: MigrationJournalEntry) -> MigrationJournalEntry:
        """
        Deterministically recover a single uncommitted or interrupted migration journal entry.
        """
        self.session.assert_active()
        staged_p = Path(entry.staged_path) if entry.staged_path else None
        target_p = Path(entry.target_path) if entry.target_path else None

        logger.info(
            "Recovering artifact '%s' (journal_id=%s) in state '%s'",
            entry.artifact_id, entry.id, entry.state.value
        )

        # -------------------------------------------------------------
        # State: DISCOVERED or VALIDATED
        # -------------------------------------------------------------
        if entry.state in (MigrationState.DISCOVERED, MigrationState.VALIDATED):
            # Target should not exist; staging may have an incomplete copy
            if staged_p and staged_p.exists():
                try:
                    staged_p.unlink(missing_ok=True)
                except Exception as e:
                    logger.warning("Could not unlink incomplete staging file %s: %e", staged_p, e)
            return entry

        # -------------------------------------------------------------
        # State: STAGED or VERIFIED
        # -------------------------------------------------------------
        elif entry.state in (MigrationState.STAGED, MigrationState.VERIFIED):
            # If target does not exist, staging file is cleaned up or preserved
            if target_p and target_p.exists():
                raise MigrationRecoveryError(
                    f"Unexpected target file pre-exists at '{target_p}' for artifact in '{entry.state.value}' state."
                )
            if staged_p and staged_p.exists():
                staged_p.unlink(missing_ok=True)
            return entry

        # -------------------------------------------------------------
        # State: PROMOTION_INTENT_RECORDED
        # -------------------------------------------------------------
        elif entry.state == MigrationState.PROMOTION_INTENT_RECORDED:
            if not staged_p or not staged_p.exists():
                raise MigrationRecoveryError(
                    f"Staging file missing at '{staged_p}' during recovery of PROMOTION_INTENT_RECORDED"
                )

            # Check if target already was hard-linked before the crash
            if target_p and target_p.exists():
                # Verify hard-link identity
                is_same = False
                try:
                    is_same = os.path.samefile(staged_p, target_p)
                except Exception:
                    pass

                if is_same:
                    # Hard link publication succeeded before crash! Advance to PROMOTED
                    updated = MigrationJournal.transition_state(
                        self.conn,
                        journal_id=entry.id,  # type: ignore
                        expected_prev_state=MigrationState.PROMOTION_INTENT_RECORDED,
                        new_state=MigrationState.PROMOTED,
                    )
                    return self.recover_entry(updated)
                else:
                    raise MigrationRecoveryError(
                        f"Target exists at '{target_p}' but is NOT the same physical file as staging '{staged_p}'"
                    )
            else:
                # Target was not yet linked before crash; publish hard-link now
                target_p.parent.mkdir(parents=True, exist_ok=True)
                try:
                    os.link(str(staged_p), str(target_p))
                except Exception as e:
                    raise MigrationRecoveryError(f"Failed to hard-link during recovery: {e}") from e

                updated = MigrationJournal.transition_state(
                    self.conn,
                    journal_id=entry.id,  # type: ignore
                    expected_prev_state=MigrationState.PROMOTION_INTENT_RECORDED,
                    new_state=MigrationState.PROMOTED,
                )
                return self.recover_entry(updated)

        # -------------------------------------------------------------
        # State: PROMOTED
        # -------------------------------------------------------------
        elif entry.state == MigrationState.PROMOTED:
            if not target_p or not target_p.exists():
                raise MigrationRecoveryError(f"Target missing at '{target_p}' for PROMOTED artifact")
            if not staged_p or not staged_p.exists():
                raise MigrationRecoveryError(f"Staged file missing at '{staged_p}' for PROMOTED artifact")

            # Finalize commit in SQLite
            now_iso = datetime.now(timezone.utc).isoformat()
            cursor = self.conn.cursor()
            cursor.execute(
                """
                UPDATE migration_journal
                SET state = 'COMMITTED', updated_at = ?
                WHERE id = ? AND state = 'PROMOTED';
                """,
                (now_iso, entry.id),
            )
            if cursor.rowcount != 1:
                raise MigrationRecoveryError(f"Failed to advance journal to COMMITTED for {entry.id}")

            # Now that database committed, unlink staging file
            staged_p.unlink(missing_ok=True)

            # Retrieve committed entry
            cursor.execute("SELECT * FROM migration_journal WHERE id = ?;", (entry.id,))
            committed_entry = MigrationJournal._row_to_entry(cursor, cursor.fetchone())

            # Deliver to JSONL outbox
            self.outbox.append_event(committed_entry)
            MigrationJournal.mark_jsonl_delivered(self.conn, committed_entry.id, now_iso)  # type: ignore

            return committed_entry

        # -------------------------------------------------------------
        # State: COMMITTED (Post-commit residue recovery)
        # -------------------------------------------------------------
        elif entry.state == MigrationState.COMMITTED:
            # Staging file cleanup residue
            if staged_p and staged_p.exists():
                staged_p.unlink(missing_ok=True)

            # Check JSONL delivery
            if entry.jsonl_delivered_at is None:
                self.outbox.append_event(entry)
                now_iso = datetime.now(timezone.utc).isoformat()
                MigrationJournal.mark_jsonl_delivered(self.conn, entry.id, now_iso)  # type: ignore
                entry.jsonl_delivered_at = now_iso

            return entry

        return entry

    def recover_all_pending(self, operation_id: Optional[str] = None) -> List[MigrationJournalEntry]:
        """
        Recover all entries in incomplete states across a given operation or database.
        Also backfills missing archive_manifest.jsonl records for committed archive entries.
        """
        self.session.assert_active()
        pending = MigrationJournal.query_pending_recovery(self.conn, operation_id=operation_id)
        undelivered = MigrationJournal.query_undelivered_jsonl_events(self.conn, operation_id=operation_id)

        recovered: List[MigrationJournalEntry] = []
        for p in pending:
            recovered.append(self.recover_entry(p))

        for u in undelivered:
            if u.id not in [r.id for r in recovered]:
                recovered.append(self.recover_entry(u))

        # Reconcile archive manifest parity: backfill any missing records for committed archive entries
        self.archive_mgr.backfill_from_committed_journal(self.conn, operation_id=operation_id)

        return recovered
