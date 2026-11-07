"""
Migration Journal Repository & State Machine - Phase E3A.

Manages durable SQLite migration_journal state, validates atomic transitions,
enforces rowcount checks, and coordinates transactional commit of active evidence.
"""

import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from app.services.migration_models import (
    InvalidStateTransitionError,
    MigrationJournalEntry,
    MigrationState,
)

logger = logging.getLogger(__name__)

# Valid state machine transition map: Current State -> Allowed Next States
ALLOWED_TRANSITIONS: Dict[Optional[MigrationState], Set[MigrationState]] = {
    None: {MigrationState.DISCOVERED},
    MigrationState.DISCOVERED: {
        MigrationState.VALIDATED,
        MigrationState.BLOCKED_COLLISION,
        MigrationState.BLOCKED_MISSING_PARENT,
        MigrationState.FAILED_INTEGRITY,
    },
    MigrationState.VALIDATED: {
        MigrationState.STAGED,
        MigrationState.BLOCKED_COLLISION,
        MigrationState.FAILED_IO,
    },
    MigrationState.STAGED: {
        MigrationState.VERIFIED,
        MigrationState.FAILED_INTEGRITY,
        MigrationState.FAILED_IO,
    },
    MigrationState.VERIFIED: {
        MigrationState.PROMOTION_INTENT_RECORDED,
        MigrationState.BLOCKED_COLLISION,
    },
    MigrationState.PROMOTION_INTENT_RECORDED: {
        MigrationState.PROMOTED,
        MigrationState.FAILED_IO,
    },
    MigrationState.PROMOTED: {
        MigrationState.COMMITTED,
        MigrationState.FAILED_IO,
    },
    # Terminal states have no valid transitions
    MigrationState.COMMITTED: set(),
    MigrationState.BLOCKED_COLLISION: set(),
    MigrationState.BLOCKED_MISSING_PARENT: set(),
    MigrationState.FAILED_INTEGRITY: set(),
    MigrationState.FAILED_IO: set(),
}


class MigrationJournal:
    """
    Durable SQLite journal interface for evidence migration operations.
    Enforces atomic transitions, rowcount validation, and failure-closed rollbacks.
    """

    SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS migration_journal (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        operation_id TEXT NOT NULL,
        artifact_id TEXT NOT NULL,
        parent_folder TEXT NOT NULL,
        source_path TEXT NOT NULL,
        staged_path TEXT NOT NULL,
        target_path TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        byte_size INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN (
            'DISCOVERED', 'VALIDATED', 'STAGED', 'VERIFIED',
            'PROMOTION_INTENT_RECORDED', 'PROMOTED', 'COMMITTED',
            'BLOCKED_COLLISION', 'BLOCKED_MISSING_PARENT',
            'FAILED_INTEGRITY', 'FAILED_IO'
        )),
        sequence INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        event_id TEXT NOT NULL UNIQUE,
        jsonl_delivered_at TEXT,
        error_detail TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_mig_journal_batch ON migration_journal (operation_id);
    CREATE INDEX IF NOT EXISTS idx_mig_journal_artifact ON migration_journal (artifact_id);
    CREATE INDEX IF NOT EXISTS idx_mig_journal_state ON migration_journal (state);
    CREATE INDEX IF NOT EXISTS idx_mig_journal_event_id ON migration_journal (event_id);
    """

    @classmethod
    def ensure_schema(cls, conn: sqlite3.Connection) -> None:
        """Create migration_journal table and indexes if they do not exist."""
        conn.executescript(cls.SCHEMA_SQL)

    @classmethod
    def validate_transition(
        cls, current_state: Optional[MigrationState], next_state: MigrationState
    ) -> None:
        """Validate state transition against the approved state machine."""
        allowed = ALLOWED_TRANSITIONS.get(current_state, set())
        if next_state not in allowed:
            raise InvalidStateTransitionError(
                f"Invalid migration state transition: '{current_state}' -> '{next_state}'. "
                f"Allowed target states: {[s.value for s in allowed]}"
            )

    @classmethod
    def record_discovered(
        cls,
        conn: sqlite3.Connection,
        operation_id: str,
        artifact_id: str,
        parent_folder: str,
        source_path: str,
        staged_path: str,
        target_path: str,
        sha256: str,
        byte_size: int,
        sequence: int,
    ) -> MigrationJournalEntry:
        """Record initial discovery of a migration artifact in the journal."""
        cls.validate_transition(None, MigrationState.DISCOVERED)
        now_iso = datetime.now(timezone.utc).isoformat()
        event_id = f"mig-evt-{uuid.uuid4().hex}"

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO migration_journal (
                operation_id, artifact_id, parent_folder, source_path,
                staged_path, target_path, sha256, byte_size, state,
                sequence, created_at, updated_at, event_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                operation_id,
                artifact_id,
                parent_folder,
                source_path,
                staged_path,
                target_path,
                sha256,
                byte_size,
                MigrationState.DISCOVERED.value,
                sequence,
                now_iso,
                now_iso,
                event_id,
            ),
        )
        if cursor.rowcount != 1:
            raise RuntimeError(f"Failed to insert DISCOVERED journal entry for '{artifact_id}'")

        entry_id = cursor.lastrowid
        return MigrationJournalEntry(
            id=entry_id,
            operation_id=operation_id,
            artifact_id=artifact_id,
            parent_folder=parent_folder,
            source_path=source_path,
            staged_path=staged_path,
            target_path=target_path,
            sha256=sha256,
            byte_size=byte_size,
            state=MigrationState.DISCOVERED,
            sequence=sequence,
            created_at=now_iso,
            updated_at=now_iso,
            event_id=event_id,
        )

    @classmethod
    def transition_state(
        cls,
        conn: sqlite3.Connection,
        journal_id: int,
        expected_prev_state: MigrationState,
        new_state: MigrationState,
        error_detail: Optional[str] = None,
        staged_path: Optional[str] = None,
        target_path: Optional[str] = None,
        sha256: Optional[str] = None,
    ) -> MigrationJournalEntry:
        """
        Atomically transition an artifact's state in SQLite with strict rowcount validation.
        """
        cls.validate_transition(expected_prev_state, new_state)
        now_iso = datetime.now(timezone.utc).isoformat()

        cursor = conn.cursor()
        query = """
            UPDATE migration_journal
            SET state = ?, updated_at = ?,
                error_detail = COALESCE(?, error_detail),
                staged_path = COALESCE(?, staged_path),
                target_path = COALESCE(?, target_path),
                sha256 = COALESCE(?, sha256)
            WHERE id = ? AND state = ?;
        """
        cursor.execute(
            query,
            (
                new_state.value,
                now_iso,
                error_detail,
                staged_path,
                target_path,
                sha256,
                journal_id,
                expected_prev_state.value,
            ),
        )

        if cursor.rowcount != 1:
            raise InvalidStateTransitionError(
                f"Failed transition to '{new_state.value}' for journal ID {journal_id}: "
                f"expected current state '{expected_prev_state.value}', but 0 rows matched."
            )

        # Retrieve and return updated entry
        cursor.execute("SELECT * FROM migration_journal WHERE id = ?;", (journal_id,))
        row = cursor.fetchone()
        return cls._row_to_entry(cursor, row)

    @classmethod
    def commit_active_evidence_atomic(
        cls,
        conn: sqlite3.Connection,
        journal_id: int,
        evidence_dict: Dict[str, Any],
    ) -> MigrationJournalEntry:
        """
        Atomically insert evidence metadata into the production evidence table AND
        transition migration_journal from PROMOTED to COMMITTED in a single transaction.
        Asserts exact rowcount == 1 on both operations.
        """
        cursor = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Insert active evidence row
        cursor.execute(
            """
            INSERT INTO evidence (
                id, assessment_id, finding_id, type, source,
                artifact_path, captured_at, sha256, redacted,
                notes, sync_status, retention_policy, legal_hold, is_deleted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'COMMITTED', ?, 0, 0);
            """,
            (
                evidence_dict["id"],
                evidence_dict["assessment_id"],
                evidence_dict.get("finding_id"),
                evidence_dict["type"],
                evidence_dict["source"],
                evidence_dict["artifact_path"],
                evidence_dict["captured_at"],
                evidence_dict["sha256"],
                1 if evidence_dict.get("redacted") else 0,
                evidence_dict.get("notes"),
                evidence_dict.get("retention_policy", "retain_90_days"),
            ),
        )
        if cursor.rowcount != 1:
            raise RuntimeError(f"Atomic evidence INSERT failed for ID '{evidence_dict['id']}'")

        # 2. Advance journal from PROMOTED to COMMITTED
        cursor.execute(
            """
            UPDATE migration_journal
            SET state = 'COMMITTED', updated_at = ?
            WHERE id = ? AND state = 'PROMOTED';
            """,
            (now_iso, journal_id),
        )
        if cursor.rowcount != 1:
            raise InvalidStateTransitionError(
                f"Atomic journal update failed for ID {journal_id}: expected state 'PROMOTED', got rowcount {cursor.rowcount}"
            )

        cursor.execute("SELECT * FROM migration_journal WHERE id = ?;", (journal_id,))
        row = cursor.fetchone()
        return cls._row_to_entry(cursor, row)

    @classmethod
    def query_pending_recovery(
        cls, conn: sqlite3.Connection, operation_id: Optional[str] = None
    ) -> List[MigrationJournalEntry]:
        """Query entries in incomplete / in-flight states that require recovery."""
        cursor = conn.cursor()
        terminal_states = (
            MigrationState.COMMITTED.value,
            MigrationState.BLOCKED_COLLISION.value,
            MigrationState.BLOCKED_MISSING_PARENT.value,
            MigrationState.FAILED_INTEGRITY.value,
        )
        placeholders = ",".join("?" for _ in terminal_states)
        
        if operation_id:
            cursor.execute(
                f"""
                SELECT * FROM migration_journal
                WHERE operation_id = ? AND state NOT IN ({placeholders})
                ORDER BY sequence ASC;
                """,
                (operation_id, *terminal_states),
            )
        else:
            cursor.execute(
                f"""
                SELECT * FROM migration_journal
                WHERE state NOT IN ({placeholders})
                ORDER BY sequence ASC;
                """,
                terminal_states,
            )

        rows = cursor.fetchall()
        return [cls._row_to_entry(cursor, r) for r in rows]

    @classmethod
    def query_undelivered_jsonl_events(
        cls, conn: sqlite3.Connection, operation_id: Optional[str] = None
    ) -> List[MigrationJournalEntry]:
        """Query entries where jsonl_delivered_at IS NULL."""
        cursor = conn.cursor()
        if operation_id:
            cursor.execute(
                """
                SELECT * FROM migration_journal
                WHERE operation_id = ? AND jsonl_delivered_at IS NULL
                ORDER BY sequence ASC;
                """,
                (operation_id,),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM migration_journal
                WHERE jsonl_delivered_at IS NULL
                ORDER BY sequence ASC;
                """
            )
        rows = cursor.fetchall()
        return [cls._row_to_entry(cursor, r) for r in rows]

    @classmethod
    def mark_jsonl_delivered(
        cls, conn: sqlite3.Connection, journal_id: int, delivered_at_iso: str
    ) -> None:
        """Mark event delivered to JSONL outbox with exact rowcount check."""
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE migration_journal
            SET jsonl_delivered_at = ?
            WHERE id = ? AND jsonl_delivered_at IS NULL;
            """,
            (delivered_at_iso, journal_id),
        )
        if cursor.rowcount != 1:
            logger.warning("mark_jsonl_delivered rowcount was %d for journal_id %d", cursor.rowcount, journal_id)

    @staticmethod
    def _row_to_entry(cursor: sqlite3.Cursor, row: Any) -> MigrationJournalEntry:
        """Convert a sqlite3 row tuple into a typed MigrationJournalEntry model."""
        cols = [desc[0] for desc in cursor.description]
        d = dict(zip(cols, row))
        d["state"] = MigrationState(d["state"])
        return MigrationJournalEntry(**d)
