import hashlib
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple, Union

from app.core.database import create_connection
from app.repositories.interfaces import IQuarantineRepository
from app.schemas.quarantine import QuarantineItem, QuarantineReason


class SqliteQuarantineRepository(IQuarantineRepository):
    """
    SQLite-backed repository for the cryptographic Quarantine ledger (ADR-02).
    Maintains an immutable sequence with cryptographic SHA-256 hash chaining
    (prev_entry_hash -> entry_hash) across all quarantined artifacts.
    """

    GENESIS_PREV_HASH = "0" * 64

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        self.db_path = db_path

    def _get_connection(self) -> sqlite3.Connection:
        return create_connection(self.db_path)

    @staticmethod
    def _row_to_quarantine_item(row: sqlite3.Row) -> QuarantineItem:
        quarantined_at = (
            datetime.fromisoformat(row["quarantined_at"])
            if isinstance(row["quarantined_at"], str)
            else row["quarantined_at"]
        )
        recovered_at = (
            datetime.fromisoformat(row["recovered_at"])
            if row["recovered_at"]
            else None
        )

        return QuarantineItem(
            seq=row["seq"],
            eventId=row["event_id"],
            quarantineId=row["quarantine_id"],
            originalPath=row["original_path"],
            quarantinePath=row["quarantine_path"],
            sha256=row["sha256"],
            byteSize=row["byte_size"],
            reason=QuarantineReason(row["reason"]),
            details=row["details"],
            prevEntryHash=row["prev_entry_hash"],
            entryHash=row["entry_hash"],
            quarantinedAt=quarantined_at,
            recoveredAt=recovered_at,
            recoveryTargetId=row["recovery_target_id"],
        )

    @classmethod
    def compute_entry_hash(
        cls,
        seq: int,
        prev_entry_hash: str,
        event_id: str,
        quarantine_id: str,
        sha256: str,
        byte_size: int,
        reason: str,
        quarantined_at_str: str,
    ) -> str:
        """Compute tamper-evident cryptographic entry hash linking to preceding ledger block."""
        payload = f"{seq}|{prev_entry_hash}|{event_id}|{quarantine_id}|{sha256}|{byte_size}|{reason}|{quarantined_at_str}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def record_quarantine_item(
        self,
        event_id: str,
        quarantine_id: str,
        original_path: str,
        quarantine_path: str,
        sha256: str,
        byte_size: int,
        reason: str,
        details: Optional[str] = None,
    ) -> QuarantineItem:
        """
        Record a quarantined artifact into the ledger with atomic hash chaining.
        Uses BEGIN IMMEDIATE to prevent race conditions during sequence allocation.
        """
        now = datetime.now(timezone.utc)
        quarantined_at_str = now.isoformat()

        conn = self._get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            # Retrieve last entry in ledger
            last_row = conn.execute(
                "SELECT seq, entry_hash FROM quarantine_items ORDER BY seq DESC LIMIT 1;"
            ).fetchone()

            if last_row is None:
                next_seq = 1
                prev_entry_hash = self.GENESIS_PREV_HASH
            else:
                next_seq = int(last_row["seq"]) + 1
                prev_entry_hash = str(last_row["entry_hash"])

            entry_hash = self.compute_entry_hash(
                seq=next_seq,
                prev_entry_hash=prev_entry_hash,
                event_id=event_id,
                quarantine_id=quarantine_id,
                sha256=sha256,
                byte_size=byte_size,
                reason=reason,
                quarantined_at_str=quarantined_at_str,
            )

            conn.execute(
                """
                INSERT INTO quarantine_items (
                    seq, event_id, quarantine_id, original_path, quarantine_path,
                    sha256, byte_size, reason, details, prev_entry_hash,
                    entry_hash, quarantined_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    next_seq,
                    event_id,
                    quarantine_id,
                    original_path,
                    quarantine_path,
                    sha256,
                    byte_size,
                    reason,
                    details,
                    prev_entry_hash,
                    entry_hash,
                    quarantined_at_str,
                ),
            )
            conn.execute("COMMIT;")

            row = conn.execute(
                "SELECT * FROM quarantine_items WHERE seq = ?;", (next_seq,)
            ).fetchone()
            return self._row_to_quarantine_item(row)
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

    def get_quarantine_item(self, quarantine_id: str) -> Optional[QuarantineItem]:
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM quarantine_items WHERE quarantine_id = ?;",
                (quarantine_id,),
            ).fetchone()
            return self._row_to_quarantine_item(row) if row else None
        finally:
            conn.close()

    def list_quarantine_items(self) -> List[QuarantineItem]:
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM quarantine_items ORDER BY seq ASC;"
            ).fetchall()
            return [self._row_to_quarantine_item(r) for r in rows]
        finally:
            conn.close()

    def get_last_quarantine_entry(self) -> Optional[QuarantineItem]:
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM quarantine_items ORDER BY seq DESC LIMIT 1;"
            ).fetchone()
            return self._row_to_quarantine_item(row) if row else None
        finally:
            conn.close()

    def mark_recovered(self, quarantine_id: str, target_id: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        conn = self._get_connection()
        try:
            cur = conn.execute(
                """
                UPDATE quarantine_items
                SET recovered_at = ?,
                    recovery_target_id = ?
                WHERE quarantine_id = ?;
                """,
                (now, target_id, quarantine_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def verify_ledger_integrity(self) -> Tuple[bool, List[str]]:
        """
        Cryptographically audit the entire quarantine chain.
        Verifies continuous sequence numbering and unbroken hash chain back to genesis.
        """
        items = self.list_quarantine_items()
        errors: List[str] = []

        expected_seq = 1
        expected_prev_hash = self.GENESIS_PREV_HASH

        for item in items:
            if item.seq != expected_seq:
                errors.append(f"Sequence break: expected seq {expected_seq}, found {item.seq}")

            if item.prevEntryHash != expected_prev_hash:
                errors.append(
                    f"Hash chain break at seq {item.seq}: expected prev_hash {expected_prev_hash}, "
                    f"found {item.prevEntryHash}"
                )

            recomputed_hash = self.compute_entry_hash(
                seq=item.seq,
                prev_entry_hash=item.prevEntryHash,
                event_id=item.eventId,
                quarantine_id=item.quarantineId,
                sha256=item.sha256,
                byte_size=item.byteSize,
                reason=item.reason.value if hasattr(item.reason, "value") else str(item.reason),
                quarantined_at_str=item.quarantinedAt.isoformat(),
            )

            if item.entryHash != recomputed_hash:
                errors.append(
                    f"Entry hash corruption at seq {item.seq}: recorded {item.entryHash}, "
                    f"computed {recomputed_hash}"
                )

            expected_seq = item.seq + 1
            expected_prev_hash = item.entryHash

        return (len(errors) == 0, errors)
