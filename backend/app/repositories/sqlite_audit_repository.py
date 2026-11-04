import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Union

from app.core.database import get_db_connection, transaction
from app.repositories.interfaces import IAuditRepository
from app.schemas.audit_log import AuditLog, AuditLogCreate


class SqliteAuditRepository(IAuditRepository):
    """SQLite-backed repository for Structured Operational Audit Logs."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        self.db_path = db_path

    @staticmethod
    def _row_to_audit_log(row: sqlite3.Row) -> AuditLog:
        before = json.loads(row["before_state"]) if row["before_state"] else None
        after = json.loads(row["after_state"]) if row["after_state"] else None
        return AuditLog(
            id=row["id"],
            actorId=row["actor_id"],
            action=row["action"],
            objectType=row["object_type"],
            objectId=row["object_id"],
            before=before,
            after=after,
            occurredAt=datetime.fromisoformat(row["occurred_at"]) if row["occurred_at"] else datetime.now(timezone.utc),
        )

    def record_audit_log(self, data: AuditLogCreate) -> AuditLog:
        log_id = data.id or f"AUD-{uuid.uuid4().hex[:8]}"
        occurred_at = data.occurredAt.isoformat() if data.occurredAt else datetime.now(timezone.utc).isoformat()
        before_str = json.dumps(data.before) if data.before is not None else None
        after_str = json.dumps(data.after) if data.after is not None else None

        with transaction(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (
                    id, actor_id, action, object_type, object_id,
                    before_state, after_state, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    log_id,
                    data.actorId,
                    data.action,
                    data.objectType,
                    data.objectId,
                    before_str,
                    after_str,
                    occurred_at,
                ),
            )

        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM audit_logs WHERE id = ?;", (log_id,)
            ).fetchone()
            if not row:
                raise RuntimeError(f"Failed to retrieve recorded audit log '{log_id}'")
            return self._row_to_audit_log(row)

    def list_audit_logs(self, limit: int = 100, offset: int = 0) -> List[AuditLog]:
        with get_db_connection(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT * FROM audit_logs
                ORDER BY occurred_at DESC
                LIMIT ? OFFSET ?;
                """,
                (limit, offset),
            ).fetchall()
            return [self._row_to_audit_log(r) for r in rows]
