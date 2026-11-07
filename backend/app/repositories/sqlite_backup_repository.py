import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Union

from app.core.database import create_connection
from app.repositories.interfaces import IBackupRepository
from app.schemas.backup import BackupSnapshot, BackupStatus


class SqliteBackupRepository(IBackupRepository):
    """
    SQLite-backed repository for Hot Backup metadata and snapshot lifecycle tracking (ADR-06).
    """

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        self.db_path = db_path

    def _get_connection(self) -> sqlite3.Connection:
        return create_connection(self.db_path)

    @staticmethod
    def _row_to_snapshot(row: sqlite3.Row) -> BackupSnapshot:
        created_at = (
            datetime.fromisoformat(row["created_at"])
            if isinstance(row["created_at"], str)
            else row["created_at"]
        )
        return BackupSnapshot(
            id=row["id"],
            createdAt=created_at,
            sqliteDataVersion=row["sqlite_data_version"],
            evidenceCount=row["evidence_count"],
            quarantineCount=row["quarantine_count"],
            manifestSha256=row["manifest_sha256"],
            byteSize=row["byte_size"],
            status=BackupStatus(row["status"]),
        )

    def record_backup_started(
        self, generation_id: str, sqlite_data_version: int
    ) -> BackupSnapshot:
        now_str = datetime.now(timezone.utc).isoformat()
        conn = self._get_connection()
        try:
            conn.execute(
                """
                INSERT INTO backup_snapshots (
                    id, created_at, sqlite_data_version, evidence_count,
                    quarantine_count, manifest_sha256, byte_size, status
                ) VALUES (?, ?, ?, 0, 0, '', 0, 'IN_PROGRESS');
                """,
                (generation_id, now_str, sqlite_data_version),
            )
            conn.commit()
            return self.get_backup(generation_id)  # type: ignore
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def record_backup_completed(
        self,
        generation_id: str,
        manifest_sha256: str,
        byte_size: int,
        evidence_count: int,
        quarantine_count: int,
    ) -> BackupSnapshot:
        conn = self._get_connection()
        try:
            conn.execute(
                """
                UPDATE backup_snapshots
                SET manifest_sha256 = ?,
                    byte_size = ?,
                    evidence_count = ?,
                    quarantine_count = ?,
                    status = 'COMPLETED'
                WHERE id = ?;
                """,
                (manifest_sha256, byte_size, evidence_count, quarantine_count, generation_id),
            )
            conn.commit()
            return self.get_backup(generation_id)  # type: ignore
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def record_backup_failed(self, generation_id: str) -> bool:
        conn = self._get_connection()
        try:
            cur = conn.execute(
                "UPDATE backup_snapshots SET status = 'FAILED' WHERE id = ?;",
                (generation_id,),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def get_backup(self, generation_id: str) -> Optional[BackupSnapshot]:
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM backup_snapshots WHERE id = ?;",
                (generation_id,),
            ).fetchone()
            return self._row_to_snapshot(row) if row else None
        finally:
            conn.close()

    def list_backups(
        self, status: Optional[BackupStatus] = None
    ) -> List[BackupSnapshot]:
        conn = self._get_connection()
        try:
            if status is not None:
                status_val = status.value if hasattr(status, "value") else str(status)
                rows = conn.execute(
                    "SELECT * FROM backup_snapshots WHERE status = ? ORDER BY created_at DESC;",
                    (status_val,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM backup_snapshots ORDER BY created_at DESC;"
                ).fetchall()
            return [self._row_to_snapshot(r) for r in rows]
        finally:
            conn.close()

    def get_last_known_good_backup(self) -> Optional[BackupSnapshot]:
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM backup_snapshots WHERE status = 'COMPLETED' ORDER BY created_at DESC LIMIT 1;"
            ).fetchone()
            return self._row_to_snapshot(row) if row else None
        finally:
            conn.close()

    def delete_backup_record(self, generation_id: str) -> bool:
        conn = self._get_connection()
        try:
            cur = conn.execute(
                "DELETE FROM backup_snapshots WHERE id = ?;", (generation_id,)
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()
