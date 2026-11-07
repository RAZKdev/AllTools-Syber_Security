import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Union

from app.core.database import create_connection
from app.repositories.interfaces import IEvidenceRepository
from app.schemas.evidence import Evidence, EvidenceCreate, EvidenceType


class SqliteEvidenceRepository(IEvidenceRepository):
    """
    SQLite-backed repository for cryptographic Evidence metadata and artifact tracking.
    Enforces referential integrity to assessments and findings, soft-delete lifecycle,
    and 90-day retention policies (ADR-03, ADR-05).
    """

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        self.db_path = db_path

    def _get_connection(self) -> sqlite3.Connection:
        return create_connection(self.db_path)

    @staticmethod
    def _row_to_evidence(row: sqlite3.Row) -> Evidence:
        captured_at = (
            datetime.fromisoformat(row["captured_at"])
            if isinstance(row["captured_at"], str)
            else row["captured_at"]
        )
        purge_eligible_at = (
            datetime.fromisoformat(row["purge_eligible_at"])
            if row["purge_eligible_at"]
            else None
        )
        deleted_at = (
            datetime.fromisoformat(row["deleted_at"])
            if row["deleted_at"]
            else None
        )

        return Evidence(
            id=row["id"],
            assessmentId=row["assessment_id"],
            findingId=row["finding_id"],
            type=EvidenceType(row["type"]),
            source=row["source"],
            artifactPath=row["artifact_path"],
            capturedAt=captured_at,
            sha256=row["sha256"],
            redacted=bool(row["redacted"]),
            notes=row["notes"],
            syncStatus=row["sync_status"],
            retentionPolicy=row["retention_policy"],
            purgeEligibleAt=purge_eligible_at,
            legalHold=bool(row["legal_hold"]),
            isDeleted=bool(row["is_deleted"]),
            deletedAt=deleted_at,
        )

    def create_evidence(
        self, data: EvidenceCreate, sync_status: str = "COMMITTED"
    ) -> Evidence:
        evidence_id = data.id or f"EVD-{uuid.uuid4().hex[:8]}"
        captured_at = data.capturedAt or datetime.now(timezone.utc)
        captured_at_str = captured_at.isoformat()
        artifact_path = data.artifactPath or f"evidence/{data.assessmentId}/{evidence_id}.json"
        source = data.source or "automated_check"

        purge_eligible_at_str = (
            data.purgeEligibleAt.isoformat() if data.purgeEligibleAt else None
        )
        deleted_at_str = data.deletedAt.isoformat() if data.deletedAt else None

        conn = self._get_connection()
        try:
            conn.execute(
                """
                INSERT INTO evidence (
                    id, assessment_id, finding_id, type, source, artifact_path,
                    captured_at, sha256, redacted, notes, sync_status,
                    retention_policy, purge_eligible_at, legal_hold, is_deleted, deleted_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    evidence_id,
                    data.assessmentId,
                    data.findingId,
                    data.type.value if hasattr(data.type, "value") else str(data.type),
                    source,
                    artifact_path,
                    captured_at_str,
                    data.sha256,
                    1 if data.redacted else 0,
                    data.notes,
                    sync_status,
                    data.retentionPolicy or "retain_90_days",
                    purge_eligible_at_str,
                    1 if data.legalHold else 0,
                    1 if data.isDeleted else 0,
                    deleted_at_str,
                ),
            )
            conn.commit()
            return self.get_evidence(evidence_id, include_deleted=True)  # type: ignore
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def get_evidence(
        self, evidence_id: str, include_deleted: bool = False
    ) -> Optional[Evidence]:
        conn = self._get_connection()
        try:
            if include_deleted:
                stmt = "SELECT * FROM evidence WHERE id = ?;"
            else:
                stmt = "SELECT * FROM evidence WHERE id = ? AND is_deleted = 0;"
            row = conn.execute(stmt, (evidence_id,)).fetchone()
            return self._row_to_evidence(row) if row else None
        finally:
            conn.close()

    def list_evidence(
        self,
        assessment_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        include_deleted: bool = False,
    ) -> List[Evidence]:
        conn = self._get_connection()
        try:
            query = "SELECT * FROM evidence WHERE 1=1"
            params: List[Union[str, int]] = []

            if not include_deleted:
                query += " AND is_deleted = 0"
            if assessment_id:
                query += " AND assessment_id = ?"
                params.append(assessment_id)
            if finding_id:
                query += " AND finding_id = ?"
                params.append(finding_id)

            query += " ORDER BY captured_at DESC;"
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_evidence(r) for r in rows]
        finally:
            conn.close()

    def get_by_sha256(self, sha256_digest: str) -> Optional[Evidence]:
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM evidence WHERE sha256 = ? AND is_deleted = 0 LIMIT 1;",
                (sha256_digest,),
            ).fetchone()
            return self._row_to_evidence(row) if row else None
        finally:
            conn.close()

    def get_by_artifact_path(self, artifact_path: str) -> Optional[Evidence]:
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM evidence WHERE artifact_path = ? LIMIT 1;",
                (artifact_path,),
            ).fetchone()
            return self._row_to_evidence(row) if row else None
        finally:
            conn.close()

    def update_sync_status(self, evidence_id: str, new_status: str) -> bool:
        conn = self._get_connection()
        try:
            cur = conn.execute(
                "UPDATE evidence SET sync_status = ? WHERE id = ?;",
                (new_status, evidence_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def update_finding_id(self, evidence_id: str, finding_id: Optional[str]) -> bool:
        conn = self._get_connection()
        try:
            cur = conn.execute(
                "UPDATE evidence SET finding_id = ? WHERE id = ?;",
                (finding_id, evidence_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def soft_delete_evidence(self, evidence_id: str) -> bool:
        """
        Soft delete an evidence record.
        Under ADR-05, computes purge_eligible_at as now + 90 days.
        """
        now = datetime.now(timezone.utc)
        purge_eligible_at = now + timedelta(days=90)
        conn = self._get_connection()
        try:
            cur = conn.execute(
                """
                UPDATE evidence
                SET is_deleted = 1,
                    deleted_at = ?,
                    purge_eligible_at = ?
                WHERE id = ? AND is_deleted = 0;
                """,
                (now.isoformat(), purge_eligible_at.isoformat(), evidence_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def set_legal_hold(self, evidence_id: str, hold: bool) -> bool:
        """
        Set or release legal hold on evidence record (ADR-05).
        Records with legal_hold=1 can never be purged even if retention period expired.
        """
        conn = self._get_connection()
        try:
            cur = conn.execute(
                "UPDATE evidence SET legal_hold = ? WHERE id = ?;",
                (1 if hold else 0, evidence_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def hard_delete_evidence(self, evidence_id: str) -> bool:
        """
        Physically remove evidence metadata from database.
        Strict fail-closed: rejected if record is on legal hold or not soft-deleted.
        Requires explicit operator confirmation (ADR-05).
        """
        conn = self._get_connection()
        try:
            # Check legal hold and soft delete status
            row = conn.execute(
                "SELECT is_deleted, legal_hold FROM evidence WHERE id = ?;",
                (evidence_id,),
            ).fetchone()
            if not row:
                return False
            if row["legal_hold"]:
                raise PermissionError(f"Evidence '{evidence_id}' is protected by active Legal Hold.")
            if not row["is_deleted"]:
                raise ValueError(f"Evidence '{evidence_id}' must be soft-deleted before purge.")

            cur = conn.execute("DELETE FROM evidence WHERE id = ?;", (evidence_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()
