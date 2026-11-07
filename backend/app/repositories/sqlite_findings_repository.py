import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Union

from app.core.database import get_db_connection, transaction
from app.repositories.interfaces import IFindingsRepository
from app.schemas.common import FindingStatus
from app.schemas.finding import Finding, FindingCreate


class SqliteFindingsRepository(IFindingsRepository):
    """SQLite-backed repository for Security Findings."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        self.db_path = db_path

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        return Finding(
            id=row["id"],
            assessmentId=row["assessment_id"],
            assetId=row["asset_id"],
            ruleId=row["rule_id"],
            title=row["title"],
            description=row["description"],
            status=FindingStatus(row["status"]),
            severity=row["severity"],
            confidence=row["confidence"],
            cwe=row["cwe"],
            cve=row["cve"],
            cvss=row["cvss"],
            impact=row["impact"],
            recommendation=row["recommendation"],
            createdAt=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            updatedAt=datetime.fromisoformat(row["updated_at"]) if row["updated_at"] else None,
        )

    def create_finding(self, data: FindingCreate) -> Finding:
        finding_id = data.id or f"FND-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()
        created_at = data.createdAt.isoformat() if data.createdAt else now
        updated_at = data.updatedAt.isoformat() if data.updatedAt else now

        with transaction(self.db_path) as conn:
            # Foreign key check: assessment must exist and not be deleted
            asm_row = conn.execute(
                "SELECT id FROM assessments WHERE id = ? AND is_deleted = 0;",
                (data.assessmentId,),
            ).fetchone()
            if not asm_row:
                raise ValueError(
                    f"Referenced assessment '{data.assessmentId}' does not exist or is deleted."
                )

            status_val = data.status.value if hasattr(data.status, "value") else str(data.status)
            severity_val = data.severity.value if hasattr(data.severity, "value") else str(data.severity)
            confidence_val = data.confidence.value if hasattr(data.confidence, "value") else str(data.confidence)

            conn.execute(
                """
                INSERT INTO findings (
                    id, assessment_id, asset_id, rule_id, title, description,
                    status, severity, confidence, cwe, cve, cvss, impact,
                    recommendation, is_deleted, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?);
                """,
                (
                    finding_id,
                    data.assessmentId,
                    data.assetId,
                    data.ruleId,
                    data.title,
                    data.description,
                    status_val,
                    severity_val,
                    confidence_val,
                    data.cwe,
                    data.cve,
                    data.cvss,
                    data.impact,
                    data.recommendation,
                    created_at,
                    updated_at,
                ),
            )

        ret = self.get_finding(finding_id)
        if not ret:
            raise RuntimeError(f"Failed to retrieve created finding '{finding_id}'")
        return ret

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE id = ? AND is_deleted = 0;",
                (finding_id,),
            ).fetchone()
            if not row:
                return None
            return self._row_to_finding(row)

    def list_findings(
        self,
        assessment_id: Optional[str] = None,
        severity: Optional[str] = None,
        confidence: Optional[str] = None,
    ) -> List[Finding]:
        query = "SELECT * FROM findings WHERE is_deleted = 0"
        params: List[Union[str, int]] = []

        if assessment_id:
            query += " AND assessment_id = ?"
            params.append(assessment_id)
        if severity:
            query += " AND LOWER(severity) = LOWER(?)"
            params.append(severity)
        if confidence:
            query += " AND LOWER(confidence) = LOWER(?)"
            params.append(confidence)

        query += " ORDER BY created_at DESC;"

        with get_db_connection(self.db_path) as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            return [self._row_to_finding(r) for r in rows]

    def update_finding_status(
        self, finding_id: str, new_status: FindingStatus
    ) -> Finding:
        status_val = new_status.value if hasattr(new_status, "value") else str(new_status)
        now = datetime.now(timezone.utc).isoformat()
        with transaction(self.db_path) as conn:
            cursor = conn.execute(
                """
                UPDATE findings
                SET status = ?, updated_at = ?
                WHERE id = ? AND is_deleted = 0;
                """,
                (status_val, now, finding_id),
            )
            if cursor.rowcount == 0:
                raise ValueError(f"Finding '{finding_id}' not found or is deleted.")

        updated = self.get_finding(finding_id)
        if not updated:
            raise RuntimeError(f"Failed to retrieve updated finding '{finding_id}'")
        return updated

    def soft_delete_finding(self, finding_id: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with transaction(self.db_path) as conn:
            cursor = conn.execute(
                """
                UPDATE findings
                SET is_deleted = 1, deleted_at = ?, updated_at = ?
                WHERE id = ? AND is_deleted = 0;
                """,
                (now, now, finding_id),
            )
            return cursor.rowcount > 0
