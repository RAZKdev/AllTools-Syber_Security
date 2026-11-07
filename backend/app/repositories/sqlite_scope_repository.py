import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Union

from app.core.database import get_db_connection, transaction
from app.repositories.interfaces import IScopeRepository
from app.schemas.assessment import Assessment, AssessmentCreate, AssessmentStatus, AssessmentType
from app.schemas.engagement import Engagement, EngagementCreate, EngagementStatus
from app.schemas.scope import ScopeItem, ScopeItemCreate, ScopeType


class SqliteScopeRepository(IScopeRepository):
    """SQLite-backed repository for Engagements, Assessments, and Scope Items."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        self.db_path = db_path

    # Helper row parsers
    @staticmethod
    def _row_to_engagement(row: sqlite3.Row) -> Engagement:
        return Engagement(
            id=row["id"],
            workspaceId=row["workspace_id"],
            name=row["name"],
            description=row["description"],
            assessor=row["assessor"],
            status=EngagementStatus(row["status"]),
            startsAt=datetime.fromisoformat(row["starts_at"]) if row["starts_at"] else None,
            endsAt=datetime.fromisoformat(row["ends_at"]) if row["ends_at"] else None,
            rulesOfEngagement=row["rules_of_engagement"],
            createdAt=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
        )

    @staticmethod
    def _row_to_assessment(row: sqlite3.Row) -> Assessment:
        return Assessment(
            id=row["id"],
            engagementId=row["engagement_id"],
            name=row["name"],
            type=AssessmentType(row["type"]) if row["type"] else None,
            status=AssessmentStatus(row["status"]),
            startedAt=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
            completedAt=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
            createdAt=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
        )

    @staticmethod
    def _row_to_scope_item(row: sqlite3.Row) -> ScopeItem:
        return ScopeItem(
            id=row["id"],
            engagementId=row["engagement_id"],
            type=ScopeType(row["type"]),
            value=row["value"],
            environment=row["environment"],
            inScope=bool(row["in_scope"]),
            notes=row["notes"],
            expiresAt=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
        )

    # Engagement Operations
    def create_engagement(self, data: EngagementCreate) -> Engagement:
        engagement_id = data.id or f"ENG-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()
        starts_at = data.startsAt.isoformat() if data.startsAt else None
        ends_at = data.endsAt.isoformat() if data.endsAt else None
        created_at = data.createdAt.isoformat() if data.createdAt else now

        with transaction(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO engagements (
                    id, workspace_id, name, description, assessor, status,
                    starts_at, ends_at, rules_of_engagement, is_deleted, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?);
                """,
                (
                    engagement_id,
                    data.workspaceId,
                    data.name,
                    data.description,
                    data.assessor,
                    data.status.value,
                    starts_at,
                    ends_at,
                    data.rulesOfEngagement,
                    created_at,
                    now,
                ),
            )

        ret = self.get_engagement(engagement_id)
        if not ret:
            raise RuntimeError(f"Failed to retrieve created engagement '{engagement_id}'")
        return ret

    def get_engagement(self, engagement_id: str) -> Optional[Engagement]:
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM engagements WHERE id = ? AND is_deleted = 0;",
                (engagement_id,),
            ).fetchone()
            if not row:
                return None
            return self._row_to_engagement(row)

    def list_engagements(self) -> List[Engagement]:
        with get_db_connection(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM engagements WHERE is_deleted = 0 ORDER BY created_at ASC;"
            ).fetchall()
            return [self._row_to_engagement(r) for r in rows]

    def update_engagement_status(
        self, engagement_id: str, new_status: EngagementStatus
    ) -> Engagement:
        now = datetime.now(timezone.utc).isoformat()
        with transaction(self.db_path) as conn:
            cursor = conn.execute(
                """
                UPDATE engagements
                SET status = ?, updated_at = ?
                WHERE id = ? AND is_deleted = 0;
                """,
                (new_status.value, now, engagement_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(f"Engagement '{engagement_id}' not found.")

        ret = self.get_engagement(engagement_id)
        if not ret:
            raise KeyError(f"Engagement '{engagement_id}' not found.")
        return ret

    def soft_delete_engagement(
        self, engagement_id: str, reason: Optional[str] = None
    ) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with transaction(self.db_path) as conn:
            # Soft delete engagement
            cursor = conn.execute(
                """
                UPDATE engagements
                SET is_deleted = 1, deleted_at = ?, deletion_reason = ?, updated_at = ?
                WHERE id = ? AND is_deleted = 0;
                """,
                (now, reason, now, engagement_id),
            )
            if cursor.rowcount == 0:
                return False

            # Cascade soft deletion to child assessments and scope items
            conn.execute(
                """
                UPDATE assessments
                SET is_deleted = 1, deleted_at = ?, updated_at = ?
                WHERE engagement_id = ? AND is_deleted = 0;
                """,
                (now, now, engagement_id),
            )
            conn.execute(
                """
                UPDATE scope_items
                SET is_deleted = 1, deleted_at = ?, updated_at = ?
                WHERE engagement_id = ? AND is_deleted = 0;
                """,
                (now, now, engagement_id),
            )
            return True

    # Assessment Operations
    def create_assessment(self, data: AssessmentCreate) -> Assessment:
        assessment_id = data.id or f"ASM-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()
        started_at = data.startedAt.isoformat() if data.startedAt else None
        completed_at = data.completedAt.isoformat() if data.completedAt else None
        created_at = data.createdAt.isoformat() if data.createdAt else now

        type_val = data.type.value if data.type else None
        with transaction(self.db_path) as conn:
            # Foreign key check: engagement must exist and not be deleted
            eng_row = conn.execute(
                "SELECT id FROM engagements WHERE id = ? AND is_deleted = 0;",
                (data.engagementId,),
            ).fetchone()
            if not eng_row:
                raise ValueError(
                    f"Referenced engagement '{data.engagementId}' does not exist or is deleted."
                )

            conn.execute(
                """
                INSERT INTO assessments (
                    id, engagement_id, name, type, status, started_at, completed_at,
                    is_deleted, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?);
                """,
                (
                    assessment_id,
                    data.engagementId,
                    data.name,
                    type_val,
                    data.status.value,
                    started_at,
                    completed_at,
                    created_at,
                    now,
                ),
            )

        ret = self.get_assessment(assessment_id)
        if not ret:
            raise RuntimeError(f"Failed to retrieve created assessment '{assessment_id}'")
        return ret

    def get_assessment(self, assessment_id: str) -> Optional[Assessment]:
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM assessments WHERE id = ? AND is_deleted = 0;",
                (assessment_id,),
            ).fetchone()
            if not row:
                return None
            return self._row_to_assessment(row)

    def list_assessments(self, engagement_id: Optional[str] = None) -> List[Assessment]:
        with get_db_connection(self.db_path) as conn:
            if engagement_id:
                rows = conn.execute(
                    """
                    SELECT * FROM assessments
                    WHERE engagement_id = ? AND is_deleted = 0
                    ORDER BY created_at ASC;
                    """,
                    (engagement_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM assessments WHERE is_deleted = 0 ORDER BY created_at ASC;"
                ).fetchall()
            return [self._row_to_assessment(r) for r in rows]

    def update_assessment_status(
        self,
        assessment_id: str,
        new_status: AssessmentStatus,
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
    ) -> Assessment:
        existing = self.get_assessment(assessment_id)
        if not existing:
            raise KeyError(f"Assessment '{assessment_id}' not found.")

        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()

        if new_status == AssessmentStatus.RUNNING and not existing.startedAt:
            started_at = started_at or now_dt
        elif new_status in (
            AssessmentStatus.COMPLETED,
            AssessmentStatus.FAILED,
            AssessmentStatus.CANCELLED,
        ):
            completed_at = completed_at or now_dt

        st_iso = started_at.isoformat() if started_at else (
            existing.startedAt.isoformat() if existing.startedAt else None
        )
        comp_iso = completed_at.isoformat() if completed_at else (
            existing.completedAt.isoformat() if existing.completedAt else None
        )

        with transaction(self.db_path) as conn:
            cursor = conn.execute(
                """
                UPDATE assessments
                SET status = ?, started_at = ?, completed_at = ?, updated_at = ?
                WHERE id = ? AND is_deleted = 0;
                """,
                (new_status.value, st_iso, comp_iso, now_iso, assessment_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(f"Assessment '{assessment_id}' not found.")

        ret = self.get_assessment(assessment_id)
        if not ret:
            raise KeyError(f"Assessment '{assessment_id}' not found.")
        return ret

    def soft_delete_assessment(self, assessment_id: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with transaction(self.db_path) as conn:
            cursor = conn.execute(
                """
                UPDATE assessments
                SET is_deleted = 1, deleted_at = ?, updated_at = ?
                WHERE id = ? AND is_deleted = 0;
                """,
                (now, now, assessment_id),
            )
            return cursor.rowcount > 0

    # Scope Item Operations
    def create_scope_item(self, data: ScopeItemCreate) -> ScopeItem:
        item_id = data.id or f"SCP-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()
        expires_at = data.expiresAt.isoformat() if data.expiresAt else None

        with transaction(self.db_path) as conn:
            # Foreign key check
            eng_row = conn.execute(
                "SELECT id FROM engagements WHERE id = ? AND is_deleted = 0;",
                (data.engagementId,),
            ).fetchone()
            if not eng_row:
                raise ValueError(
                    f"Referenced engagement '{data.engagementId}' does not exist or is deleted."
                )

            conn.execute(
                """
                INSERT INTO scope_items (
                    id, engagement_id, type, value, environment, in_scope, notes,
                    expires_at, is_deleted, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?);
                """,
                (
                    item_id,
                    data.engagementId,
                    data.type.value,
                    data.value,
                    data.environment,
                    1 if data.inScope else 0,
                    data.notes,
                    expires_at,
                    now,
                    now,
                ),
            )

        ret = self.get_scope_item(item_id)
        if not ret:
            raise RuntimeError(f"Failed to retrieve created scope item '{item_id}'")
        return ret

    def get_scope_item(self, item_id: str) -> Optional[ScopeItem]:
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM scope_items WHERE id = ? AND is_deleted = 0;",
                (item_id,),
            ).fetchone()
            if not row:
                return None
            return self._row_to_scope_item(row)

    def list_scope_items(self, engagement_id: Optional[str] = None) -> List[ScopeItem]:
        with get_db_connection(self.db_path) as conn:
            if engagement_id:
                rows = conn.execute(
                    """
                    SELECT * FROM scope_items
                    WHERE engagement_id = ? AND is_deleted = 0
                    ORDER BY created_at ASC;
                    """,
                    (engagement_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scope_items WHERE is_deleted = 0 ORDER BY created_at ASC;"
                ).fetchall()
            return [self._row_to_scope_item(r) for r in rows]

    def get_scope_for_assessment(self, assessment_id: str) -> List[ScopeItem]:
        assessment = self.get_assessment(assessment_id)
        if not assessment:
            return []
        return self.list_scope_items(assessment.engagementId)

    def soft_delete_scope_item(self, item_id: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with transaction(self.db_path) as conn:
            cursor = conn.execute(
                """
                UPDATE scope_items
                SET is_deleted = 1, deleted_at = ?, updated_at = ?
                WHERE id = ? AND is_deleted = 0;
                """,
                (now, now, item_id),
            )
            return cursor.rowcount > 0
