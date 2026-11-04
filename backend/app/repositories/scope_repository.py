from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
import uuid
from app.repositories.interfaces import IScopeRepository
from app.schemas.scope import ScopeItem, ScopeItemCreate, ScopeType
from app.schemas.assessment import Assessment, AssessmentCreate, AssessmentType, AssessmentStatus
from app.schemas.engagement import Engagement, EngagementCreate, EngagementStatus


class InMemoryScopeRepository(IScopeRepository):
    """In-memory repository for engagements, assessments, and scope items."""

    def __init__(self) -> None:
        self._engagements: Dict[str, Engagement] = {}
        self._assessments: Dict[str, Assessment] = {}
        self._scope_items: Dict[str, ScopeItem] = {}
        self._deleted_engagement_ids: Set[str] = set()
        self._deleted_assessment_ids: Set[str] = set()
        self._deleted_scope_ids: Set[str] = set()
        self._seed_defaults()

    def _seed_defaults(self) -> None:
        now = datetime.now(timezone.utc)
        self._engagements["ENG-001"] = Engagement(
            id="ENG-001",
            workspaceId="WKS-001",
            name="Laboratory Defensive Security Assessment",
            description="Default authorized engagement for laboratory evaluation and compliance checks.",
            assessor="Lead Security Assessor",
            status=EngagementStatus.ACTIVE,
            rulesOfEngagement="Defensive evaluation only. Strict adherence to Scope Guard boundary.",
            createdAt=now,
        )
        self._assessments["ASM-001"] = Assessment(
            id="ASM-001",
            engagementId="ENG-001",
            name="Comprehensive Laboratory Assessment",
            type=AssessmentType.GENERAL,
            status=AssessmentStatus.RUNNING,
            startedAt=now,
            createdAt=now,
        )
        self._scope_items["SCP-001"] = ScopeItem(
            id="SCP-001",
            engagementId="ENG-001",
            type=ScopeType.DOMAIN,
            value="lab.local",
            environment="lab",
            inScope=True,
            notes="Default authorized lab domain and subdomains (*.lab.local)",
        )
        self._scope_items["SCP-002"] = ScopeItem(
            id="SCP-002",
            engagementId="ENG-001",
            type=ScopeType.CIDR,
            value="192.168.1.0/24",
            environment="lab",
            inScope=True,
            notes="Internal laboratory test subnet",
        )
        self._scope_items["SCP-003"] = ScopeItem(
            id="SCP-003",
            engagementId="ENG-001",
            type=ScopeType.DOMAIN,
            value="critical.lab.local",
            environment="production",
            inScope=False,
            notes="Explicitly excluded management host (default-deny exclusion test)",
        )

    # Engagement operations
    def create_engagement(self, data: EngagementCreate) -> Engagement:
        engagement_id = data.id or f"ENG-{uuid.uuid4().hex[:8]}"
        engagement = Engagement(
            id=engagement_id,
            workspaceId=data.workspaceId,
            name=data.name,
            description=data.description,
            assessor=data.assessor,
            status=data.status,
            startsAt=data.startsAt,
            endsAt=data.endsAt,
            rulesOfEngagement=data.rulesOfEngagement,
            createdAt=data.createdAt,
        )
        self._engagements[engagement_id] = engagement
        self._deleted_engagement_ids.discard(engagement_id)
        return engagement

    def get_engagement(self, engagement_id: str) -> Optional[Engagement]:
        if engagement_id in self._deleted_engagement_ids:
            return None
        return self._engagements.get(engagement_id)

    def list_engagements(self) -> List[Engagement]:
        return [
            e for eid, e in self._engagements.items()
            if eid not in self._deleted_engagement_ids
        ]

    def update_engagement_status(
        self,
        engagement_id: str,
        new_status: EngagementStatus,
    ) -> Engagement:
        engagement = self.get_engagement(engagement_id)
        if not engagement:
            raise KeyError(f"Engagement '{engagement_id}' not found.")
        updated = Engagement(
            id=engagement.id,
            workspaceId=engagement.workspaceId,
            name=engagement.name,
            description=engagement.description,
            assessor=engagement.assessor,
            status=new_status,
            startsAt=engagement.startsAt,
            endsAt=engagement.endsAt,
            rulesOfEngagement=engagement.rulesOfEngagement,
            createdAt=engagement.createdAt,
        )
        self._engagements[engagement_id] = updated
        return updated

    def soft_delete_engagement(
        self, engagement_id: str, reason: Optional[str] = None
    ) -> bool:
        if engagement_id in self._engagements and engagement_id not in self._deleted_engagement_ids:
            self._deleted_engagement_ids.add(engagement_id)
            # Cascade soft deletion to child assessments and scope items
            for asm_id, asm in self._assessments.items():
                if asm.engagementId == engagement_id:
                    self._deleted_assessment_ids.add(asm_id)
            for scp_id, scp in self._scope_items.items():
                if scp.engagementId == engagement_id:
                    self._deleted_scope_ids.add(scp_id)
            return True
        return False

    # Assessment operations
    def create_assessment(self, data: AssessmentCreate) -> Assessment:
        assessment_id = data.id or f"ASM-{uuid.uuid4().hex[:8]}"
        assessment = Assessment(
            id=assessment_id,
            engagementId=data.engagementId,
            name=data.name,
            type=data.type,
            status=data.status,
            startedAt=data.startedAt,
            completedAt=data.completedAt,
            createdAt=data.createdAt,
        )
        self._assessments[assessment_id] = assessment
        self._deleted_assessment_ids.discard(assessment_id)
        return assessment

    def get_assessment(self, assessment_id: str) -> Optional[Assessment]:
        if assessment_id in self._deleted_assessment_ids:
            return None
        return self._assessments.get(assessment_id)

    def list_assessments(self, engagement_id: Optional[str] = None) -> List[Assessment]:
        results = [
            a for aid, a in self._assessments.items()
            if aid not in self._deleted_assessment_ids
        ]
        if engagement_id:
            return [a for a in results if a.engagementId == engagement_id]
        return results

    def update_assessment_status(
        self,
        assessment_id: str,
        new_status: AssessmentStatus,
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
    ) -> Assessment:
        assessment = self.get_assessment(assessment_id)
        if not assessment:
            raise KeyError(f"Assessment '{assessment_id}' not found.")
        now = datetime.now(timezone.utc)
        if new_status == AssessmentStatus.RUNNING and not assessment.startedAt:
            started_at = started_at or now
        elif new_status in (AssessmentStatus.COMPLETED, AssessmentStatus.FAILED, AssessmentStatus.CANCELLED):
            completed_at = completed_at or now

        updated = Assessment(
            id=assessment.id,
            engagementId=assessment.engagementId,
            name=assessment.name,
            type=assessment.type,
            status=new_status,
            startedAt=started_at or assessment.startedAt,
            completedAt=completed_at or assessment.completedAt,
            createdAt=assessment.createdAt,
        )
        self._assessments[assessment_id] = updated
        return updated

    def soft_delete_assessment(self, assessment_id: str) -> bool:
        if assessment_id in self._assessments and assessment_id not in self._deleted_assessment_ids:
            self._deleted_assessment_ids.add(assessment_id)
            return True
        return False

    # Scope operations
    def create_scope_item(self, data: ScopeItemCreate) -> ScopeItem:
        item_id = data.id or f"SCP-{uuid.uuid4().hex[:8]}"
        item = ScopeItem(
            id=item_id,
            engagementId=data.engagementId,
            type=data.type,
            value=data.value,
            environment=data.environment,
            inScope=data.inScope,
            notes=data.notes,
            expiresAt=data.expiresAt,
        )
        self._scope_items[item_id] = item
        self._deleted_scope_ids.discard(item_id)
        return item

    def get_scope_item(self, item_id: str) -> Optional[ScopeItem]:
        if item_id in self._deleted_scope_ids:
            return None
        return self._scope_items.get(item_id)

    def list_scope_items(self, engagement_id: Optional[str] = None) -> List[ScopeItem]:
        results = [
            s for sid, s in self._scope_items.items()
            if sid not in self._deleted_scope_ids
        ]
        if engagement_id:
            return [s for s in results if s.engagementId == engagement_id]
        return results

    def get_scope_for_assessment(self, assessment_id: str) -> List[ScopeItem]:
        assessment = self.get_assessment(assessment_id)
        if not assessment:
            return []
        return self.list_scope_items(assessment.engagementId)

    def soft_delete_scope_item(self, item_id: str) -> bool:
        if item_id in self._scope_items and item_id not in self._deleted_scope_ids:
            self._deleted_scope_ids.add(item_id)
            return True
        return False


class ScopeRepositoryProxy(IScopeRepository):
    """
    Transparent proxy to the active scope repository provided by dependency injection.
    Maintains 100% backward compatibility for legacy imports while directing all
    operations to the configured SQLite database in production.
    """

    @property
    def _active_repo(self) -> IScopeRepository:
        from app.dependencies import get_scope_repository, get_db_path
        return get_scope_repository(db_path=get_db_path())

    def create_engagement(self, data: EngagementCreate) -> Engagement:
        return self._active_repo.create_engagement(data)

    def get_engagement(self, engagement_id: str) -> Optional[Engagement]:
        return self._active_repo.get_engagement(engagement_id)

    def list_engagements(self) -> List[Engagement]:
        return self._active_repo.list_engagements()

    def update_engagement_status(
        self, engagement_id: str, new_status: EngagementStatus
    ) -> Engagement:
        return self._active_repo.update_engagement_status(engagement_id, new_status)

    def soft_delete_engagement(self, engagement_id: str) -> bool:
        return self._active_repo.soft_delete_engagement(engagement_id)

    def create_assessment(self, data: AssessmentCreate) -> Assessment:
        return self._active_repo.create_assessment(data)

    def get_assessment(self, assessment_id: str) -> Optional[Assessment]:
        return self._active_repo.get_assessment(assessment_id)

    def list_assessments(self, engagement_id: Optional[str] = None) -> List[Assessment]:
        return self._active_repo.list_assessments(engagement_id=engagement_id)

    def update_assessment_status(
        self,
        assessment_id: str,
        new_status: AssessmentStatus,
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
    ) -> Assessment:
        return self._active_repo.update_assessment_status(
            assessment_id, new_status, started_at=started_at, completed_at=completed_at
        )

    def soft_delete_assessment(self, assessment_id: str) -> bool:
        return self._active_repo.soft_delete_assessment(assessment_id)

    def create_scope_item(self, data: ScopeItemCreate) -> ScopeItem:
        return self._active_repo.create_scope_item(data)

    def get_scope_item(self, item_id: str) -> Optional[ScopeItem]:
        return self._active_repo.get_scope_item(item_id)

    def list_scope_items(self, engagement_id: Optional[str] = None) -> List[ScopeItem]:
        return self._active_repo.list_scope_items(engagement_id=engagement_id)

    def get_scope_for_assessment(self, assessment_id: str) -> List[ScopeItem]:
        return self._active_repo.get_scope_for_assessment(assessment_id)

    def soft_delete_scope_item(self, item_id: str) -> bool:
        return self._active_repo.soft_delete_scope_item(item_id)


scope_repository: IScopeRepository = ScopeRepositoryProxy()
