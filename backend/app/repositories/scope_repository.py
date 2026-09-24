from typing import Dict, List, Optional
import uuid
from app.schemas.scope import ScopeItem, ScopeItemCreate
from app.schemas.assessment import Assessment, AssessmentCreate
from app.schemas.engagement import Engagement, EngagementCreate


class InMemoryScopeRepository:
    """In-memory repository for engagements, assessments, and scope items."""

    def __init__(self) -> None:
        self._engagements: Dict[str, Engagement] = {}
        self._assessments: Dict[str, Assessment] = {}
        self._scope_items: Dict[str, ScopeItem] = {}

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
        return engagement

    def get_engagement(self, engagement_id: str) -> Optional[Engagement]:
        return self._engagements.get(engagement_id)

    def list_engagements(self) -> List[Engagement]:
        return list(self._engagements.values())

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
        return assessment

    def get_assessment(self, assessment_id: str) -> Optional[Assessment]:
        return self._assessments.get(assessment_id)

    def list_assessments(self, engagement_id: Optional[str] = None) -> List[Assessment]:
        if engagement_id:
            return [a for a in self._assessments.values() if a.engagementId == engagement_id]
        return list(self._assessments.values())

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
        return item

    def get_scope_item(self, item_id: str) -> Optional[ScopeItem]:
        return self._scope_items.get(item_id)

    def list_scope_items(self, engagement_id: Optional[str] = None) -> List[ScopeItem]:
        if engagement_id:
            return [s for s in self._scope_items.values() if s.engagementId == engagement_id]
        return list(self._scope_items.values())

    def get_scope_for_assessment(self, assessment_id: str) -> List[ScopeItem]:
        assessment = self.get_assessment(assessment_id)
        if not assessment:
            return []
        return self.list_scope_items(assessment.engagementId)


scope_repository = InMemoryScopeRepository()
