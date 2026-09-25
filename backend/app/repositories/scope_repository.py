from datetime import datetime, timezone
from typing import Dict, List, Optional
import uuid
from app.schemas.scope import ScopeItem, ScopeItemCreate, ScopeType
from app.schemas.assessment import Assessment, AssessmentCreate, AssessmentType, AssessmentStatus
from app.schemas.engagement import Engagement, EngagementCreate, EngagementStatus


class InMemoryScopeRepository:
    """In-memory repository for engagements, assessments, and scope items."""

    def __init__(self) -> None:
        self._engagements: Dict[str, Engagement] = {}
        self._assessments: Dict[str, Assessment] = {}
        self._scope_items: Dict[str, ScopeItem] = {}
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
