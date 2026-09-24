from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class EngagementStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class EngagementBase(BaseModel):
    workspaceId: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    description: Optional[str] = None
    assessor: Optional[str] = None
    status: EngagementStatus = Field(default=EngagementStatus.DRAFT)
    startsAt: Optional[datetime] = None
    endsAt: Optional[datetime] = None
    rulesOfEngagement: Optional[str] = None
    createdAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EngagementCreate(EngagementBase):
    id: Optional[str] = None


class Engagement(EngagementBase):
    id: str = Field(..., min_length=1)

    model_config = {"extra": "forbid"}
