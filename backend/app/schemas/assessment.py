from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class AssessmentType(str, Enum):
    WEB = "web"
    INFRASTRUCTURE = "infrastructure"
    CODE = "code"
    DEPENDENCY = "dependency"
    CONFIGURATION = "configuration"
    LOG = "log"
    INCIDENT = "incident"
    GENERAL = "general"


class AssessmentStatus(str, Enum):
    DRAFT = "draft"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AssessmentBase(BaseModel):
    engagementId: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    type: Optional[AssessmentType] = None
    status: AssessmentStatus = Field(default=AssessmentStatus.DRAFT)
    startedAt: Optional[datetime] = None
    completedAt: Optional[datetime] = None
    createdAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AssessmentCreate(AssessmentBase):
    id: Optional[str] = None


class Assessment(AssessmentBase):
    id: str = Field(..., min_length=1)

    model_config = {"extra": "forbid"}
