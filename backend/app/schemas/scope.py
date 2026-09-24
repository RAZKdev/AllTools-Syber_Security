from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

from app.schemas.common import Environment, ScopeDecision


class ScopeType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    CIDR = "cidr"
    HOSTNAME = "hostname"
    URL = "url"
    APPLICATION = "application"
    REPOSITORY = "repository"
    LOG_SOURCE = "log_source"
    FILE_SET = "file_set"


class ScopeItemBase(BaseModel):
    engagementId: str = Field(..., min_length=1, description="Engagement ID this scope item belongs to")
    type: ScopeType = Field(..., description="Target type definition")
    value: str = Field(..., min_length=1, description="Target value or pattern")
    environment: Optional[Environment] = Field(None, description="Environment classification")
    inScope: bool = Field(True, description="True for allowed targets, False for explicit exclusions")
    notes: Optional[str] = Field(None, description="Optional analyst notes")
    expiresAt: Optional[datetime] = Field(None, description="Optional expiration date")


class ScopeItemCreate(ScopeItemBase):
    id: Optional[str] = None


class ScopeItem(ScopeItemBase):
    id: str = Field(..., min_length=1)

    model_config = {"extra": "forbid"}


class ScopeEvaluationRequest(BaseModel):
    assessmentId: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    targetType: Optional[ScopeType] = None


class ScopeEvaluationResult(BaseModel):
    assessmentId: str
    target: str
    decision: ScopeDecision
    reason: str
    matchedScopeItemId: Optional[str] = None
    evaluatedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
