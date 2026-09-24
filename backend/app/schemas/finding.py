from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field

from app.schemas.common import Confidence, FindingStatus, Severity


class FindingBase(BaseModel):
    assessmentId: str = Field(..., min_length=1)
    assetId: str = Field(..., min_length=1)
    ruleId: Optional[str] = None
    title: str = Field(..., min_length=1)
    description: Optional[str] = None
    status: FindingStatus = Field(default=FindingStatus.NEEDS_REVIEW)
    severity: Severity = Field(default=Severity.MEDIUM)
    confidence: Confidence = Field(default=Confidence.HIGH)
    cwe: Optional[str] = None
    cve: Optional[str] = None
    cvss: Optional[float] = Field(None, ge=0, le=10)
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    createdAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updatedAt: Optional[datetime] = None


class FindingCreate(FindingBase):
    id: Optional[str] = None


class Finding(FindingBase):
    id: str = Field(..., min_length=1)

    model_config = {"extra": "forbid"}
