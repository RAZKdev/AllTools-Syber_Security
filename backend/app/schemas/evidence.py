from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class EvidenceType(str, Enum):
    HTTP_RESPONSE = "http_response"
    SCREENSHOT = "screenshot"
    LOG_EXCERPT = "log_excerpt"
    JSON_RESULT = "json_result"
    FILE = "file"
    CONFIGURATION_SNAPSHOT = "configuration_snapshot"
    HASH = "hash"
    OTHER = "other"


class EvidenceBase(BaseModel):
    assessmentId: str = Field(..., min_length=1)
    findingId: Optional[str] = None
    type: EvidenceType = Field(default=EvidenceType.JSON_RESULT)
    source: Optional[str] = None
    artifactPath: Optional[str] = None
    capturedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sha256: str = Field(..., pattern=r"^[A-Fa-f0-9]{64}$")
    redacted: Optional[bool] = False
    notes: Optional[str] = None


class EvidenceCreate(EvidenceBase):
    id: Optional[str] = None


class Evidence(EvidenceBase):
    id: str = Field(..., min_length=1)

    model_config = {"extra": "forbid"}
