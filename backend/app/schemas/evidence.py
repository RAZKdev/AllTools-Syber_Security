from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class EvidenceType(str, Enum):
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    SCREENSHOT = "screenshot"
    LOG_SNIPPET = "log_snippet"
    LOG_EXCERPT = "log_excerpt"
    RAW_OUTPUT = "raw_output"
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
    syncStatus: str = Field(default="COMMITTED")
    retentionPolicy: str = Field(default="retain_90_days")
    purgeEligibleAt: Optional[datetime] = None
    legalHold: bool = Field(default=False)
    isDeleted: bool = Field(default=False)
    deletedAt: Optional[datetime] = None


class EvidenceCreate(EvidenceBase):
    id: Optional[str] = None


class Evidence(EvidenceBase):
    id: str = Field(..., min_length=1)

    model_config = {"extra": "forbid"}
