from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class QuarantineReason(str, Enum):
    INVALID_JSON = "INVALID_JSON"
    UNKNOWN_SCHEMA = "UNKNOWN_SCHEMA"
    HASH_MISMATCH = "HASH_MISMATCH"
    ORPHAN_NO_ASSESSMENT = "ORPHAN_NO_ASSESSMENT"
    TEST_ARTIFACT = "TEST_ARTIFACT"
    MANUAL_QUARANTINE = "MANUAL_QUARANTINE"
    UNRECORDED_ISOLATED_ARTIFACT = "UNRECORDED_ISOLATED_ARTIFACT"


class QuarantineItemBase(BaseModel):
    eventId: str = Field(..., min_length=1)
    quarantineId: str = Field(..., min_length=1)
    originalPath: str = Field(..., min_length=1)
    quarantinePath: str = Field(..., min_length=1)
    sha256: str = Field(..., pattern=r"^[A-Fa-f0-9]{64}$")
    byteSize: int = Field(..., ge=0)
    reason: QuarantineReason
    details: Optional[str] = None
    prevEntryHash: str = Field(..., min_length=64)
    entryHash: str = Field(..., pattern=r"^[A-Fa-f0-9]{64}$")
    quarantinedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    recoveredAt: Optional[datetime] = None
    recoveryTargetId: Optional[str] = None


class QuarantineItem(QuarantineItemBase):
    seq: int = Field(..., ge=1)

    model_config = {"extra": "forbid"}
