from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class AuditLogBase(BaseModel):
    actorId: Optional[str] = None
    action: str = Field(..., min_length=1)
    objectType: Optional[str] = None
    objectId: Optional[str] = None
    before: Optional[Dict[str, Any]] = None
    after: Optional[Dict[str, Any]] = None
    occurredAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuditLogCreate(AuditLogBase):
    id: Optional[str] = None


class AuditLog(AuditLogBase):
    id: str = Field(..., min_length=1)

    model_config = {"extra": "forbid"}
