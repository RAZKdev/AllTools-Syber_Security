from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field

from app.schemas.common import ExecutionStatus, ScopeDecision


class CheckExecutionBase(BaseModel):
    assessmentId: str = Field(..., min_length=1)
    ruleId: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    scopeDecision: ScopeDecision
    status: ExecutionStatus
    ruleVersion: Optional[str] = None
    durationMs: Optional[int] = Field(None, ge=0)
    errorCode: Optional[str] = None
    errorMessage: Optional[str] = None
    executedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CheckExecutionCreate(CheckExecutionBase):
    id: Optional[str] = None


class CheckExecution(CheckExecutionBase):
    id: str = Field(..., min_length=1)

    model_config = {"extra": "forbid"}
