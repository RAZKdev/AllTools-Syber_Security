from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from app.schemas.scope import (
    ScopeItem,
    ScopeItemCreate,
    ScopeEvaluationRequest,
    ScopeEvaluationResult,
)
from app.repositories.scope_repository import scope_repository
from app.services.scope_guard import ScopeGuard

router = APIRouter(prefix="/scope")
scope_guard = ScopeGuard()


@router.post("/evaluate", response_model=ScopeEvaluationResult)
def evaluate_target(payload: ScopeEvaluationRequest) -> ScopeEvaluationResult:
    """
    Evaluate whether a target is permitted under an assessment's authorized scope.
    Fails closed: If target is out of scope or matches an explicit exclusion, decision is BLOCK.
    """
    assessment = scope_repository.get_assessment(payload.assessmentId)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{payload.assessmentId}' not found.",
        )

    scope_items = scope_repository.get_scope_for_assessment(payload.assessmentId)
    result = scope_guard.evaluate_target(
        assessment_id=payload.assessmentId,
        target=payload.target,
        scope_items=scope_items,
        target_type=payload.targetType,
    )
    return ScopeEvaluationResult(
        assessmentId=result.assessmentId,
        target=result.target,
        decision=result.decision,
        reason=result.reason,
        matchedScopeItemId=result.matchedScopeItemId,
        evaluatedAt=result.evaluatedAt,
    )


@router.post("/items", response_model=ScopeItem, status_code=status.HTTP_201_CREATED)
def create_scope_item(payload: ScopeItemCreate) -> ScopeItem:
    """Create a new scope item for an engagement."""
    engagement = scope_repository.get_engagement(payload.engagementId)
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Engagement '{payload.engagementId}' not found.",
        )
    return scope_repository.create_scope_item(payload)


@router.get("/items", response_model=List[ScopeItem])
def list_scope_items(engagement_id: Optional[str] = Query(None, alias="engagementId")) -> List[ScopeItem]:
    """List scope items, optionally filtered by engagementId."""
    return scope_repository.list_scope_items(engagement_id=engagement_id)
