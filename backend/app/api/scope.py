from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.schemas.scope import (
    ScopeItem,
    ScopeItemCreate,
    ScopeEvaluationRequest,
    ScopeEvaluationResult,
)
from app.repositories.interfaces import IScopeRepository
from app.dependencies import get_scope_repository
from app.services.scope_guard import ScopeGuard

router = APIRouter(prefix="/scope")
scope_guard = ScopeGuard()


@router.post("/evaluate", response_model=ScopeEvaluationResult)
def evaluate_target(
    payload: ScopeEvaluationRequest,
    repo: IScopeRepository = Depends(get_scope_repository),
) -> ScopeEvaluationResult:
    """
    Evaluate whether a target is permitted under an assessment's authorized scope.
    Fails closed: If target is out of scope or matches an explicit exclusion, decision is BLOCK.
    """
    assessment = repo.get_assessment(payload.assessmentId)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{payload.assessmentId}' not found.",
        )

    scope_items = repo.get_scope_for_assessment(payload.assessmentId)
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
def create_scope_item(
    payload: ScopeItemCreate,
    repo: IScopeRepository = Depends(get_scope_repository),
) -> ScopeItem:
    """Create a new scope item for an engagement."""
    engagement = repo.get_engagement(payload.engagementId)
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Engagement '{payload.engagementId}' not found.",
        )
    return repo.create_scope_item(payload)


@router.get("/items", response_model=List[ScopeItem])
def list_scope_items(
    engagement_id: Optional[str] = Query(None, alias="engagementId"),
    repo: IScopeRepository = Depends(get_scope_repository),
) -> List[ScopeItem]:
    """List non-deleted scope items, optionally filtered by engagementId."""
    return repo.list_scope_items(engagement_id=engagement_id)


@router.delete("/items/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scope_item(
    item_id: str,
    repo: IScopeRepository = Depends(get_scope_repository),
) -> Response:
    """Soft-delete a scope item."""
    item = repo.get_scope_item(item_id)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scope item '{item_id}' not found.",
        )
    repo.soft_delete_scope_item(item_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
