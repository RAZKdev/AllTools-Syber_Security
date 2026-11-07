from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel

from app.schemas.assessment import Assessment, AssessmentCreate, AssessmentStatus
from app.schemas.engagement import EngagementStatus
from app.schemas.scope import ScopeItem
from app.repositories.interfaces import IScopeRepository
from app.dependencies import get_scope_repository

router = APIRouter(prefix="/assessments")


class AssessmentStatusUpdate(BaseModel):
    status: AssessmentStatus
    startedAt: Optional[datetime] = None
    completedAt: Optional[datetime] = None


@router.post("", response_model=Assessment, status_code=status.HTTP_201_CREATED)
def create_assessment(
    payload: AssessmentCreate,
    repo: IScopeRepository = Depends(get_scope_repository),
) -> Assessment:
    """Create a new security assessment under an active engagement."""
    engagement = repo.get_engagement(payload.engagementId)
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Engagement '{payload.engagementId}' not found.",
        )
    return repo.create_assessment(payload)


@router.get("", response_model=List[Assessment])
def list_assessments(
    engagement_id: Optional[str] = Query(None, alias="engagementId"),
    repo: IScopeRepository = Depends(get_scope_repository),
) -> List[Assessment]:
    """List non-deleted assessments, optionally filtered by engagementId."""
    return repo.list_assessments(engagement_id=engagement_id)


@router.get("/{assessment_id}", response_model=Assessment)
def get_assessment(
    assessment_id: str,
    repo: IScopeRepository = Depends(get_scope_repository),
) -> Assessment:
    """Get single assessment details."""
    assessment = repo.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )
    return assessment


@router.get("/{assessment_id}/scope", response_model=List[ScopeItem])
def get_assessment_scope(
    assessment_id: str,
    repo: IScopeRepository = Depends(get_scope_repository),
) -> List[ScopeItem]:
    """Retrieve all scope items applicable to the given assessment."""
    assessment = repo.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )
    return repo.get_scope_for_assessment(assessment_id)


@router.patch("/{assessment_id}/status", response_model=Assessment)
def update_assessment_status(
    assessment_id: str,
    payload: AssessmentStatusUpdate,
    repo: IScopeRepository = Depends(get_scope_repository),
) -> Assessment:
    """Update assessment lifecycle status (e.g. DRAFT -> RUNNING, RUNNING -> COMPLETED)."""
    assessment = repo.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )
    engagement = repo.get_engagement(assessment.engagementId)
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Parent engagement '{assessment.engagementId}' not found.",
        )
    if payload.status == AssessmentStatus.RUNNING and engagement.status != EngagementStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot start assessment '{assessment_id}': Parent engagement '{engagement.id}' is '{engagement.status.value}', must be ACTIVE.",
        )
    return repo.update_assessment_status(
        assessment_id=assessment_id,
        new_status=payload.status,
        started_at=payload.startedAt,
        completed_at=payload.completedAt,
    )


@router.delete("/{assessment_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_assessment(
    assessment_id: str,
    repo: IScopeRepository = Depends(get_scope_repository),
) -> Response:
    """Soft-delete an assessment and its associated items."""
    assessment = repo.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )
    repo.soft_delete_assessment(assessment_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
