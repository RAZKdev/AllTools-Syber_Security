from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from app.schemas.assessment import Assessment, AssessmentCreate, AssessmentStatus
from app.schemas.engagement import EngagementStatus
from app.schemas.scope import ScopeItem
from app.repositories.scope_repository import scope_repository

router = APIRouter(prefix="/assessments")


class AssessmentStatusUpdate(BaseModel):
    status: AssessmentStatus
    startedAt: Optional[datetime] = None
    completedAt: Optional[datetime] = None


@router.post("", response_model=Assessment, status_code=status.HTTP_201_CREATED)
def create_assessment(payload: AssessmentCreate) -> Assessment:
    """Create a new security assessment under an engagement."""
    engagement = scope_repository.get_engagement(payload.engagementId)
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Engagement '{payload.engagementId}' not found.",
        )
    return scope_repository.create_assessment(payload)


@router.get("", response_model=List[Assessment])
def list_assessments(engagement_id: Optional[str] = Query(None, alias="engagementId")) -> List[Assessment]:
    """List assessments, optionally filtered by engagementId."""
    return scope_repository.list_assessments(engagement_id=engagement_id)


@router.get("/{assessment_id}", response_model=Assessment)
def get_assessment(assessment_id: str) -> Assessment:
    """Get single assessment details."""
    assessment = scope_repository.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )
    return assessment


@router.get("/{assessment_id}/scope", response_model=List[ScopeItem])
def get_assessment_scope(assessment_id: str) -> List[ScopeItem]:
    """Retrieve all scope items applicable to the given assessment."""
    assessment = scope_repository.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )
    return scope_repository.get_scope_for_assessment(assessment_id)


@router.patch("/{assessment_id}/status", response_model=Assessment)
def update_assessment_status(assessment_id: str, payload: AssessmentStatusUpdate) -> Assessment:
    """Update assessment lifecycle status (e.g. DRAFT -> RUNNING, RUNNING -> COMPLETED)."""
    assessment = scope_repository.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )
    engagement = scope_repository.get_engagement(assessment.engagementId)
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
    return scope_repository.update_assessment_status(
        assessment_id=assessment_id,
        new_status=payload.status,
        started_at=payload.startedAt,
        completed_at=payload.completedAt,
    )
