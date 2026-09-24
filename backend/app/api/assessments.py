from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from app.schemas.assessment import Assessment, AssessmentCreate
from app.schemas.scope import ScopeItem
from app.repositories.scope_repository import scope_repository

router = APIRouter(prefix="/assessments")


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
