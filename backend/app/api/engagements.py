from typing import List
from fastapi import APIRouter, HTTPException, status

from app.schemas.engagement import Engagement, EngagementCreate
from app.repositories.scope_repository import scope_repository

router = APIRouter(prefix="/engagements")


@router.post("", response_model=Engagement, status_code=status.HTTP_201_CREATED)
def create_engagement(payload: EngagementCreate) -> Engagement:
    """Create a new security assessment engagement."""
    return scope_repository.create_engagement(payload)


@router.get("", response_model=List[Engagement])
def list_engagements() -> List[Engagement]:
    """List all registered engagements."""
    return scope_repository.list_engagements()


@router.get("/{engagement_id}", response_model=Engagement)
def get_engagement(engagement_id: str) -> Engagement:
    """Get single engagement details."""
    engagement = scope_repository.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Engagement '{engagement_id}' not found.",
        )
    return engagement
