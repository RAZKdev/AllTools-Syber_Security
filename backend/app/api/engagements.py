from typing import List
from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel

from app.schemas.engagement import Engagement, EngagementCreate, EngagementStatus
from app.repositories.interfaces import IScopeRepository
from app.dependencies import get_scope_repository

router = APIRouter(prefix="/engagements")


class EngagementStatusUpdate(BaseModel):
    status: EngagementStatus


@router.post("", response_model=Engagement, status_code=status.HTTP_201_CREATED)
def create_engagement(
    payload: EngagementCreate,
    repo: IScopeRepository = Depends(get_scope_repository),
) -> Engagement:
    """Create a new security assessment engagement."""
    return repo.create_engagement(payload)


@router.get("", response_model=List[Engagement])
def list_engagements(
    repo: IScopeRepository = Depends(get_scope_repository),
) -> List[Engagement]:
    """List all registered, non-deleted engagements."""
    return repo.list_engagements()


@router.get("/{engagement_id}", response_model=Engagement)
def get_engagement(
    engagement_id: str,
    repo: IScopeRepository = Depends(get_scope_repository),
) -> Engagement:
    """Get single engagement details."""
    engagement = repo.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Engagement '{engagement_id}' not found.",
        )
    return engagement


@router.patch("/{engagement_id}/status", response_model=Engagement)
def update_engagement_status(
    engagement_id: str,
    payload: EngagementStatusUpdate,
    repo: IScopeRepository = Depends(get_scope_repository),
) -> Engagement:
    """Update engagement lifecycle status."""
    engagement = repo.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Engagement '{engagement_id}' not found.",
        )
    return repo.update_engagement_status(engagement_id, payload.status)


@router.delete("/{engagement_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_engagement(
    engagement_id: str,
    repo: IScopeRepository = Depends(get_scope_repository),
) -> Response:
    """Soft-delete an engagement and its cascaded assessments and scope items."""
    engagement = repo.get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Engagement '{engagement_id}' not found.",
        )
    repo.soft_delete_engagement(engagement_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
