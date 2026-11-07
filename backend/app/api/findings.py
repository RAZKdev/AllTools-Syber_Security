from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel

from app.schemas.common import FindingStatus
from app.schemas.finding import Finding, FindingCreate
from app.repositories.interfaces import IFindingsRepository, IScopeRepository
from app.dependencies import get_findings_repository, get_scope_repository

router = APIRouter(prefix="/findings")


class FindingStatusUpdate(BaseModel):
    status: FindingStatus


@router.get("", response_model=List[Finding])
def list_findings(
    assessment_id: Optional[str] = Query(None, alias="assessmentId"),
    severity: Optional[str] = Query(None),
    confidence: Optional[str] = Query(None),
    findings_repo: IFindingsRepository = Depends(get_findings_repository),
) -> List[Finding]:
    """List findings, optionally filtered by assessment, severity, or confidence."""
    return findings_repo.list_findings(
        assessment_id=assessment_id, severity=severity, confidence=confidence
    )


@router.post("", response_model=Finding, status_code=status.HTTP_201_CREATED)
def create_finding(
    payload: FindingCreate,
    findings_repo: IFindingsRepository = Depends(get_findings_repository),
    scope_repo: IScopeRepository = Depends(get_scope_repository),
) -> Finding:
    """Create a security finding with foreign-key validation on parent assessment."""
    assessment = scope_repo.get_assessment(payload.assessmentId)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Parent assessment '{payload.assessmentId}' not found or is deleted.",
        )
    try:
        return findings_repo.create_finding(payload)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("/{finding_id}", response_model=Finding)
def get_finding(
    finding_id: str,
    findings_repo: IFindingsRepository = Depends(get_findings_repository),
) -> Finding:
    """Retrieve detailed finding by ID."""
    finding = findings_repo.get_finding(finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found.",
        )
    return finding


@router.patch("/{finding_id}/status", response_model=Finding)
def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    findings_repo: IFindingsRepository = Depends(get_findings_repository),
) -> Finding:
    """Update status of a security finding."""
    try:
        return findings_repo.update_finding_status(finding_id, payload.status)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found.",
        )


@router.delete("/{finding_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_finding(
    finding_id: str,
    findings_repo: IFindingsRepository = Depends(get_findings_repository),
) -> Response:
    """Soft-delete a security finding."""
    deleted = findings_repo.soft_delete_finding(finding_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found.",
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
