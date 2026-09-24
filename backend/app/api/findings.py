from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from app.schemas.finding import Finding, FindingCreate
from app.repositories.findings_repository import findings_repository

router = APIRouter(prefix="/findings")


@router.get("", response_model=List[Finding])
def list_findings(assessment_id: Optional[str] = Query(None, alias="assessmentId")) -> List[Finding]:
    """List findings, optionally filtered by assessment."""
    return findings_repository.list_findings(assessment_id=assessment_id)


@router.get("/{finding_id}", response_model=Finding)
def get_finding(finding_id: str) -> Finding:
    """Retrieve detailed finding by ID."""
    finding = findings_repository.get_finding(finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found.",
        )
    return finding
