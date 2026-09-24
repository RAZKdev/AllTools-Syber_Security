from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from app.schemas.evidence import Evidence
from evidence.storage import evidence_store

router = APIRouter(prefix="/evidence")


@router.get("", response_model=List[Evidence])
def list_evidence(
    assessment_id: Optional[str] = Query(None, alias="assessmentId"),
    finding_id: Optional[str] = Query(None, alias="findingId"),
) -> List[Evidence]:
    """List recorded evidence artifacts."""
    if finding_id:
        return evidence_store.list_evidence_for_finding(finding_id)
    if assessment_id:
        return evidence_store.list_evidence_for_assessment(assessment_id)
    return list(evidence_store._evidence_records.values())


@router.get("/{evidence_id}", response_model=Evidence)
def get_evidence(evidence_id: str) -> Evidence:
    """Retrieve evidence metadata by ID."""
    ev = evidence_store.get_evidence(evidence_id)
    if not ev:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence '{evidence_id}' not found.",
        )
    return ev
