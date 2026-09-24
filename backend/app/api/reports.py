from fastapi import APIRouter, HTTPException, Response, status
from app.repositories.scope_repository import scope_repository
from app.repositories.findings_repository import findings_repository
from evidence.storage import evidence_store
from reports.generator import SecurityReportGenerator

router = APIRouter(prefix="/reports")


@router.get("/{assessment_id}/markdown", response_class=Response)
def get_markdown_report(assessment_id: str) -> Response:
    """Generate and export audit-grade Markdown security assessment report."""
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
            detail=f"Engagement '{assessment.engagementId}' not found.",
        )

    scope_items = scope_repository.get_scope_for_assessment(assessment_id)
    findings = findings_repository.list_findings(assessment_id=assessment_id)
    evidence_list = evidence_store.list_evidence_for_assessment(assessment_id=assessment_id)

    md_content = SecurityReportGenerator.generate_markdown(
        engagement=engagement,
        assessment=assessment,
        scope_items=scope_items,
        findings=findings,
        evidence_list=evidence_list,
    )

    return Response(
        content=md_content,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f"attachment; filename=report-{assessment_id}.md"
        },
    )


@router.get("/{assessment_id}/html", response_class=Response)
def get_html_report(assessment_id: str) -> Response:
    """Generate and export printable standalone HTML security assessment report."""
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
            detail=f"Engagement '{assessment.engagementId}' not found.",
        )

    scope_items = scope_repository.get_scope_for_assessment(assessment_id)
    findings = findings_repository.list_findings(assessment_id=assessment_id)
    evidence_list = evidence_store.list_evidence_for_assessment(assessment_id=assessment_id)

    html_content = SecurityReportGenerator.generate_html(
        engagement=engagement,
        assessment=assessment,
        scope_items=scope_items,
        findings=findings,
        evidence_list=evidence_list,
    )

    return Response(
        content=html_content,
        media_type="text/html",
        headers={
            "Content-Disposition": f"inline; filename=report-{assessment_id}.html"
        },
    )
