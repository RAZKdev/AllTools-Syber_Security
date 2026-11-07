from pathlib import Path
from typing import List, Tuple
from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.core.database import get_db_connection
from app.dependencies import get_db_path
from app.repositories.sqlite_scope_repository import SqliteScopeRepository
from app.repositories.sqlite_findings_repository import SqliteFindingsRepository
from app.repositories.sqlite_execution_repository import SqliteExecutionRepository
from app.repositories.sqlite_evidence_repository import SqliteEvidenceRepository
from app.schemas.assessment import Assessment
from app.schemas.engagement import Engagement
from app.schemas.scope import ScopeItem
from app.schemas.finding import Finding
from app.schemas.check_execution import CheckExecution
from app.schemas.evidence import Evidence
from evidence.storage import evidence_store
from reports.generator import SecurityReportGenerator

router = APIRouter(prefix="/reports")


def fetch_consistent_report_dataset(
    db_path: Path,
    assessment_id: str,
) -> Tuple[Assessment, Engagement, List[ScopeItem], List[Finding], List[CheckExecution], List[Evidence]]:
    """
    Load assessment, parent engagement, scope rules, findings, and check executions
    within a single explicit 'BEGIN DEFERRED' read transaction on the active SQLite database
    to ensure atomic WAL snapshot consistency across all entities.

    Eliminates data tearing between separate table queries.
    Evidence metadata currently reads from the filesystem-backed evidence store
    pending Phase C SQLite evidence table migration.
    """
    with get_db_connection(db_path) as conn:
        conn.execute("BEGIN DEFERRED;")
        try:
            # 1. Assessment
            asm_row = conn.execute(
                "SELECT * FROM assessments WHERE id = ? AND is_deleted = 0;",
                (assessment_id,),
            ).fetchone()
            if not asm_row:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Assessment '{assessment_id}' not found.",
                )
            assessment = SqliteScopeRepository._row_to_assessment(asm_row)

            # 2. Engagement
            eng_row = conn.execute(
                "SELECT * FROM engagements WHERE id = ? AND is_deleted = 0;",
                (assessment.engagementId,),
            ).fetchone()
            if not eng_row:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Engagement '{assessment.engagementId}' not found.",
                )
            engagement = SqliteScopeRepository._row_to_engagement(eng_row)

            # 3. Scope items (ordered newest-first)
            scope_rows = conn.execute(
                "SELECT * FROM scope_items WHERE engagement_id = ? AND is_deleted = 0 ORDER BY created_at DESC;",
                (assessment.engagementId,),
            ).fetchall()
            scope_items = [SqliteScopeRepository._row_to_scope_item(r) for r in scope_rows]

            # 4. Findings (ordered newest-first)
            finding_rows = conn.execute(
                "SELECT * FROM findings WHERE assessment_id = ? AND is_deleted = 0 ORDER BY created_at DESC;",
                (assessment_id,),
            ).fetchall()
            findings = [SqliteFindingsRepository._row_to_finding(r) for r in finding_rows]

            # 5. Check Executions (ordered newest-first)
            exec_rows = conn.execute(
                "SELECT * FROM check_executions WHERE assessment_id = ? ORDER BY executed_at DESC;",
                (assessment_id,),
            ).fetchall()
            executions = [SqliteExecutionRepository._row_to_execution(r) for r in exec_rows]

            # 6. Evidence Metadata (Phase C SQLite Evidence Snapshot)
            evidence_rows = conn.execute(
                "SELECT * FROM evidence WHERE assessment_id = ? AND is_deleted = 0 ORDER BY captured_at DESC;",
                (assessment_id,),
            ).fetchall()
            evidence_list = [SqliteEvidenceRepository._row_to_evidence(r) for r in evidence_rows]

            conn.execute("COMMIT;")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK;")
            raise

    # If no SQLite evidence records found, check fallback in-memory store
    if not evidence_list:
        evidence_list = evidence_store.list_evidence_for_assessment(assessment_id=assessment_id)
    return assessment, engagement, scope_items, findings, executions, evidence_list


@router.get("/{assessment_id}/markdown", response_class=Response)
def get_markdown_report(
    assessment_id: str,
    db_path: Path = Depends(get_db_path),
) -> Response:
    """Generate and export audit-grade Markdown security assessment report from a consistent SQLite snapshot."""
    assessment, engagement, scope_items, findings, executions, evidence_list = fetch_consistent_report_dataset(
        db_path, assessment_id
    )

    md_content = SecurityReportGenerator.generate_markdown(
        engagement=engagement,
        assessment=assessment,
        scope_items=scope_items,
        findings=findings,
        evidence_list=evidence_list,
        executions=executions,
    )

    return Response(
        content=md_content,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f"attachment; filename=report-{assessment_id}.md"
        },
    )


@router.get("/{assessment_id}/html", response_class=Response)
def get_html_report(
    assessment_id: str,
    db_path: Path = Depends(get_db_path),
) -> Response:
    """Generate and export printable standalone HTML security assessment report from a consistent SQLite snapshot."""
    assessment, engagement, scope_items, findings, executions, evidence_list = fetch_consistent_report_dataset(
        db_path, assessment_id
    )

    html_content = SecurityReportGenerator.generate_html(
        engagement=engagement,
        assessment=assessment,
        scope_items=scope_items,
        findings=findings,
        evidence_list=evidence_list,
        executions=executions,
    )

    return Response(
        content=html_content,
        media_type="text/html",
        headers={
            "Content-Disposition": f"inline; filename=report-{assessment_id}.html",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox;",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        },
    )
