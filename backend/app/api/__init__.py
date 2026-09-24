from fastapi import APIRouter
from app.api.scope import router as scope_router
from app.api.engagements import router as engagements_router
from app.api.assessments import router as assessments_router
from app.api.executions import router as executions_router
from app.api.findings import router as findings_router
from app.api.evidence import router as evidence_router
from app.api.reports import router as reports_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(engagements_router, tags=["Engagements"])
api_router.include_router(assessments_router, tags=["Assessments"])
api_router.include_router(scope_router, tags=["Scope Guard"])
api_router.include_router(executions_router, tags=["Executions"])
api_router.include_router(findings_router, tags=["Findings"])
api_router.include_router(evidence_router, tags=["Evidence"])
api_router.include_router(reports_router, tags=["Reports"])
