import uuid
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.schemas.common import ExecutionStatus, ScopeDecision, FindingStatus
from app.schemas.check_execution import CheckExecution
from app.schemas.finding import FindingCreate
from app.schemas.evidence import EvidenceType
from app.repositories.scope_repository import scope_repository
from app.repositories.findings_repository import findings_repository
from app.services.scope_guard import ScopeGuard
from evidence.storage import evidence_store

from security.collectors.http_header_collector import HttpHeaderCollector
from security.rules.web.sec_web_001 import SecWeb001Rule
from security.collectors.tls_collector import TlsCollector
from security.rules.tls.sec_tls_001 import SecTls001Rule
from security.collectors.dns_collector import DnsCollector
from security.rules.dns.sec_dns_001 import SecDns001Rule

router = APIRouter(prefix="/executions")
scope_guard = ScopeGuard()

# In-memory execution store for local workbench
_executions: Dict[str, CheckExecution] = {}


class PreFlightCheckRequest(BaseModel):
    assessmentId: str = Field(..., min_length=1)
    ruleId: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    ruleVersion: Optional[str] = "1.0.0"


class PreFlightCheckResponse(BaseModel):
    allowed: bool
    executionRecord: CheckExecution
    message: str


class RunCheckRequest(BaseModel):
    assessmentId: str = Field(..., min_length=1)
    assetId: Optional[str] = "AST-001"
    ruleId: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    simulatedData: Optional[Dict[str, Any]] = None


class RunCheckResponse(BaseModel):
    allowed: bool
    executionRecord: CheckExecution
    observation: Optional[Dict[str, Any]] = None
    finding: Optional[Dict[str, Any]] = None
    evidence: Optional[Dict[str, Any]] = None
    message: str


@router.post("/pre-flight", response_model=PreFlightCheckResponse)
def pre_flight_scope_check(payload: PreFlightCheckRequest) -> PreFlightCheckResponse:
    """
    Scope Guard pre-flight check before any security check execution.
    Enforces fail-closed: out-of-scope targets are blocked by default.
    """
    assessment = scope_repository.get_assessment(payload.assessmentId)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{payload.assessmentId}' not found.",
        )

    scope_items = scope_repository.get_scope_for_assessment(payload.assessmentId)
    decision_result = scope_guard.evaluate_target(
        assessment_id=payload.assessmentId,
        target=payload.target,
        scope_items=scope_items,
    )

    execution_id = f"CHK-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)

    if decision_result.is_allowed:
        record = CheckExecution(
            id=execution_id,
            assessmentId=payload.assessmentId,
            ruleId=payload.ruleId,
            target=payload.target,
            scopeDecision=ScopeDecision.ALLOW,
            status=ExecutionStatus.PASS,
            ruleVersion=payload.ruleVersion,
            executedAt=now,
        )
        _executions[execution_id] = record
        return PreFlightCheckResponse(
            allowed=True,
            executionRecord=record,
            message=f"Scope check ALLOWED. Target authorized under scope rule {decision_result.matchedScopeItemId}.",
        )
    else:
        record = CheckExecution(
            id=execution_id,
            assessmentId=payload.assessmentId,
            ruleId=payload.ruleId,
            target=payload.target,
            scopeDecision=ScopeDecision.BLOCK,
            status=ExecutionStatus.BLOCKED_OUT_OF_SCOPE,
            ruleVersion=payload.ruleVersion,
            errorCode="SCOPE_VIOLATION",
            errorMessage=decision_result.reason,
            executedAt=now,
        )
        _executions[execution_id] = record
        return PreFlightCheckResponse(
            allowed=False,
            executionRecord=record,
            message=decision_result.format_scope_block(),
        )


@router.post("/run", response_model=RunCheckResponse)
def run_check(payload: RunCheckRequest) -> RunCheckResponse:
    """
    Run defensive security check with mandatory Scope Guard verification.
    If scope check fails, execution terminates immediately with BLOCKED_OUT_OF_SCOPE.
    """
    assessment = scope_repository.get_assessment(payload.assessmentId)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{payload.assessmentId}' not found.",
        )

    scope_items = scope_repository.get_scope_for_assessment(payload.assessmentId)
    decision = scope_guard.evaluate_target(payload.assessmentId, payload.target, scope_items)

    execution_id = f"CHK-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)

    # If blocked by Scope Guard, fail closed immediately
    if not decision.is_allowed:
        record = CheckExecution(
            id=execution_id,
            assessmentId=payload.assessmentId,
            ruleId=payload.ruleId,
            target=payload.target,
            scopeDecision=ScopeDecision.BLOCK,
            status=ExecutionStatus.BLOCKED_OUT_OF_SCOPE,
            errorCode="SCOPE_VIOLATION",
            errorMessage=decision.reason,
            executedAt=now,
        )
        _executions[execution_id] = record
        return RunCheckResponse(
            allowed=False,
            executionRecord=record,
            message=decision.format_scope_block(),
        )

    # Allowed: Proceed with security rule execution
    start_time = datetime.now(timezone.utc)
    obs = None
    fnd = None
    evd = None
    exec_status = ExecutionStatus.PASS

    try:
        if payload.ruleId == "SEC-WEB-001":
            collector = HttpHeaderCollector()
            if payload.simulatedData:
                collector_res = collector.collect_from_dict(payload.target, payload.simulatedData)
            else:
                # Fallback to local default headers if simulated data is empty
                collector_res = collector.collect_from_dict(
                    payload.target,
                    {"server": "test-workbench", "content-type": "text/html"},
                )
            rule = SecWeb001Rule()
            exec_status, obs, fnd, evd = rule.evaluate(payload.assessmentId, payload.assetId or "AST-001", collector_res)

        elif payload.ruleId == "SEC-TLS-001":
            collector = TlsCollector()
            if payload.simulatedData:
                collector_res = collector.collect_from_dict(payload.target, payload.simulatedData)
            else:
                collector_res = collector.collect_from_dict(
                    payload.target,
                    {
                        "commonName": payload.target,
                        "subjectAltName": [["DNS", payload.target]],
                        "notAfter": "Jan  1 00:00:00 2030 GMT",
                    },
                    tls_version="TLSv1.3",
                )
            rule = SecTls001Rule()
            exec_status, obs, fnd, evd = rule.evaluate(payload.assessmentId, payload.assetId or "AST-001", collector_res)

        elif payload.ruleId == "SEC-DNS-001":
            collector = DnsCollector()
            if payload.simulatedData:
                collector_res = collector.collect_from_dict(payload.target, payload.simulatedData)
            else:
                collector_res = collector.collect_from_dict(
                    payload.target,
                    {
                        "A": ["192.168.1.10"],
                        "TXT": [
                            "v=spf1 -all",
                            f"v=DMARC1; p=reject; rua=mailto:dmarc@{payload.target}",
                        ],
                    },
                )
            rule = SecDns001Rule()
            exec_status, obs, fnd, evd = rule.evaluate(payload.assessmentId, payload.assetId or "AST-001", collector_res)

        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown rule ID '{payload.ruleId}'.",
            )

        duration_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)

        # Store finding if generated
        if fnd:
            findings_repository.create_finding(FindingCreate(**fnd))

        # Store evidence
        if evd:
            evidence_store.record_evidence(
                assessment_id=payload.assessmentId,
                evidence_type=EvidenceType.JSON_RESULT,
                source=payload.target,
                raw_content=evd,
                finding_id=fnd["id"] if fnd else None,
                notes=evd.get("notes"),
            )

        record = CheckExecution(
            id=execution_id,
            assessmentId=payload.assessmentId,
            ruleId=payload.ruleId,
            target=payload.target,
            scopeDecision=ScopeDecision.ALLOW,
            status=exec_status,
            durationMs=duration_ms,
            executedAt=now,
        )
        _executions[execution_id] = record

        return RunCheckResponse(
            allowed=True,
            executionRecord=record,
            observation=obs,
            finding=fnd,
            evidence=evd,
            message=f"Check completed with status {exec_status.value}.",
        )

    except Exception as e:
        record = CheckExecution(
            id=execution_id,
            assessmentId=payload.assessmentId,
            ruleId=payload.ruleId,
            target=payload.target,
            scopeDecision=ScopeDecision.ALLOW,
            status=ExecutionStatus.ERROR,
            errorCode="EXECUTION_ERROR",
            errorMessage=str(e),
            executedAt=now,
        )
        _executions[execution_id] = record
        return RunCheckResponse(
            allowed=True,
            executionRecord=record,
            message=f"Check execution error: {str(e)}",
        )


@router.get("", response_model=List[CheckExecution])
def list_executions(assessment_id: Optional[str] = None) -> List[CheckExecution]:
    """List recorded check executions."""
    if assessment_id:
        return [e for e in _executions.values() if e.assessmentId == assessment_id]
    return list(_executions.values())


@router.get("/{execution_id}", response_model=CheckExecution)
def get_execution(execution_id: str) -> CheckExecution:
    """Get single execution record."""
    exec_record = _executions.get(execution_id)
    if not exec_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Execution record '{execution_id}' not found.",
        )
    return exec_record
