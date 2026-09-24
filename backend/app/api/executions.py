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

# Collectors
from security.collectors.http_header_collector import HttpHeaderCollector
from security.collectors.tls_collector import TlsCollector
from security.collectors.dns_collector import DnsCollector
from security.collectors.cookie_collector import CookieCollector
from security.collectors.cors_collector import CorsCollector
from security.collectors.sensitive_file_collector import SensitiveFileCollector
from security.collectors.port_collector import PortCollector

# Rules
from security.rules.web.sec_web_001 import SecWeb001Rule
from security.rules.tls.sec_tls_001 import SecTls001Rule
from security.rules.dns.sec_dns_001 import SecDns001Rule
from security.rules.web.sec_web_002 import SecWeb002Rule
from security.rules.web.sec_web_003 import SecWeb003Rule
from security.rules.web.sec_web_004 import SecWeb004Rule
from security.rules.web.sec_web_005 import SecWeb005Rule
from security.rules.dns.sec_dns_002 import SecDns002Rule
from security.rules.net.sec_net_001 import SecNet001Rule
from security.rules.crypto.sec_crypto_001 import SecCrypto001Rule
from security.rules.auth.sec_auth_001 import SecAuth001Rule

router = APIRouter(prefix="/executions")
scope_guard = ScopeGuard()

# In-memory execution store for local workbench
_executions: Dict[str, CheckExecution] = {}

AVAILABLE_RULES_METADATA = [
    {
        "ruleId": "SEC-WEB-001",
        "title": "HTTP Defensive Security Headers Audit",
        "category": "Web Security",
        "cwe": "CWE-693",
        "description": "Validates mandatory defensive headers: HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy.",
    },
    {
        "ruleId": "SEC-TLS-001",
        "title": "TLS/SSL Certificate & Cipher Version Inspector",
        "category": "Transport Security",
        "cwe": "CWE-295",
        "description": "Audits certificate validity, SAN/CN matching, expiration grace period, and deprecated protocols.",
    },
    {
        "ruleId": "SEC-DNS-001",
        "title": "DNS Email Security & Anti-Spoofing (SPF/DMARC)",
        "category": "DNS & Email",
        "cwe": "CWE-290",
        "description": "Verifies SPF records and DMARC enforcement policies preventing domain email spoofing.",
    },
    {
        "ruleId": "SEC-WEB-002",
        "title": "Cookie Defensive Security Attributes Audit",
        "category": "Web Security",
        "cwe": "CWE-614",
        "description": "Audits Set-Cookie headers for Secure, HttpOnly, and SameSite attributes to prevent session theft.",
    },
    {
        "ruleId": "SEC-WEB-003",
        "title": "Server Banner & Tech Stack Disclosure Audit",
        "category": "Information Disclosure",
        "cwe": "CWE-200",
        "description": "Detects leaking server tokens, framework headers (X-Powered-By), and version fingerprints.",
    },
    {
        "ruleId": "SEC-WEB-004",
        "title": "CORS Policy & Access-Control Auditor",
        "category": "Web Security",
        "cwe": "CWE-942",
        "description": "Audits CORS headers for dangerous wildcard origins with credentials, null origins, and reflection.",
    },
    {
        "ruleId": "SEC-WEB-005",
        "title": "Sensitive Files & RFC 9116 security.txt Audit",
        "category": "Configuration Hygiene",
        "cwe": "CWE-538",
        "description": "Checks for accidental exposure of .git/.env and validates security.txt disclosure compliance.",
    },
    {
        "ruleId": "SEC-DNS-002",
        "title": "DNS CAA (Certification Authority Authorization) Audit",
        "category": "DNS & Email",
        "cwe": "CWE-295",
        "description": "Verifies DNS CAA records restricting which CAs are permitted to issue certificates.",
    },
    {
        "ruleId": "SEC-NET-001",
        "title": "Authorized Port & Critical Service Exposure Audit",
        "category": "Network Security",
        "cwe": "CWE-284",
        "description": "Probes common sensitive ports (Telnet, FTP, MySQL, Redis, MongoDB, RDP) for unintended exposure.",
    },
    {
        "ruleId": "SEC-CRYPTO-001",
        "title": "Cryptographic Hash Algorithm Strength Analyzer",
        "category": "Cryptography",
        "cwe": "CWE-327",
        "description": "Evaluates hash collision resistance: flags weak MD5/SHA-1 vs strong SHA-256/SHA-512/bcrypt/Argon2.",
    },
    {
        "ruleId": "SEC-AUTH-001",
        "title": "Password Policy & Entropy Compliance Auditor",
        "category": "Identity & Auth",
        "cwe": "CWE-521",
        "description": "Audits password sample complexity, Shannon entropy, and dictionary weaknesses against NIST SP 800-63B.",
    },
]


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


@router.get("/rules")
def get_available_rules():
    """List all available defensive security audit tools/rules."""
    return AVAILABLE_RULES_METADATA


@router.post("/pre-flight", response_model=PreFlightCheckResponse)
def pre_flight_check(payload: PreFlightCheckRequest) -> PreFlightCheckResponse:
    """Pre-flight check verifying target is within authorized scope."""
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
        return PreFlightCheckResponse(
            allowed=False,
            executionRecord=record,
            message=decision.format_scope_block(),
        )

    record = CheckExecution(
        id=execution_id,
        assessmentId=payload.assessmentId,
        ruleId=payload.ruleId,
        target=payload.target,
        scopeDecision=ScopeDecision.ALLOW,
        status=ExecutionStatus.PASS,
        executedAt=now,
    )
    _executions[execution_id] = record
    return PreFlightCheckResponse(
        allowed=True,
        executionRecord=record,
        message=f"Target '{payload.target}' is authorized and within scope.",
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
        # 1. SEC-WEB-001: HTTP Security Headers
        if payload.ruleId == "SEC-WEB-001":
            collector = HttpHeaderCollector()
            if payload.simulatedData:
                collector_res = collector.collect_from_dict(payload.target, payload.simulatedData)
            else:
                collector_res = collector.collect_from_dict(
                    payload.target,
                    {"server": "test-workbench", "content-type": "text/html"},
                )
            rule = SecWeb001Rule()
            exec_status, obs, fnd, evd = rule.evaluate(payload.assessmentId, payload.assetId or "AST-001", collector_res)

        # 2. SEC-TLS-001: TLS Certificate & Protocol
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

        # 3. SEC-DNS-001: DNS Email Security (SPF/DMARC)
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

        # 4. SEC-WEB-002: Cookie Security Attributes
        elif payload.ruleId == "SEC-WEB-002":
            collector = CookieCollector()
            if payload.simulatedData:
                collector_res = collector.collect_from_dict(payload.target, payload.simulatedData)
            else:
                collector_res = collector.collect_from_dict(
                    payload.target,
                    {"setCookie": ["session_id=xyz; Secure; HttpOnly; SameSite=Strict"]},
                )
            rule = SecWeb002Rule()
            exec_status, obs, fnd, evd = rule.evaluate(payload.assessmentId, payload.assetId or "AST-001", collector_res)

        # 5. SEC-WEB-003: Server Banner Disclosure
        elif payload.ruleId == "SEC-WEB-003":
            collector = HttpHeaderCollector()
            if payload.simulatedData:
                collector_res = collector.collect_from_dict(payload.target, payload.simulatedData)
            else:
                collector_res = collector.collect_from_dict(
                    payload.target,
                    {"server": "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.4.3"},
                )
            rule = SecWeb003Rule()
            exec_status, obs, fnd, evd = rule.evaluate(payload.assessmentId, payload.assetId or "AST-001", collector_res)

        # 6. SEC-WEB-004: CORS Misconfiguration
        elif payload.ruleId == "SEC-WEB-004":
            collector = CorsCollector()
            if payload.simulatedData:
                collector_res = collector.collect_from_dict(payload.target, payload.simulatedData)
            else:
                collector_res = collector.collect_from_dict(
                    payload.target,
                    {
                        "headers": {
                            "access-control-allow-origin": "https://untrusted-origin.example.com",
                            "access-control-allow-credentials": "true",
                        }
                    },
                )
            rule = SecWeb004Rule()
            exec_status, obs, fnd, evd = rule.evaluate(payload.assessmentId, payload.assetId or "AST-001", collector_res)

        # 7. SEC-WEB-005: Sensitive Files & security.txt
        elif payload.ruleId == "SEC-WEB-005":
            collector = SensitiveFileCollector()
            if payload.simulatedData:
                collector_res = collector.collect_from_dict(payload.target, payload.simulatedData)
            else:
                collector_res = collector.collect_from_dict(
                    payload.target,
                    {
                        "paths": {
                            "/.well-known/security.txt": {"statusCode": 200, "accessible": True, "snippet": "Contact: mailto:security@lab.local"},
                            "/.git/HEAD": {"statusCode": 404, "accessible": False},
                            "/.env": {"statusCode": 404, "accessible": False},
                        }
                    },
                )
            rule = SecWeb005Rule()
            exec_status, obs, fnd, evd = rule.evaluate(payload.assessmentId, payload.assetId or "AST-001", collector_res)

        # 8. SEC-DNS-002: DNS CAA Record Verification
        elif payload.ruleId == "SEC-DNS-002":
            collector = DnsCollector()
            if payload.simulatedData:
                collector_res = collector.collect_from_dict(payload.target, payload.simulatedData)
            else:
                collector_res = collector.collect_from_dict(
                    payload.target,
                    {"CAA": ["0 issue \"letsencrypt.org\"", f"0 iodef \"mailto:security@{payload.target}\""]},
                )
            rule = SecDns002Rule()
            exec_status, obs, fnd, evd = rule.evaluate(payload.assessmentId, payload.assetId or "AST-001", collector_res)

        # 9. SEC-NET-001: Authorized Port Exposure
        elif payload.ruleId == "SEC-NET-001":
            collector = PortCollector()
            if payload.simulatedData:
                collector_res = collector.collect_from_dict(payload.target, payload.simulatedData)
            else:
                collector_res = collector.collect_from_dict(
                    payload.target,
                    {
                        "resolvedIp": "192.168.1.50",
                        "openPorts": [80, 443],
                        "closedPorts": [21, 23, 25, 3306, 5432, 6379, 27017, 3389],
                    },
                )
            rule = SecNet001Rule()
            exec_status, obs, fnd, evd = rule.evaluate(payload.assessmentId, payload.assetId or "AST-001", collector_res)

        # 10. SEC-CRYPTO-001: Hash Algorithm Strength
        elif payload.ruleId == "SEC-CRYPTO-001":
            hash_sample = (payload.simulatedData or {}).get("hash", payload.target)
            rule = SecCrypto001Rule()
            exec_status, obs, fnd, evd = rule.evaluate(payload.assessmentId, payload.assetId or "AST-001", hash_sample)

        # 11. SEC-AUTH-001: Password Policy & Entropy
        elif payload.ruleId == "SEC-AUTH-001":
            password_sample = (payload.simulatedData or {}).get("password", payload.target)
            rule = SecAuth001Rule()
            exec_status, obs, fnd, evd = rule.evaluate(payload.assessmentId, payload.assetId or "AST-001", password_sample)

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
