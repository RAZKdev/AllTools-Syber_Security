import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.common import Confidence, ExecutionStatus, FindingStatus, Severity
from security.normalizers.http_header_normalizer import HttpHeaderNormalizer
from security.collectors.http_header_collector import HttpHeaderCollectorResult


class SecWeb001Rule:
    """
    SEC-WEB-001: HTTP Security Headers Validation
    
    Inspects HTTP responses for mandatory and recommended defensive security headers:
    1. Content-Security-Policy (CSP)
    2. Strict-Transport-Security (HSTS)
    3. X-Content-Type-Options: nosniff
    4. X-Frame-Options
    5. Referrer-Policy
    """

    RULE_ID = "SEC-WEB-001"
    VERSION = "1.0.0"
    TITLE = "Missing or Weak HTTP Security Headers"
    CWE = "CWE-693"
    REFERENCES = [
        "https://owasp.org/www-project-secure-headers/",
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
    ]

    REQUIRED_HEADERS = {
        "content-security-policy": "Protects against Cross-Site Scripting (XSS) and data injection.",
        "strict-transport-security": "Enforces secure HTTPS transport and protects against downgrade attacks.",
        "x-content-type-options": "Prevents MIME-type sniffing (expected value: 'nosniff').",
        "x-frame-options": "Mitigates clickjacking attacks (expected 'DENY' or 'SAMEORIGIN').",
    }

    RECOMMENDED_HEADERS = {
        "referrer-policy": "Controls how much referrer information is included with requests.",
        "permissions-policy": "Restricts browser feature and API usage.",
    }

    def evaluate(
        self,
        assessment_id: str,
        asset_id: str,
        collector_result: HttpHeaderCollectorResult,
    ) -> Tuple[ExecutionStatus, Optional[Dict[str, Any]], Optional[Dict[str, Any]], Dict[str, Any]]:
        """
        Evaluate headers against defensive security policy.
        
        Returns:
            Tuple of (ExecutionStatus, Optional[Observation], Optional[Finding], Evidence)
        """
        now = datetime.now(timezone.utc)
        headers = HttpHeaderNormalizer.normalize(collector_result.headers)

        missing_required = []
        for header_name, desc in self.REQUIRED_HEADERS.items():
            if header_name not in headers or not headers[header_name]:
                missing_required.append(header_name)

        missing_recommended = []
        for header_name, desc in self.RECOMMENDED_HEADERS.items():
            if header_name not in headers or not headers[header_name]:
                missing_recommended.append(header_name)

        # Header value quality checks
        config_warnings = []
        if "x-content-type-options" in headers and headers["x-content-type-options"] != "nosniff":
            config_warnings.append("x-content-type-options is present but value is not 'nosniff'")

        if "content-security-policy" in headers:
            csp_val = headers["content-security-policy"].lower()
            if "'unsafe-inline'" in csp_val:
                config_warnings.append("Content-Security-Policy contains 'unsafe-inline'")
            if "'unsafe-eval'" in csp_val:
                config_warnings.append("Content-Security-Policy contains 'unsafe-eval'")

        evidence_payload = {
            "id": f"EVD-{uuid.uuid4().hex[:8]}",
            "assessmentId": assessment_id,
            "type": "http_response",
            "source": collector_result.target,
            "capturedAt": collector_result.captured_at.isoformat(),
            "sha256": collector_result.sha256,
            "redacted": False,
            "notes": f"Captured {len(collector_result.headers)} HTTP response headers.",
        }

        # PASS: No missing required headers and no config warnings
        if not missing_required and not config_warnings:
            observation = {
                "id": f"OBS-{uuid.uuid4().hex[:8]}",
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "summary": "All required HTTP security headers are present and configured.",
                "details": {
                    "evaluatedHeaders": list(headers.keys()),
                    "missingRecommended": missing_recommended,
                },
                "observedAt": now.isoformat(),
            }
            return ExecutionStatus.PASS, observation, None, evidence_payload

        # WARN: Only recommended headers missing or minor configuration warning, but required headers exist
        if not missing_required and config_warnings:
            observation = {
                "id": f"OBS-{uuid.uuid4().hex[:8]}",
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "summary": f"HTTP security headers present with warnings: {'; '.join(config_warnings)}",
                "details": {
                    "evaluatedHeaders": list(headers.keys()),
                    "configWarnings": config_warnings,
                },
                "observedAt": now.isoformat(),
            }
            return ExecutionStatus.WARN, observation, None, evidence_payload

        # FAIL: Missing critical required headers -> Generates Finding
        severity = Severity.MEDIUM if len(missing_required) >= 2 else Severity.LOW
        finding_id = f"FND-{uuid.uuid4().hex[:8]}"

        observation = {
            "id": f"OBS-{uuid.uuid4().hex[:8]}",
            "assessmentId": assessment_id,
            "assetId": asset_id,
            "ruleId": self.RULE_ID,
            "summary": f"Target is missing required defensive security headers: {', '.join(missing_required)}.",
            "details": {
                "missingRequired": missing_required,
                "missingRecommended": missing_recommended,
                "configWarnings": config_warnings,
                "observedHeaders": list(headers.keys()),
            },
            "observedAt": now.isoformat(),
        }

        finding = {
            "id": finding_id,
            "assessmentId": assessment_id,
            "assetId": asset_id,
            "ruleId": self.RULE_ID,
            "title": f"Missing Defensive HTTP Security Headers ({len(missing_required)} missing)",
            "description": (
                f"The web service at {collector_result.target} does not return the following recommended "
                f"defensive HTTP security headers: {', '.join(missing_required)}. Without these headers, "
                "the browser client is exposed to avoidable clickjacking, MIME-confusion, or injection risks."
            ),
            "status": FindingStatus.NEEDS_REVIEW.value,
            "severity": severity.value,
            "confidence": Confidence.HIGH.value,
            "cwe": self.CWE,
            "impact": "Clients connecting to this endpoint lack browser-level protections such as HSTS enforcement, XSS filtering, or frame sandboxing.",
            "recommendation": (
                "Configure the web server or reverse proxy to include the missing headers:\n"
                "- Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                "- Content-Security-Policy: default-src 'self'\n"
                "- X-Content-Type-Options: nosniff\n"
                "- X-Frame-Options: DENY\n"
                "- Referrer-Policy: strict-origin-when-cross-origin"
            ),
            "createdAt": now.isoformat(),
        }

        evidence_payload["findingId"] = finding_id
        return ExecutionStatus.FAIL, observation, finding, evidence_payload
