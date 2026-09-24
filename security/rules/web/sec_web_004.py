import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.common import Confidence, ExecutionStatus, FindingStatus, Severity
from security.collectors.cors_collector import CorsCollectorResult


class SecWeb004Rule:
    """
    SEC-WEB-004: CORS Policy & Cross-Origin Resource Sharing Auditor

    Audits CORS response headers for common dangerous misconfigurations:
    1. Insecure wildcard Access-Control-Allow-Origin: * with credentials enabled.
    2. Overly permissive reflection of untrusted request Origin.
    3. Insecure trust of 'null' Origin.
    """

    RULE_ID = "SEC-WEB-004"
    VERSION = "1.0.0"
    TITLE = "Overly Permissive Cross-Origin Resource Sharing (CORS) Policy"
    CWE = "CWE-942"  # Permissive Cross-Domain Policy with Untrusted Domains
    REFERENCES = [
        "https://portswigger.net/web-security/cors",
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
    ]

    def evaluate(
        self,
        assessment_id: str,
        asset_id: str,
        collector_result: CorsCollectorResult,
    ) -> Tuple[ExecutionStatus, Optional[Dict[str, Any]], Optional[Dict[str, Any]], Dict[str, Any]]:
        now = datetime.now(timezone.utc)

        if collector_result.error:
            obs = {
                "id": f"OBS-{uuid.uuid4().hex[:8]}",
                "summary": f"CORS collection failed for {collector_result.target}: {collector_result.error}",
                "details": {"error": collector_result.error},
                "observedAt": now.isoformat(),
            }
            evd = {
                "id": f"EVD-{uuid.uuid4().hex[:8]}",
                "findingId": None,
                "type": "log",
                "source": "CorsCollector",
                "rawContent": collector_result.error,
                "capturedAt": now.isoformat(),
            }
            return ExecutionStatus.ERROR, obs, None, evd

        allow_origin = collector_result.allow_origin
        allow_cred = collector_result.allow_credentials
        tested_origin = collector_result.tested_origin

        obs = {
            "id": f"OBS-{uuid.uuid4().hex[:8]}",
            "summary": (
                f"CORS evaluation on {collector_result.target}: "
                f"Access-Control-Allow-Origin='{allow_origin or 'None'}', "
                f"Access-Control-Allow-Credentials={allow_cred}"
            ),
            "details": {
                "allowOrigin": allow_origin,
                "allowCredentials": allow_cred,
                "allowMethods": collector_result.allow_methods,
                "allowHeaders": collector_result.allow_headers,
                "testedOrigin": tested_origin,
            },
            "observedAt": now.isoformat(),
        }

        finding = None
        raw_evidence = (
            f"Tested Origin: {tested_origin}\n"
            f"Access-Control-Allow-Origin: {allow_origin}\n"
            f"Access-Control-Allow-Credentials: {str(allow_cred).lower()}\n"
            f"Access-Control-Allow-Methods: {collector_result.allow_methods}\n"
            f"Access-Control-Allow-Headers: {collector_result.allow_headers}"
        )

        # 1. Arbitrary reflection of untrusted origin with credentials
        if allow_origin == tested_origin and allow_cred:
            status = ExecutionStatus.FAIL
            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": f"Arbitrary Origin Reflection with Credentials on {collector_result.target}",
                "description": (
                    f"The server dynamically reflects the untrusted request Origin '{tested_origin}' "
                    "in Access-Control-Allow-Origin while also setting Access-Control-Allow-Credentials: true. "
                    "This allows any third-party malicious website to execute authenticated cross-origin API requests."
                ),
                "status": FindingStatus.DETECTED,
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe": self.CWE,
                "cvss": 8.6,
                "impact": "Complete compromise of user session confidentiality; malicious origins can read sensitive authenticated data.",
                "recommendation": (
                    "Implement a strict whitelist of approved origins. Do not blindly reflect the incoming Origin header, "
                    "and avoid setting Access-Control-Allow-Credentials to true unless required for authenticated partners."
                ),
                "createdAt": now.isoformat(),
            }

        # 2. Insecure null origin trust
        elif allow_origin == "null":
            status = ExecutionStatus.FAIL
            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": f"Insecure Trust of 'null' Origin on {collector_result.target}",
                "description": (
                    "The server allows Access-Control-Allow-Origin: null. "
                    "Sandboxed iframes and local file URIs generate a null origin, allowing attackers to bypass CORS controls."
                ),
                "status": FindingStatus.DETECTED,
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe": self.CWE,
                "cvss": 7.5,
                "impact": "Cross-origin data leakage through sandboxed frames or local document contexts.",
                "recommendation": "Remove 'null' from the list of allowed origins.",
                "createdAt": now.isoformat(),
            }

        # 3. Wildcard origin on potential private endpoint
        elif allow_origin == "*":
            status = ExecutionStatus.WARN
            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": f"Wildcard CORS Policy (Access-Control-Allow-Origin: *) on {collector_result.target}",
                "description": (
                    "The server uses a wildcard origin '*'. While appropriate for completely public APIs, "
                    "it may expose internal metadata if applied to authenticated or internal endpoints."
                ),
                "status": FindingStatus.DETECTED,
                "severity": Severity.LOW,
                "confidence": Confidence.MEDIUM,
                "cwe": self.CWE,
                "cvss": 3.7,
                "impact": "Unrestricted cross-origin reading of public responses.",
                "recommendation": "If this endpoint serves private or tenant data, replace '*' with a restricted origin whitelist.",
                "createdAt": now.isoformat(),
            }

        else:
            status = ExecutionStatus.PASS

        evd = {
            "id": f"EVD-{uuid.uuid4().hex[:8]}",
            "findingId": finding["id"] if finding else None,
            "type": "http_response",
            "source": "CorsCollector",
            "rawContent": raw_evidence,
            "capturedAt": now.isoformat(),
        }

        return status, obs, finding, evd
