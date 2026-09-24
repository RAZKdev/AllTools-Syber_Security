import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.common import Confidence, ExecutionStatus, FindingStatus, Severity
from security.collectors.http_header_collector import HttpHeaderCollectorResult
from security.normalizers.http_header_normalizer import HttpHeaderNormalizer


class SecWeb003Rule:
    """
    SEC-WEB-003: Server & Technology Information Disclosure Audit

    Audits response headers for technological banners and version fingerprints that
    leak software stack details (e.g., Apache/2.4.49, PHP/7.4.3, Express, ASP.NET).
    """

    RULE_ID = "SEC-WEB-003"
    VERSION = "1.0.0"
    TITLE = "Server Banner and Technology Stack Information Disclosure"
    CWE = "CWE-200"  # Exposure of Sensitive Information to an Unauthorized Actor
    REFERENCES = [
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Server",
        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
    ]

    DISCLOSURE_HEADERS = [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
        "x-runtime",
    ]

    VERSION_PATTERN = re.compile(r"\b(\d+\.\d+(\.\d+)?)\b")

    def evaluate(
        self,
        assessment_id: str,
        asset_id: str,
        collector_result: HttpHeaderCollectorResult,
    ) -> Tuple[ExecutionStatus, Optional[Dict[str, Any]], Optional[Dict[str, Any]], Dict[str, Any]]:
        now = datetime.now(timezone.utc)

        err = getattr(collector_result, "error", None)
        if err:
            obs = {
                "id": f"OBS-{uuid.uuid4().hex[:8]}",
                "summary": f"Header collection failed for {collector_result.target}: {err}",
                "details": {"error": err},
                "observedAt": now.isoformat(),
            }
            evd = {
                "id": f"EVD-{uuid.uuid4().hex[:8]}",
                "findingId": None,
                "type": "log",
                "source": "HttpHeaderCollector",
                "rawContent": str(err),
                "capturedAt": now.isoformat(),
            }
            return ExecutionStatus.ERROR, obs, None, evd

        headers = HttpHeaderNormalizer.normalize(collector_result.headers)

        leaked_headers = {}
        has_version_number = False

        for h in self.DISCLOSURE_HEADERS:
            val = headers.get(h)
            if val:
                leaked_headers[h] = val
                if self.VERSION_PATTERN.search(val):
                    has_version_number = True

        obs = {
            "id": f"OBS-{uuid.uuid4().hex[:8]}",
            "summary": (
                f"Detected {len(leaked_headers)} technology disclosure header(s) on {collector_result.target}."
                if leaked_headers
                else f"No technology banner disclosure headers detected on {collector_result.target}."
            ),
            "details": {
                "leakedHeaders": leaked_headers,
                "versionNumberExposed": has_version_number,
            },
            "observedAt": now.isoformat(),
        }

        finding = None
        raw_evidence = "\n".join([f"{k}: {v}" for k, v in leaked_headers.items()]) or "No disclosure headers found."

        if leaked_headers:
            # If explicit versions (e.g. PHP/7.4.3 or Apache/2.4.29) are exposed, higher severity
            severity = Severity.LOW if not has_version_number else Severity.MEDIUM
            status = ExecutionStatus.WARN

            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": f"Technology Stack Disclosure via HTTP Headers on {collector_result.target}",
                "description": (
                    f"The web server exposes internal stack information via headers: {', '.join(leaked_headers.keys())}. "
                    + ("Explicit version numbers were detected, allowing targeted CVE lookups." if has_version_number else "Software identities are visible.")
                ),
                "status": FindingStatus.DETECTED,
                "severity": severity,
                "confidence": Confidence.HIGH,
                "cwe": self.CWE,
                "cvss": 4.3 if has_version_number else 2.6,
                "impact": "Facilitates reconnaissance by attackers searching for specific unpatched vulnerabilities in the exposed stack.",
                "recommendation": (
                    "Disable or sanitize banner headers in server configurations:\n"
                    "- Nginx: server_tokens off;\n"
                    "- Apache: ServerTokens Prod, ServerSignature Off\n"
                    "- Express.js: app.disable('x-powered-by');\n"
                    "- ASP.NET: <httpRuntime enableVersionHeader=\"false\" />"
                ),
                "createdAt": now.isoformat(),
            }
        else:
            status = ExecutionStatus.PASS

        evd = {
            "id": f"EVD-{uuid.uuid4().hex[:8]}",
            "findingId": finding["id"] if finding else None,
            "type": "http_response",
            "source": "HttpHeaderCollector",
            "rawContent": raw_evidence,
            "capturedAt": now.isoformat(),
        }

        return status, obs, finding, evd
