import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.common import Confidence, ExecutionStatus, FindingStatus, Severity
from security.collectors.cookie_collector import CookieCollectorResult


class SecWeb002Rule:
    """
    SEC-WEB-002: Cookie Security Attributes Audit

    Inspects Set-Cookie headers for essential defensive security attributes:
    1. 'Secure' flag - ensures cookie is only transmitted over encrypted HTTPS.
    2. 'HttpOnly' flag - prevents client-side JavaScript access (mitigates XSS cookie theft).
    3. 'SameSite' attribute (Strict/Lax) - mitigates Cross-Site Request Forgery (CSRF).
    """

    RULE_ID = "SEC-WEB-002"
    VERSION = "1.0.0"
    TITLE = "Missing Defensive Cookie Security Flags"
    CWE = "CWE-614"  # Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
    REFERENCES = [
        "https://owasp.org/www-community/controls/SecureCookieAttribute",
        "https://owasp.org/www-community/HttpOnly",
        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies-attributes",
    ]

    def evaluate(
        self,
        assessment_id: str,
        asset_id: str,
        collector_result: CookieCollectorResult,
    ) -> Tuple[ExecutionStatus, Optional[Dict[str, Any]], Optional[Dict[str, Any]], Dict[str, Any]]:
        now = datetime.now(timezone.utc)

        if collector_result.error:
            obs = {
                "id": f"OBS-{uuid.uuid4().hex[:8]}",
                "summary": f"Cookie audit failed for {collector_result.target}: {collector_result.error}",
                "details": {"error": collector_result.error},
                "observedAt": now.isoformat(),
            }
            evd = {
                "id": f"EVD-{uuid.uuid4().hex[:8]}",
                "findingId": None,
                "type": "log",
                "source": "CookieCollector",
                "rawContent": collector_result.error,
                "capturedAt": now.isoformat(),
            }
            return ExecutionStatus.ERROR, obs, None, evd

        cookies = collector_result.cookies
        if not cookies:
            obs = {
                "id": f"OBS-{uuid.uuid4().hex[:8]}",
                "summary": f"No Set-Cookie headers observed on target {collector_result.target}.",
                "details": {"totalCookies": 0},
                "observedAt": now.isoformat(),
            }
            evd = {
                "id": f"EVD-{uuid.uuid4().hex[:8]}",
                "findingId": None,
                "type": "http_response",
                "source": "CookieCollector",
                "rawContent": f"Status: {collector_result.status_code}\nSet-Cookie: None",
                "capturedAt": now.isoformat(),
            }
            return ExecutionStatus.PASS, obs, None, evd

        insecure_cookies = []
        for c in cookies:
            issues = []
            if not c.secure:
                issues.append("Missing 'Secure' flag")
            if not c.http_only:
                issues.append("Missing 'HttpOnly' flag")
            if not c.same_site:
                issues.append("Missing 'SameSite' attribute")
            elif c.same_site.lower() == "none" and not c.secure:
                issues.append("SameSite=None without Secure flag")

            if issues:
                insecure_cookies.append({"cookie": c.name, "issues": issues, "raw": c.raw})

        obs = {
            "id": f"OBS-{uuid.uuid4().hex[:8]}",
            "summary": f"Observed {len(cookies)} cookies, {len(insecure_cookies)} with missing defensive flags.",
            "details": {
                "totalCookies": len(cookies),
                "insecureCount": len(insecure_cookies),
                "insecureCookies": insecure_cookies,
            },
            "observedAt": now.isoformat(),
        }

        raw_evidence = "\n".join([f"Set-Cookie: {c.raw}" for c in cookies])
        finding = None

        if insecure_cookies:
            # If Secure flag is missing on any cookie, mark as HIGH/MEDIUM
            has_insecure_flag = any("Missing 'Secure' flag" in ic["issues"] for ic in insecure_cookies)
            has_httponly_missing = any("Missing 'HttpOnly' flag" in ic["issues"] for ic in insecure_cookies)

            if has_insecure_flag:
                severity = Severity.HIGH
                status = ExecutionStatus.FAIL
            elif has_httponly_missing:
                severity = Severity.MEDIUM
                status = ExecutionStatus.WARN
            else:
                severity = Severity.LOW
                status = ExecutionStatus.WARN

            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": f"Cookies Lacking Security Flags on {collector_result.target}",
                "description": (
                    f"Found {len(insecure_cookies)} cookie(s) missing protective attributes (Secure, HttpOnly, SameSite). "
                    "Cookies transmitted without 'Secure' are susceptible to interception over plaintext channels. "
                    "Cookies without 'HttpOnly' can be read by malicious JavaScript if an XSS flaw exists."
                ),
                "status": FindingStatus.DETECTED,
                "severity": severity,
                "confidence": Confidence.HIGH,
                "cwe": self.CWE,
                "cvss": 6.5 if severity == Severity.HIGH else 4.3,
                "impact": "Session hijacking, credential theft, or unauthorized cross-site actions via CSRF.",
                "recommendation": (
                    "Configure all session and sensitive cookies with:\n"
                    "1. 'Secure' to enforce HTTPS transmission.\n"
                    "2. 'HttpOnly' to prevent access via document.cookie.\n"
                    "3. 'SameSite=Lax' or 'SameSite=Strict' to protect against CSRF attacks."
                ),
                "createdAt": now.isoformat(),
            }
        else:
            status = ExecutionStatus.PASS

        evd = {
            "id": f"EVD-{uuid.uuid4().hex[:8]}",
            "findingId": finding["id"] if finding else None,
            "type": "http_response",
            "source": "CookieCollector",
            "rawContent": raw_evidence,
            "capturedAt": now.isoformat(),
        }

        return status, obs, finding, evd
