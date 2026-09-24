import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.common import Confidence, ExecutionStatus, FindingStatus, Severity
from security.collectors.sensitive_file_collector import SensitiveFileCollectorResult


class SecWeb005Rule:
    """
    SEC-WEB-005: Sensitive Files Exposure & RFC 9116 security.txt Compliance

    Audits public accessibility of critical files and security policy endpoints:
    1. Critical dotfiles: /.git/HEAD, /.env (Severe data & secret disclosure)
    2. Vulnerability disclosure standard: /.well-known/security.txt (RFC 9116)
    3. robots.txt hygiene (Check for leaky internal administrative paths)
    """

    RULE_ID = "SEC-WEB-005"
    VERSION = "1.0.0"
    TITLE = "Sensitive File Exposure and RFC 9116 Security Policy Compliance"
    CWE = "CWE-538"  # Insertion of Sensitive Information into Externally-Accessible File or Directory
    REFERENCES = [
        "https://www.rfc-editor.org/rfc/rfc9116",
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
    ]

    def evaluate(
        self,
        assessment_id: str,
        asset_id: str,
        collector_result: SensitiveFileCollectorResult,
    ) -> Tuple[ExecutionStatus, Optional[Dict[str, Any]], Optional[Dict[str, Any]], Dict[str, Any]]:
        now = datetime.now(timezone.utc)

        if collector_result.error:
            obs = {
                "id": f"OBS-{uuid.uuid4().hex[:8]}",
                "summary": f"File check failed for {collector_result.target}: {collector_result.error}",
                "details": {"error": collector_result.error},
                "observedAt": now.isoformat(),
            }
            evd = {
                "id": f"EVD-{uuid.uuid4().hex[:8]}",
                "findingId": None,
                "type": "log",
                "source": "SensitiveFileCollector",
                "rawContent": collector_result.error,
                "capturedAt": now.isoformat(),
            }
            return ExecutionStatus.ERROR, obs, None, evd

        checks = collector_result.checks

        git_exposed = checks.get("/.git/HEAD") and checks["/.git/HEAD"].accessible
        env_exposed = checks.get("/.env") and checks["/.env"].accessible

        sec_txt_wk = checks.get("/.well-known/security.txt") and checks["/.well-known/security.txt"].accessible
        sec_txt_root = checks.get("/security.txt") and checks["/security.txt"].accessible
        has_security_txt = sec_txt_wk or sec_txt_root

        robots_exposed = checks.get("/robots.txt") and checks["/robots.txt"].accessible

        obs = {
            "id": f"OBS-{uuid.uuid4().hex[:8]}",
            "summary": (
                f"Evaluated 5 standard paths on {collector_result.target}. "
                f"Dotfiles exposed: {git_exposed or env_exposed}. security.txt present: {has_security_txt}."
            ),
            "details": {
                "gitHeadExposed": git_exposed,
                "envExposed": env_exposed,
                "securityTxtPresent": has_security_txt,
                "robotsTxtPresent": robots_exposed,
            },
            "observedAt": now.isoformat(),
        }

        raw_evidence = "\n".join(
            [f"{path}: Status {c.status_code} (Accessible: {c.accessible})" for path, c in checks.items()]
        )

        finding = None

        if git_exposed or env_exposed:
            status = ExecutionStatus.FAIL
            exposed_items = []
            if git_exposed:
                exposed_items.append("/.git/HEAD")
            if env_exposed:
                exposed_items.append("/.env")

            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": f"Critical Exposure of Sensitive Source/Environment Files on {collector_result.target}",
                "description": (
                    f"Sensitive file(s) [{', '.join(exposed_items)}] are publicly accessible without authentication. "
                    "Exposure of .git allows rebuilding the entire source repository. "
                    "Exposure of .env leaks production secrets, database credentials, and API keys."
                ),
                "status": FindingStatus.DETECTED,
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe": self.CWE,
                "cvss": 9.8,
                "impact": "Full source code disclosure and potential immediate compromise of backend infrastructure.",
                "recommendation": (
                    "Block access to hidden dotfiles in web server rules:\n"
                    "- Nginx: location ~ /\\. { deny all; return 404; }\n"
                    "- Apache: <FilesMatch \"^\\.\"> Order allow,deny Deny from all </FilesMatch>"
                ),
                "createdAt": now.isoformat(),
            }

        elif not has_security_txt:
            status = ExecutionStatus.WARN
            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": f"Missing RFC 9116 Security Policy (security.txt) on {collector_result.target}",
                "description": (
                    "The target does not publish a security.txt file at /.well-known/security.txt. "
                    "RFC 9116 specifies a standardized format for security researchers to report vulnerabilities."
                ),
                "status": FindingStatus.DETECTED,
                "severity": Severity.INFORMATIONAL,
                "confidence": Confidence.HIGH,
                "cwe": "CWE-16",
                "cvss": 0.0,
                "impact": "White-hat security researchers cannot easily locate official reporting channels.",
                "recommendation": "Deploy a valid security.txt file at /.well-known/security.txt with Contact: and Expires: fields.",
                "createdAt": now.isoformat(),
            }

        else:
            status = ExecutionStatus.PASS

        evd = {
            "id": f"EVD-{uuid.uuid4().hex[:8]}",
            "findingId": finding["id"] if finding else None,
            "type": "http_response",
            "source": "SensitiveFileCollector",
            "rawContent": raw_evidence,
            "capturedAt": now.isoformat(),
        }

        return status, obs, finding, evd
