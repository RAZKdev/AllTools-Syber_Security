import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.common import Confidence, ExecutionStatus, FindingStatus, Severity
from security.analyzers.password_analyzer import PasswordAuditResult, PasswordEntropyAnalyzer


class SecAuth001Rule:
    """
    SEC-AUTH-001: Password Policy & Entropy Compliance Auditor

    Audits password strength, character pool diversity, and Shannon entropy against
    NIST SP 800-63B (Digital Identity Guidelines: Authentication and Lifecycle Management).
    Detects common breached dictionary words, weak entropy, and insufficient lengths.
    """

    RULE_ID = "SEC-AUTH-001"
    VERSION = "1.0.0"
    TITLE = "Weak Password Policy and Low Entropy Configuration"
    CWE = "CWE-521"  # Weak Password Requirements
    REFERENCES = [
        "https://pages.nist.gov/800-63-3/sp800-63b.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    ]

    def __init__(self):
        self.analyzer = PasswordEntropyAnalyzer()

    def evaluate(
        self,
        assessment_id: str,
        asset_id: str,
        password_sample: str,
    ) -> Tuple[ExecutionStatus, Optional[Dict[str, Any]], Optional[Dict[str, Any]], Dict[str, Any]]:
        now = datetime.now(timezone.utc)
        result: PasswordAuditResult = self.analyzer.analyze(password_sample)

        obs = {
            "id": f"OBS-{uuid.uuid4().hex[:8]}",
            "summary": f"Audited password sample: length {result.length}, entropy {result.entropy_bits} bits ({result.strength}).",
            "details": {
                "length": result.length,
                "entropyBits": result.entropy_bits,
                "strength": result.strength,
                "hasUppercase": result.has_uppercase,
                "hasLowercase": result.has_lowercase,
                "hasDigits": result.has_digits,
                "hasSpecial": result.has_special,
                "isCommonPattern": result.is_common_pattern,
                "feedback": result.feedback,
            },
            "observedAt": now.isoformat(),
        }

        # Redact the password in raw evidence for security hygiene!
        masked_pwd = password_sample[0] + ("*" * (len(password_sample) - 2)) + password_sample[-1] if len(password_sample) > 2 else "***"
        raw_evidence = (
            f"Sample (Masked): {masked_pwd}\n"
            f"Length: {result.length}\n"
            f"Entropy: {result.entropy_bits} bits\n"
            f"Rating: {result.strength}\n"
            f"Feedback: {'; '.join(result.feedback)}"
        )

        finding = None

        if result.strength == "VERY_WEAK":
            status = ExecutionStatus.FAIL
            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": "Very Weak Password / Common Dictionary Credential Detected",
                "description": (
                    f"The evaluated password exhibits critical vulnerabilities: {'; '.join(result.feedback)}. "
                    "Short lengths (<8 characters) and top dictionary passwords can be cracked in seconds."
                ),
                "status": FindingStatus.DETECTED,
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe": self.CWE,
                "cvss": 8.8,
                "impact": "Account takeover via rapid offline/online dictionary and automated credential stuffing attacks.",
                "recommendation": (
                    "Enforce NIST SP 800-63B standards:\n"
                    "1. Minimum length of 12-16 characters.\n"
                    "2. Check new passwords against known breached password lists (e.g. HaveIBeenPwned).\n"
                    "3. Implement rate-limiting and multi-factor authentication (MFA)."
                ),
                "createdAt": now.isoformat(),
            }

        elif result.strength == "WEAK":
            status = ExecutionStatus.FAIL
            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": f"Low Password Entropy ({result.entropy_bits} bits)",
                "description": f"The password offers low complexity and entropy: {'; '.join(result.feedback)}.",
                "status": FindingStatus.DETECTED,
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe": self.CWE,
                "cvss": 7.0,
                "impact": "Susceptible to targeted brute-force cracking on modern GPU hardware.",
                "recommendation": "Encourage passphrases with 14+ characters combining multiple words or diverse character sets.",
                "createdAt": now.isoformat(),
            }

        elif result.strength == "FAIR":
            status = ExecutionStatus.WARN
            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": "Moderate Password Entropy - Enhancement Recommended",
                "description": f"Password meets basic length but could be strengthened: {'; '.join(result.feedback)}.",
                "status": FindingStatus.DETECTED,
                "severity": Severity.LOW,
                "confidence": Confidence.HIGH,
                "cwe": self.CWE,
                "cvss": 3.5,
                "impact": "Moderate resistance, but vulnerable over long periods if hashes leak.",
                "recommendation": "Increase minimum required password length to 14 or recommend password managers.",
                "createdAt": now.isoformat(),
            }

        else:
            status = ExecutionStatus.PASS

        evd = {
            "id": f"EVD-{uuid.uuid4().hex[:8]}",
            "findingId": finding["id"] if finding else None,
            "type": "log",
            "source": "PasswordEntropyAnalyzer",
            "rawContent": raw_evidence,
            "capturedAt": now.isoformat(),
        }

        return status, obs, finding, evd
