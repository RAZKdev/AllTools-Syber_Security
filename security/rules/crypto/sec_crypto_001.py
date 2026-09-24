import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.common import Confidence, ExecutionStatus, FindingStatus, Severity
from security.analyzers.crypto_analyzer import CryptoHashAnalyzer, HashAnalysis


class SecCrypto001Rule:
    """
    SEC-CRYPTO-001: Cryptographic Hash Algorithm Strength Analyzer

    Audits hash digests, signatures, and stored password formats to ensure compliance
    with modern collision-resistance standards (NIST SP 800-131A / OWASP A02:2021).
    Detects insecure MD5, SHA-1, CRC32 vs approved SHA-256, SHA-512, bcrypt, Argon2.
    """

    RULE_ID = "SEC-CRYPTO-001"
    VERSION = "1.0.0"
    TITLE = "Use of Cryptographically Broken or Weak Hash Algorithm"
    CWE = "CWE-327"  # Use of a Broken or Risky Cryptographic Algorithm
    REFERENCES = [
        "https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final",
        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    ]

    def __init__(self):
        self.analyzer = CryptoHashAnalyzer()

    def evaluate(
        self,
        assessment_id: str,
        asset_id: str,
        hash_string: str,
    ) -> Tuple[ExecutionStatus, Optional[Dict[str, Any]], Optional[Dict[str, Any]], Dict[str, Any]]:
        now = datetime.now(timezone.utc)
        result: HashAnalysis = self.analyzer.analyze(hash_string)

        obs = {
            "id": f"OBS-{uuid.uuid4().hex[:8]}",
            "summary": f"Analyzed hash: detected '{result.detected_algorithm}' ({result.security_status}).",
            "details": {
                "inputSample": hash_string[:12] + "..." if len(hash_string) > 12 else hash_string,
                "detectedAlgorithm": result.detected_algorithm,
                "bitLength": result.bit_length,
                "securityStatus": result.security_status,
                "isSaltedOrKdf": result.is_salted_or_kdf,
                "description": result.description,
            },
            "observedAt": now.isoformat(),
        }

        finding = None
        raw_evidence = (
            f"Input Hash: {hash_string}\n"
            f"Detected Algorithm: {result.detected_algorithm}\n"
            f"Bit Length: {result.bit_length}\n"
            f"Security Status: {result.security_status}\n"
            f"Evaluation: {result.description}"
        )

        if result.security_status == "INSECURE":
            status = ExecutionStatus.FAIL
            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": f"Insecure Cryptographic Algorithm ({result.detected_algorithm}) Detected",
                "description": (
                    f"The analyzed digest utilizes {result.detected_algorithm}, a cryptographically broken algorithm "
                    "with known practical collision and preimage attacks. It cannot guarantee data integrity or authenticity."
                ),
                "status": FindingStatus.DETECTED,
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe": self.CWE,
                "cvss": 8.1,
                "impact": "Collision generation, signature spoofing, and rapid rainbow table reversal of stored values.",
                "recommendation": result.recommendation,
                "createdAt": now.isoformat(),
            }

        elif result.security_status == "DEPRECATED":
            status = ExecutionStatus.FAIL
            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": f"Deprecated Cryptographic Algorithm ({result.detected_algorithm}) Detected",
                "description": (
                    f"The algorithm {result.detected_algorithm} is formally deprecated by NIST due to demonstrated collision vulnerabilities (SHAttered attack). "
                    "It is no longer considered safe for digital signatures or security-critical verification."
                ),
                "status": FindingStatus.DETECTED,
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe": "CWE-328",
                "cvss": 6.5,
                "impact": "Vulnerability to collision attacks in certificates, commit signatures, and file verification.",
                "recommendation": result.recommendation,
                "createdAt": now.isoformat(),
            }

        elif result.security_status == "WARN":
            status = ExecutionStatus.WARN
            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": "Unverified or Custom Cryptographic Format",
                "description": "The input hash could not be matched with high confidence to a recognized standard algorithm.",
                "status": FindingStatus.DETECTED,
                "severity": Severity.LOW,
                "confidence": Confidence.MEDIUM,
                "cwe": "CWE-326",
                "cvss": 3.0,
                "impact": "Potential reliance on non-standard or proprietary hashing routines.",
                "recommendation": result.recommendation,
                "createdAt": now.isoformat(),
            }

        else:
            status = ExecutionStatus.PASS

        evd = {
            "id": f"EVD-{uuid.uuid4().hex[:8]}",
            "findingId": finding["id"] if finding else None,
            "type": "log",
            "source": "CryptoHashAnalyzer",
            "rawContent": raw_evidence,
            "capturedAt": now.isoformat(),
        }

        return status, obs, finding, evd
