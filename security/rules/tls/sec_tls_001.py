import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.common import Confidence, ExecutionStatus, FindingStatus, Severity
from security.collectors.tls_collector import TlsCollectorResult


class SecTls001Rule:
    """
    SEC-TLS-001: TLS Certificate & Protocol Inspection.
    
    Verifies:
    1. Certificate expiration and validity window.
    2. Hostname matching against Common Name (CN) and Subject Alternative Names (SANs).
    3. Minimum protocol version (deprecating SSLv3, TLS 1.0, TLS 1.1).
    """

    RULE_ID = "SEC-TLS-001"
    VERSION = "1.0.0"
    TITLE = "TLS Certificate Validity and Protocol Inspection"
    REFERENCES = [
        "https://cwe.mitre.org/data/definitions/295.html",
        "https://cwe.mitre.org/data/definitions/298.html",
        "https://cwe.mitre.org/data/definitions/297.html",
    ]

    INSECURE_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}

    @staticmethod
    def _parse_cert_date(date_str: str) -> Optional[datetime]:
        """Parse ASN1 date strings commonly returned by ssl library."""
        formats = [
            "%b %d %H:%M:%S %Y %Z",
            "%b  %d %H:%M:%S %Y %Z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(date_str.strip(), fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
        return None

    def evaluate(
        self,
        assessment_id: str,
        asset_id: str,
        collector_result: TlsCollectorResult,
    ) -> Tuple[ExecutionStatus, Optional[Dict[str, Any]], Optional[Dict[str, Any]], Dict[str, Any]]:
        """
        Evaluate certificate and TLS configuration.
        """
        now = datetime.now(timezone.utc)
        cert = collector_result.cert_data
        target_host = collector_result.host.lower()

        evidence_payload = {
            "id": f"EVD-{uuid.uuid4().hex[:8]}",
            "assessmentId": assessment_id,
            "type": "configuration_snapshot",
            "source": f"{collector_result.target}:{collector_result.port}",
            "capturedAt": collector_result.captured_at.isoformat(),
            "sha256": collector_result.sha256,
            "redacted": False,
            "notes": f"Captured TLS certificate and handshake info for {collector_result.target}",
        }

        # 1. Check Protocol Version
        tls_ver = (collector_result.tls_version or "").strip()
        if tls_ver in self.INSECURE_PROTOCOLS:
            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            observation = {
                "id": f"OBS-{uuid.uuid4().hex[:8]}",
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "summary": f"Insecure legacy TLS protocol negotiated: {tls_ver}.",
                "details": {"negotiatedProtocol": tls_ver, "cipher": collector_result.cipher},
                "observedAt": now.isoformat(),
            }
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": f"Insecure TLS Protocol In Use ({tls_ver})",
                "description": f"The host negotiated {tls_ver}, which is deprecated and contains known cryptographic weaknesses.",
                "status": FindingStatus.NEEDS_REVIEW.value,
                "severity": Severity.MEDIUM.value,
                "confidence": Confidence.HIGH.value,
                "cwe": "CWE-326",
                "impact": "Communications may be susceptible to protocol downgrade or eavesdropping attacks.",
                "recommendation": "Disable SSLv3, TLS 1.0, and TLS 1.1 on the server. Configure TLS 1.2 or TLS 1.3 as minimum protocol.",
                "createdAt": now.isoformat(),
            }
            evidence_payload["findingId"] = finding_id
            return ExecutionStatus.FAIL, observation, finding, evidence_payload

        # 2. Extract validity dates
        not_after_str = cert.get("notAfter")
        not_before_str = cert.get("notBefore")

        if not_after_str:
            not_after_dt = self._parse_cert_date(not_after_str)
            if not_after_dt:
                # Expired certificate check
                if now > not_after_dt:
                    finding_id = f"FND-{uuid.uuid4().hex[:8]}"
                    observation = {
                        "id": f"OBS-{uuid.uuid4().hex[:8]}",
                        "assessmentId": assessment_id,
                        "assetId": asset_id,
                        "ruleId": self.RULE_ID,
                        "summary": f"TLS certificate expired on {not_after_dt.isoformat()}.",
                        "details": {"expiredAt": not_after_dt.isoformat(), "target": collector_result.target},
                        "observedAt": now.isoformat(),
                    }
                    finding = {
                        "id": finding_id,
                        "assessmentId": assessment_id,
                        "assetId": asset_id,
                        "ruleId": self.RULE_ID,
                        "title": "Expired TLS Certificate",
                        "description": f"The TLS certificate for {collector_result.target} expired on {not_after_dt.isoformat()}.",
                        "status": FindingStatus.NEEDS_REVIEW.value,
                        "severity": Severity.HIGH.value,
                        "confidence": Confidence.HIGH.value,
                        "cwe": "CWE-298",
                        "impact": "Clients will receive browser warnings and terminate connections. Confidentiality cannot be guaranteed.",
                        "recommendation": "Renew the TLS certificate immediately and automate certificate lifecycle management.",
                        "createdAt": now.isoformat(),
                    }
                    evidence_payload["findingId"] = finding_id
                    return ExecutionStatus.FAIL, observation, finding, evidence_payload

                # Expiring soon check (<= 14 days)
                days_left = (not_after_dt - now).days
                if days_left <= 14:
                    observation = {
                        "id": f"OBS-{uuid.uuid4().hex[:8]}",
                        "assessmentId": assessment_id,
                        "assetId": asset_id,
                        "ruleId": self.RULE_ID,
                        "summary": f"TLS certificate is expiring soon in {days_left} days ({not_after_dt.isoformat()}).",
                        "details": {"daysRemaining": days_left, "expiresAt": not_after_dt.isoformat()},
                        "observedAt": now.isoformat(),
                    }
                    # A warning is an observation for planning, not a vulnerability finding
                    return ExecutionStatus.WARN, observation, None, evidence_payload

        # 3. Check Hostname / SubjectAltName Match
        sans = [san[1].lower() for san in cert.get("subjectAltName", []) if san[0] == "DNS"]
        cn = cert.get("commonName", "").lower()

        valid_names = set(sans)
        if cn:
            valid_names.add(cn)

        if valid_names:
            matched = False
            for name in valid_names:
                if name.startswith("*."):
                    suffix = name[2:]
                    if target_host.endswith(f".{suffix}") or target_host == suffix:
                        matched = True
                        break
                elif name == target_host:
                    matched = True
                    break

            if not matched:
                finding_id = f"FND-{uuid.uuid4().hex[:8]}"
                observation = {
                    "id": f"OBS-{uuid.uuid4().hex[:8]}",
                    "assessmentId": assessment_id,
                    "assetId": asset_id,
                    "ruleId": self.RULE_ID,
                    "summary": f"Certificate hostname mismatch: '{target_host}' does not match SANs ({', '.join(valid_names)}).",
                    "details": {"targetHost": target_host, "validNames": list(valid_names)},
                    "observedAt": now.isoformat(),
                }
                finding = {
                    "id": finding_id,
                    "assessmentId": assessment_id,
                    "assetId": asset_id,
                    "ruleId": self.RULE_ID,
                    "title": "TLS Certificate Hostname Mismatch",
                    "description": f"The certificate presented by {collector_result.target} is issued for {list(valid_names)}, which does not match target '{target_host}'.",
                    "status": FindingStatus.NEEDS_REVIEW.value,
                    "severity": Severity.MEDIUM.value,
                    "confidence": Confidence.HIGH.value,
                    "cwe": "CWE-297",
                    "impact": "Clients will reject the connection or display a security error due to host mismatch.",
                    "recommendation": "Reissue certificate including the requested domain in Subject Alternative Name (SAN).",
                    "createdAt": now.isoformat(),
                }
                evidence_payload["findingId"] = finding_id
                return ExecutionStatus.FAIL, observation, finding, evidence_payload

        # PASS: Valid cert, modern TLS, matching host, > 14 days remaining
        observation = {
            "id": f"OBS-{uuid.uuid4().hex[:8]}",
            "assessmentId": assessment_id,
            "assetId": asset_id,
            "ruleId": self.RULE_ID,
            "summary": f"TLS certificate is valid, matches hostname '{target_host}', and uses modern {tls_ver}.",
            "details": {
                "tlsVersion": tls_ver,
                "cipher": collector_result.cipher,
                "expiresAt": not_after_str,
            },
            "observedAt": now.isoformat(),
        }
        return ExecutionStatus.PASS, observation, None, evidence_payload
