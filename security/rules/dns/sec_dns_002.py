import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.common import Confidence, ExecutionStatus, FindingStatus, Severity
from security.collectors.dns_collector import DnsCollectorResult


class SecDns002Rule:
    """
    SEC-DNS-002: DNS CAA (Certification Authority Authorization) Record Verification

    Audits DNS records for valid CAA (RFC 8659) entries.
    CAA records allow domain owners to declare which Certificate Authorities (CAs)
    are permitted to issue digital certificates for their domain, protecting against
    fraudulent or unauthorized certificate issuance.
    """

    RULE_ID = "SEC-DNS-002"
    VERSION = "1.0.0"
    TITLE = "Missing DNS Certification Authority Authorization (CAA) Record"
    CWE = "CWE-295"  # Improper Certificate Validation
    REFERENCES = [
        "https://www.rfc-editor.org/rfc/rfc8659",
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Weak_TLS_Ciphers",
    ]

    def evaluate(
        self,
        assessment_id: str,
        asset_id: str,
        collector_result: DnsCollectorResult,
    ) -> Tuple[ExecutionStatus, Optional[Dict[str, Any]], Optional[Dict[str, Any]], Dict[str, Any]]:
        now = datetime.now(timezone.utc)

        target_name = getattr(collector_result, "domain", getattr(collector_result, "target", "unknown"))
        err = getattr(collector_result, "error", None)

        if err:
            obs = {
                "id": f"OBS-{uuid.uuid4().hex[:8]}",
                "summary": f"DNS query failed for {target_name}: {err}",
                "details": {"error": err},
                "observedAt": now.isoformat(),
            }
            evd = {
                "id": f"EVD-{uuid.uuid4().hex[:8]}",
                "findingId": None,
                "type": "log",
                "source": "DnsCollector",
                "rawContent": str(err),
                "capturedAt": now.isoformat(),
            }
            return ExecutionStatus.ERROR, obs, None, evd

        caa_records = collector_result.records.get("CAA", [])
        raw_evidence = f"Domain: {target_name}\nCAA Records: {caa_records if caa_records else 'None'}"

        obs = {
            "id": f"OBS-{uuid.uuid4().hex[:8]}",
            "summary": (
                f"Observed {len(caa_records)} CAA record(s) on domain {target_name}."
                if caa_records
                else f"No CAA records found on domain {target_name}."
            ),
            "details": {
                "caaRecords": caa_records,
                "hasCaa": len(caa_records) > 0,
            },
            "observedAt": now.isoformat(),
        }

        finding = None

        if not caa_records:
            status = ExecutionStatus.WARN
            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": f"Missing DNS CAA Record on {target_name}",
                "description": (
                    f"The domain {target_name} does not define any CAA DNS records. "
                    "Without CAA records, any publicly trusted Certificate Authority (CA) is permitted "
                    "to issue certificates for this domain, increasing exposure to rogue or compromised CAs."
                ),
                "status": FindingStatus.DETECTED,
                "severity": Severity.LOW,
                "confidence": Confidence.HIGH,
                "cwe": self.CWE,
                "cvss": 3.7,
                "impact": "Unrestricted certificate issuance by any commercial Certificate Authority.",
                "recommendation": (
                    "Publish CAA records in your authoritative DNS zone to restrict issuance to your trusted CAs. Example:\n"
                    f"{target_name}. IN CAA 0 issue \"letsencrypt.org\"\n"
                    f"{target_name}. IN CAA 0 iodef \"mailto:security@{target_name}\""
                ),
                "createdAt": now.isoformat(),
            }
        else:
            status = ExecutionStatus.PASS

        evd = {
            "id": f"EVD-{uuid.uuid4().hex[:8]}",
            "findingId": finding["id"] if finding else None,
            "type": "dns_record",
            "source": "DnsCollector",
            "rawContent": raw_evidence,
            "capturedAt": now.isoformat(),
        }

        return status, obs, finding, evd
