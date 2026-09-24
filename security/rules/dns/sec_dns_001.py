import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.common import Confidence, ExecutionStatus, FindingStatus, Severity
from security.collectors.dns_collector import DnsCollectorResult


class SecDns001Rule:
    """
    SEC-DNS-001: Domain Email Defense & Anti-Spoofing Configuration (SPF/DMARC)
    
    Inspects DNS TXT records for:
    1. SPF record (v=spf1)
    2. DMARC record (v=DMARC1)
    """

    RULE_ID = "SEC-DNS-001"
    VERSION = "1.0.0"
    TITLE = "Missing or Weak Domain Email Authentication (SPF/DMARC)"
    CWE = "CWE-358"
    REFERENCES = [
        "https://www.rfc-editor.org/rfc/rfc7208",
        "https://www.rfc-editor.org/rfc/rfc7489",
        "https://cwe.mitre.org/data/definitions/358.html",
    ]

    def evaluate(
        self,
        assessment_id: str,
        asset_id: str,
        collector_result: DnsCollectorResult,
    ) -> Tuple[ExecutionStatus, Optional[Dict[str, Any]], Optional[Dict[str, Any]], Dict[str, Any]]:
        """
        Evaluate SPF and DMARC configuration from DNS records.
        """
        now = datetime.now(timezone.utc)
        txt_records = collector_result.records.get("TXT", [])

        spf_record = None
        dmarc_record = None

        for record in txt_records:
            clean_rec = record.strip()
            if clean_rec.startswith("v=spf1"):
                spf_record = clean_rec
            elif "v=dmarc1" in clean_rec.lower():
                dmarc_record = clean_rec

        evidence_payload = {
            "id": f"EVD-{uuid.uuid4().hex[:8]}",
            "assessmentId": assessment_id,
            "type": "configuration_snapshot",
            "source": f"dns://{collector_result.domain}",
            "capturedAt": collector_result.captured_at.isoformat(),
            "sha256": collector_result.sha256,
            "redacted": False,
            "notes": f"Captured {len(txt_records)} TXT records for {collector_result.domain}",
        }

        missing_controls = []
        if not spf_record:
            missing_controls.append("SPF (v=spf1)")
        if not dmarc_record:
            missing_controls.append("DMARC (v=DMARC1)")

        # Case 1: Missing both SPF and DMARC -> FAIL (Medium Severity)
        if len(missing_controls) >= 1:
            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            observation = {
                "id": f"OBS-{uuid.uuid4().hex[:8]}",
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "summary": f"Domain {collector_result.domain} is missing email defense records: {', '.join(missing_controls)}.",
                "details": {
                    "domain": collector_result.domain,
                    "missingControls": missing_controls,
                    "txtRecords": txt_records,
                },
                "observedAt": now.isoformat(),
            }
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": f"Missing Email Domain Anti-Spoofing Records ({', '.join(missing_controls)})",
                "description": (
                    f"The domain {collector_result.domain} does not publish valid defensive email records: "
                    f"{', '.join(missing_controls)}. Threat actors can impersonate this domain in phishing "
                    "or fraud campaigns targeting users and third parties."
                ),
                "status": FindingStatus.NEEDS_REVIEW.value,
                "severity": Severity.MEDIUM.value,
                "confidence": Confidence.HIGH.value,
                "cwe": self.CWE,
                "impact": "Unprotected domain can be spoofed in unauthorized email communications, damaging reputation and security trust.",
                "recommendation": (
                    "Publish defensive DNS TXT records:\n"
                    "1. SPF: 'v=spf1 -all' (or specify authorized mail relays).\n"
                    "2. DMARC: 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@"
                    f"{collector_result.domain}' at _dmarc.{collector_result.domain}."
                ),
                "createdAt": now.isoformat(),
            }
            evidence_payload["findingId"] = finding_id
            return ExecutionStatus.FAIL, observation, finding, evidence_payload

        # Case 2: Records exist, check for weak policy (e.g. +all in SPF or p=none in DMARC) -> WARN
        warnings = []
        if spf_record and ("+all" in spf_record or "?all" in spf_record):
            warnings.append("SPF record uses permissive mechanism (+all or ?all)")

        if dmarc_record and "p=none" in dmarc_record.lower():
            warnings.append("DMARC policy is set to 'p=none' (monitoring only, not rejecting spoofed emails)")

        if warnings:
            observation = {
                "id": f"OBS-{uuid.uuid4().hex[:8]}",
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "summary": f"Email authentication records present with policy warnings: {'; '.join(warnings)}.",
                "details": {
                    "domain": collector_result.domain,
                    "spf": spf_record,
                    "dmarc": dmarc_record,
                    "warnings": warnings,
                },
                "observedAt": now.isoformat(),
            }
            return ExecutionStatus.WARN, observation, None, evidence_payload

        # Case 3: Fully hardened -> PASS
        observation = {
            "id": f"OBS-{uuid.uuid4().hex[:8]}",
            "assessmentId": assessment_id,
            "assetId": asset_id,
            "ruleId": self.RULE_ID,
            "summary": f"Domain {collector_result.domain} has hardened SPF and DMARC enforcement policies.",
            "details": {
                "domain": collector_result.domain,
                "spf": spf_record,
                "dmarc": dmarc_record,
            },
            "observedAt": now.isoformat(),
        }
        return ExecutionStatus.PASS, observation, None, evidence_payload
