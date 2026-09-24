import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.common import Confidence, ExecutionStatus, FindingStatus, Severity
from security.collectors.port_collector import PortCollectorResult


class SecNet001Rule:
    """
    SEC-NET-001: Authorized Port & Critical Service Exposure Audit

    Audits reachable network TCP ports on authorized targets to detect accidental
    public exposure of databases (MySQL, Postgres, Redis, MongoDB), legacy unencrypted
    services (Telnet, FTP), or remote desktop (RDP).
    """

    RULE_ID = "SEC-NET-001"
    VERSION = "1.0.0"
    TITLE = "Exposure of High-Risk Network Ports and Critical Services"
    CWE = "CWE-284"  # Improper Access Control
    REFERENCES = [
        "https://www.cisecurity.org/controls/cis-controls-list",
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Network_Infrastructure",
    ]

    def evaluate(
        self,
        assessment_id: str,
        asset_id: str,
        collector_result: PortCollectorResult,
    ) -> Tuple[ExecutionStatus, Optional[Dict[str, Any]], Optional[Dict[str, Any]], Dict[str, Any]]:
        now = datetime.now(timezone.utc)

        if collector_result.error:
            obs = {
                "id": f"OBS-{uuid.uuid4().hex[:8]}",
                "summary": f"Port probe failed for {collector_result.target}: {collector_result.error}",
                "details": {"error": collector_result.error},
                "observedAt": now.isoformat(),
            }
            evd = {
                "id": f"EVD-{uuid.uuid4().hex[:8]}",
                "findingId": None,
                "type": "log",
                "source": "PortCollector",
                "rawContent": collector_result.error,
                "capturedAt": now.isoformat(),
            }
            return ExecutionStatus.ERROR, obs, None, evd

        open_ports = collector_result.open_ports

        critical_ports = [p for p in open_ports if p.risk_level == "CRITICAL"]
        high_ports = [p for p in open_ports if p.risk_level == "HIGH"]
        medium_ports = [p for p in open_ports if p.risk_level == "MEDIUM"]

        obs = {
            "id": f"OBS-{uuid.uuid4().hex[:8]}",
            "summary": (
                f"Scanned {len(collector_result.scanned_ports)} ports on {collector_result.target} ({collector_result.resolved_ip}). "
                f"Found {len(open_ports)} open: {[f'{p.port}/{p.service}' for p in open_ports]}."
            ),
            "details": {
                "resolvedIp": collector_result.resolved_ip,
                "openCount": len(open_ports),
                "openServices": [
                    {"port": p.port, "service": p.service, "risk": p.risk_level, "description": p.description}
                    for p in open_ports
                ],
                "closedCount": len(collector_result.closed_ports),
            },
            "observedAt": now.isoformat(),
        }

        raw_evidence = (
            f"Target: {collector_result.target} (IP: {collector_result.resolved_ip})\n"
            + "\n".join([f"Port {p.port}/TCP - {p.service} [OPEN, Risk: {p.risk_level}] - {p.description}" for p in open_ports])
        )

        finding = None

        if critical_ports:
            status = ExecutionStatus.FAIL
            crit_names = [f"{p.service} (Port {p.port})" for p in critical_ports]
            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": f"Critical Service Exposure ({', '.join(crit_names)}) on {collector_result.target}",
                "description": (
                    f"Highly dangerous service port(s) [{', '.join(crit_names)}] are open to the network. "
                    "Unauthenticated in-memory databases (Redis/MongoDB) or plaintext management shells (Telnet) "
                    "present immediate risks of unauthorized remote data exfiltration or host takeover."
                ),
                "status": FindingStatus.DETECTED,
                "severity": Severity.CRITICAL,
                "confidence": Confidence.HIGH,
                "cwe": self.CWE,
                "cvss": 9.1,
                "impact": "Direct unauthorized database manipulation, cleartext credential sniffing, or host compromise.",
                "recommendation": (
                    "Apply host and network firewall rules to block external access to these ports:\n"
                    "1. Bind database services to localhost (127.0.0.1) or private VPC subnets only.\n"
                    "2. Decommission legacy unencrypted services (e.g. migrate Telnet to SSH).\n"
                    "3. Restrict administrative access via VPN or IP whitelisting."
                ),
                "createdAt": now.isoformat(),
            }

        elif high_ports:
            status = ExecutionStatus.FAIL
            high_names = [f"{p.service} (Port {p.port})" for p in high_ports]
            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": f"High-Risk Database/Management Port Exposure on {collector_result.target}",
                "description": (
                    f"Exposed database or remote access service(s): [{', '.join(high_names)}]. "
                    "Databases and RDP interfaces should not be publicly accessible over untrusted networks."
                ),
                "status": FindingStatus.DETECTED,
                "severity": Severity.HIGH,
                "confidence": Confidence.HIGH,
                "cwe": self.CWE,
                "cvss": 7.5,
                "impact": "Vulnerability to brute-force attacks and authentication bypasses on exposed backend services.",
                "recommendation": "Close external firewall access for database and management ports; use SSH tunnels or private bastion hosts.",
                "createdAt": now.isoformat(),
            }

        elif medium_ports:
            status = ExecutionStatus.WARN
            med_names = [f"{p.service} (Port {p.port})" for p in medium_ports]
            finding_id = f"FND-{uuid.uuid4().hex[:8]}"
            finding = {
                "id": finding_id,
                "assessmentId": assessment_id,
                "assetId": asset_id,
                "ruleId": self.RULE_ID,
                "title": f"Non-Standard/Exposed Service ({', '.join(med_names)}) on {collector_result.target}",
                "description": f"Service(s) [{', '.join(med_names)}] were detected listening on the target.",
                "status": FindingStatus.DETECTED,
                "severity": Severity.MEDIUM,
                "confidence": Confidence.HIGH,
                "cwe": self.CWE,
                "cvss": 5.3,
                "impact": "Enlarged attack surface; potential unintended service exposure.",
                "recommendation": "Review whether this service is required externally, or enforce access control restrictions.",
                "createdAt": now.isoformat(),
            }

        else:
            status = ExecutionStatus.PASS

        evd = {
            "id": f"EVD-{uuid.uuid4().hex[:8]}",
            "findingId": finding["id"] if finding else None,
            "type": "network_probe",
            "source": "PortCollector",
            "rawContent": raw_evidence,
            "capturedAt": now.isoformat(),
        }

        return status, obs, finding, evd
