import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.services.scope_guard import ScopeGuard


@dataclass
class PortServiceInfo:
    port: int
    service: str
    is_open: bool
    risk_level: str  # Critical, High, Medium, Low, Info
    description: str


@dataclass
class PortCollectorResult:
    target: str
    resolved_ip: Optional[str] = None
    open_ports: List[PortServiceInfo] = field(default_factory=list)
    closed_ports: List[int] = field(default_factory=list)
    scanned_ports: List[int] = field(default_factory=list)
    error: Optional[str] = None


class PortCollector:
    """Authorized network port availability probe with Scope Guard enforcement."""

    DEFAULT_PROBE_PORTS = {
        21: ("FTP", "HIGH", "Legacy unencrypted file transfer protocol. Credentials sent in plaintext."),
        22: ("SSH", "LOW", "Encrypted remote administration service. Ensure key-based auth."),
        23: ("Telnet", "CRITICAL", "Legacy unencrypted shell. Vulnerable to sniffing and MITM."),
        25: ("SMTP", "MEDIUM", "Mail transfer service. Ensure open relay is disabled."),
        80: ("HTTP", "INFO", "Standard unencrypted web server."),
        443: ("HTTPS", "INFO", "Standard encrypted web server."),
        3306: ("MySQL", "HIGH", "Relational database server. Should never be exposed publicly."),
        5432: ("PostgreSQL", "HIGH", "Relational database server. Should never be exposed publicly."),
        6379: ("Redis", "CRITICAL", "In-memory database often configured without authentication."),
        27017: ("MongoDB", "CRITICAL", "NoSQL database. Frequently targeted when exposed to public."),
        3389: ("RDP", "HIGH", "Windows Remote Desktop Protocol. Target for brute-force attacks."),
        8080: ("HTTP-Alt", "INFO", "Alternative web proxy/management port."),
    }

    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
        self.scope_guard = ScopeGuard()

    def collect(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        scope_items: Optional[List[Any]] = None,
    ) -> PortCollectorResult:
        if scope_items is not None:
            decision = self.scope_guard.evaluate_target("default", target, scope_items)
            if not decision.is_allowed:
                return PortCollectorResult(
                    target=target,
                    error=f"Target {target} blocked by Scope Guard: {decision.reason}",
                )

        target_host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        try:
            resolved_ip = socket.gethostbyname(target_host)
        except Exception as e:
            return PortCollectorResult(target=target, error=f"DNS resolution failed for {target_host}: {e}")

        ports_to_check = ports or list(self.DEFAULT_PROBE_PORTS.keys())
        open_list: List[PortServiceInfo] = []
        closed_list: List[int] = []

        for port in ports_to_check:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((resolved_ip, port))
                    if result == 0:
                        svc_info = self.DEFAULT_PROBE_PORTS.get(
                            port, ("Unknown", "MEDIUM", "Unrecognized open port.")
                        )
                        open_list.append(
                            PortServiceInfo(
                                port=port,
                                service=svc_info[0],
                                is_open=True,
                                risk_level=svc_info[1],
                                description=svc_info[2],
                            )
                        )
                    else:
                        closed_list.append(port)
            except Exception:
                closed_list.append(port)

        return PortCollectorResult(
            target=target,
            resolved_ip=resolved_ip,
            open_ports=open_list,
            closed_ports=closed_list,
            scanned_ports=ports_to_check,
        )

    def collect_from_dict(self, target: str, simulated_data: Dict[str, Any]) -> PortCollectorResult:
        open_list: List[PortServiceInfo] = []
        closed_list = simulated_data.get("closedPorts", [])
        scanned = simulated_data.get("scannedPorts", list(self.DEFAULT_PROBE_PORTS.keys()))

        for p in simulated_data.get("openPorts", []):
            if isinstance(p, int):
                svc_info = self.DEFAULT_PROBE_PORTS.get(p, ("Custom", "MEDIUM", "Open port."))
                open_list.append(
                    PortServiceInfo(
                        port=p,
                        service=svc_info[0],
                        is_open=True,
                        risk_level=svc_info[1],
                        description=svc_info[2],
                    )
                )
            elif isinstance(p, dict):
                open_list.append(
                    PortServiceInfo(
                        port=p["port"],
                        service=p.get("service", "Unknown"),
                        is_open=True,
                        risk_level=p.get("riskLevel", "MEDIUM"),
                        description=p.get("description", ""),
                    )
                )

        return PortCollectorResult(
            target=target,
            resolved_ip=simulated_data.get("resolvedIp", "192.168.1.50"),
            open_ports=open_list,
            closed_ports=closed_list,
            scanned_ports=scanned,
        )
