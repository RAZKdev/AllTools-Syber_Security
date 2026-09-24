import hashlib
import json
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.schemas.scope import ScopeItem
from app.services.scope_guard import ScopeGuard
from security.collectors.http_header_collector import ScopeViolationError


class TlsCollectorResult:
    def __init__(
        self,
        target: str,
        host: str,
        port: int,
        cert_data: Dict[str, Any],
        tls_version: str = "TLSv1.3",
        cipher: Optional[str] = None,
        captured_at: Optional[datetime] = None,
    ):
        self.target = target
        self.host = host
        self.port = port
        self.cert_data = cert_data
        self.tls_version = tls_version
        self.cipher = cipher
        self.captured_at = captured_at or datetime.now(timezone.utc)
        self.sha256 = self._compute_sha256()

    def _compute_sha256(self) -> str:
        payload = json.dumps(
            {
                "target": self.target,
                "host": self.host,
                "port": self.port,
                "cert": self.cert_data,
                "tls_version": self.tls_version,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class TlsCollector:
    """
    Passive TLS and Certificate Collector.
    Inspects certificates and cipher negotiation only after strict Scope Guard authorization.
    """

    def __init__(self, scope_guard: Optional[ScopeGuard] = None) -> None:
        self.scope_guard = scope_guard or ScopeGuard()

    def collect_from_network(
        self,
        target: str,
        assessment_id: str,
        scope_items: List[ScopeItem],
        default_port: int = 443,
        timeout_seconds: float = 4.0,
    ) -> TlsCollectorResult:
        """
        Passive TLS handshake to extract public server certificate.
        Scope Guard check is strictly enforced prior to network connection.
        """
        decision = self.scope_guard.evaluate_target(assessment_id, target, scope_items)
        if not decision.is_allowed:
            raise ScopeViolationError(
                f"Scope Guard blocked target '{target}': {decision.reason}"
            )

        host, port = ScopeGuard.extract_host_and_ip(target)
        port = port or default_port

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Passive inspection mode to examine even untrusted/expired certs

        try:
            with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert() or {}
                    tls_ver = ssock.version() or "UNKNOWN"
                    cipher_info = ssock.cipher()
                    cipher_name = cipher_info[0] if cipher_info else None

                    # If binary certificate exists, parse and record
                    if cert_bin:
                        cert_dict["_raw_sha256"] = hashlib.sha256(cert_bin).hexdigest()

                    return TlsCollectorResult(
                        target=target,
                        host=host,
                        port=port,
                        cert_data=cert_dict,
                        tls_version=tls_ver,
                        cipher=cipher_name,
                    )
        except Exception as e:
            raise RuntimeError(f"TLS inspection failed for '{target}': {str(e)}") from e

    def collect_from_dict(
        self,
        target: str,
        cert_data: Dict[str, Any],
        tls_version: str = "TLSv1.3",
        cipher: Optional[str] = "TLS_AES_256_GCM_SHA384",
    ) -> TlsCollectorResult:
        """Collect certificate metadata from test fixtures or offline logs."""
        host, port = ScopeGuard.extract_host_and_ip(target)
        return TlsCollectorResult(
            target=target,
            host=host,
            port=port or 443,
            cert_data=cert_data,
            tls_version=tls_version,
            cipher=cipher,
        )
