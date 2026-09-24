import hashlib
import json
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.schemas.scope import ScopeItem
from app.services.scope_guard import ScopeGuard
from security.collectors.http_header_collector import ScopeViolationError


class DnsCollectorResult:
    def __init__(
        self,
        domain: str,
        records: Dict[str, List[str]],
        captured_at: Optional[datetime] = None,
    ):
        self.domain = domain
        self.records = records
        self.captured_at = captured_at or datetime.now(timezone.utc)
        self.sha256 = self._compute_sha256()

    def _compute_sha256(self) -> str:
        payload = json.dumps(
            {"domain": self.domain, "records": self.records},
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class DnsCollector:
    """
    Passive DNS Defensive Record Collector.
    Resolves domain records only after passing Scope Guard verification.
    """

    def __init__(self, scope_guard: Optional[ScopeGuard] = None) -> None:
        self.scope_guard = scope_guard or ScopeGuard()

    def collect_from_network(
        self,
        domain: str,
        assessment_id: str,
        scope_items: List[ScopeItem],
    ) -> DnsCollectorResult:
        """
        Query public DNS records for the domain.
        Scope Guard check is strictly enforced prior to query dispatch.
        """
        decision = self.scope_guard.evaluate_target(assessment_id, domain, scope_items)
        if not decision.is_allowed:
            raise ScopeViolationError(
                f"Scope Guard blocked target '{domain}': {decision.reason}"
            )

        clean_domain, _ = ScopeGuard.extract_host_and_ip(domain)
        records: Dict[str, List[str]] = {"A": [], "TXT": []}

        # Resolve A records via standard library
        try:
            _, _, ip_addresses = socket.gethostbyname_ex(clean_domain)
            records["A"] = ip_addresses
        except Exception:
            pass

        return DnsCollectorResult(
            domain=clean_domain,
            records=records,
        )

    def collect_from_dict(
        self,
        domain: str,
        records: Dict[str, List[str]],
    ) -> DnsCollectorResult:
        """Collect DNS records from lab test fixtures or offline zone data."""
        clean_domain, _ = ScopeGuard.extract_host_and_ip(domain)
        return DnsCollectorResult(
            domain=clean_domain,
            records=records,
        )
