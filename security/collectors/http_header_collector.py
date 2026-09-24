import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import httpx

from app.schemas.scope import ScopeItem
from app.services.scope_guard import ScopeGuard


class ScopeViolationError(Exception):
    """Raised when a collector attempts to target an unauthorized host."""
    pass


class HttpHeaderCollectorResult:
    def __init__(
        self,
        target: str,
        status_code: int,
        headers: Dict[str, str],
        raw_body: str = "",
        captured_at: Optional[datetime] = None,
    ):
        self.target = target
        self.status_code = status_code
        self.headers = headers
        self.raw_body = raw_body
        self.captured_at = captured_at or datetime.now(timezone.utc)
        self.sha256 = self._compute_sha256()

    def _compute_sha256(self) -> str:
        payload = json.dumps({"target": self.target, "headers": self.headers}, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class HttpHeaderCollector:
    """
    Passive HTTP Header Collector.
    Collects HTTP response headers only after passing Scope Guard verification.
    """

    def __init__(self, scope_guard: Optional[ScopeGuard] = None) -> None:
        self.scope_guard = scope_guard or ScopeGuard()

    def collect_from_network(
        self,
        target_url: str,
        assessment_id: str,
        scope_items: List[ScopeItem],
        timeout_seconds: float = 5.0,
    ) -> HttpHeaderCollectorResult:
        """
        Fetch headers from live target over HTTP/HTTPS.
        CRITICAL: Validates scope first. Out-of-scope targets are strictly blocked before sending any packet.
        """
        decision = self.scope_guard.evaluate_target(assessment_id, target_url, scope_items)
        if not decision.is_allowed:
            raise ScopeViolationError(
                f"Scope Guard blocked target '{target_url}': {decision.reason}"
            )

        try:
            with httpx.Client(timeout=timeout_seconds, follow_redirects=True, verify=False) as client:
                resp = client.head(target_url)
                if resp.status_code == 405:  # Method not allowed for HEAD, fallback to GET
                    resp = client.get(target_url)

                headers_dict = dict(resp.headers)
                return HttpHeaderCollectorResult(
                    target=target_url,
                    status_code=resp.status_code,
                    headers=headers_dict,
                )
        except Exception as e:
            raise RuntimeError(f"Network collection failed for '{target_url}': {str(e)}") from e

    def collect_from_dict(
        self,
        target: str,
        headers: Dict[str, Any],
        status_code: int = 200,
    ) -> HttpHeaderCollectorResult:
        """Collect headers from simulated, lab fixture, or offline data."""
        clean_headers = {str(k): str(v) for k, v in headers.items()}
        return HttpHeaderCollectorResult(
            target=target,
            status_code=status_code,
            headers=clean_headers,
        )
