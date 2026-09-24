from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import httpx

from app.services.scope_guard import ScopeGuard


@dataclass
class CorsCollectorResult:
    target: str
    allow_origin: Optional[str] = None
    allow_credentials: bool = False
    allow_methods: Optional[str] = None
    allow_headers: Optional[str] = None
    all_headers: Dict[str, str] = field(default_factory=dict)
    tested_origin: str = "https://untrusted-origin.example.com"
    status_code: int = 200
    error: Optional[str] = None


class CorsCollector:
    """Collects CORS policy response headers with Scope Guard enforcement."""

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout
        self.scope_guard = ScopeGuard()

    def collect(
        self,
        target: str,
        test_origin: str = "https://untrusted-origin.example.com",
        scope_items: Optional[List[Any]] = None,
    ) -> CorsCollectorResult:
        if scope_items is not None:
            decision = self.scope_guard.evaluate_target("default", target, scope_items)
            if not decision.is_allowed:
                return CorsCollectorResult(
                    target=target,
                    error=f"Target {target} blocked by Scope Guard: {decision.reason}",
                )

        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        headers = {
            "Origin": test_origin,
            "Access-Control-Request-Method": "GET",
        }

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                # 1. Preflight OPTIONS
                resp = client.options(url, headers=headers)
                if resp.status_code in (405, 501):
                    # Fallback to GET if OPTIONS not implemented
                    resp = client.get(url, headers=headers)

                h = {k.lower(): v for k, v in resp.headers.items()}
                allow_cred_str = h.get("access-control-allow-credentials", "false").lower()

                return CorsCollectorResult(
                    target=target,
                    allow_origin=h.get("access-control-allow-origin"),
                    allow_credentials=allow_cred_str == "true",
                    allow_methods=h.get("access-control-allow-methods"),
                    allow_headers=h.get("access-control-allow-headers"),
                    all_headers=dict(resp.headers),
                    tested_origin=test_origin,
                    status_code=resp.status_code,
                )
        except Exception as e:
            return CorsCollectorResult(target=target, error=str(e))

    def collect_from_dict(self, target: str, simulated_data: Dict[str, Any]) -> CorsCollectorResult:
        h = {k.lower(): str(v) for k, v in simulated_data.get("headers", {}).items()}
        allow_cred_str = h.get("access-control-allow-credentials", "false").lower()

        return CorsCollectorResult(
            target=target,
            allow_origin=h.get("access-control-allow-origin"),
            allow_credentials=allow_cred_str == "true",
            allow_methods=h.get("access-control-allow-methods"),
            allow_headers=h.get("access-control-allow-headers"),
            all_headers=h,
            tested_origin=simulated_data.get("testedOrigin", "https://untrusted-origin.example.com"),
            status_code=simulated_data.get("statusCode", 200),
        )
