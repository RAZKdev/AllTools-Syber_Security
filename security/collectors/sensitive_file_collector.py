from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import httpx

from app.services.scope_guard import ScopeGuard


@dataclass
class FileCheckResult:
    path: str
    status_code: int
    accessible: bool = False
    content_snippet: str = ""
    content_type: str = ""


@dataclass
class SensitiveFileCollectorResult:
    target: str
    checks: Dict[str, FileCheckResult] = field(default_factory=dict)
    error: Optional[str] = None


class SensitiveFileCollector:
    """Audits public accessibility of security.txt, robots.txt, and sensitive dotfiles."""

    AUDIT_PATHS = [
        "/.well-known/security.txt",
        "/security.txt",
        "/robots.txt",
        "/.git/HEAD",
        "/.env",
    ]

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout
        self.scope_guard = ScopeGuard()

    def collect(self, target: str, scope_items: Optional[List[Any]] = None) -> SensitiveFileCollectorResult:
        if scope_items is not None:
            decision = self.scope_guard.evaluate_target("default", target, scope_items)
            if not decision.is_allowed:
                return SensitiveFileCollectorResult(
                    target=target,
                    error=f"Target {target} blocked by Scope Guard: {decision.reason}",
                )

        base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        base_url = base_url.rstrip("/")

        results: Dict[str, FileCheckResult] = {}

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=False, verify=False) as client:
                for path in self.AUDIT_PATHS:
                    try:
                        url = f"{base_url}{path}"
                        resp = client.get(url)
                        is_accessible = resp.status_code == 200 and len(resp.text.strip()) > 0
                        snippet = resp.text[:200].strip() if is_accessible else ""
                        results[path] = FileCheckResult(
                            path=path,
                            status_code=resp.status_code,
                            accessible=is_accessible,
                            content_snippet=snippet,
                            content_type=resp.headers.get("content-type", ""),
                        )
                    except Exception:
                        results[path] = FileCheckResult(path=path, status_code=0, accessible=False)
            return SensitiveFileCollectorResult(target=target, checks=results)
        except Exception as e:
            return SensitiveFileCollectorResult(target=target, error=str(e))

    def collect_from_dict(self, target: str, simulated_data: Dict[str, Any]) -> SensitiveFileCollectorResult:
        results: Dict[str, FileCheckResult] = {}
        for path, data in simulated_data.get("paths", {}).items():
            results[path] = FileCheckResult(
                path=path,
                status_code=data.get("statusCode", 404),
                accessible=data.get("accessible", False),
                content_snippet=data.get("snippet", ""),
                content_type=data.get("contentType", "text/plain"),
            )
        return SensitiveFileCollectorResult(target=target, checks=results)
