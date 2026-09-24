import http.cookies
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import httpx

from app.services.scope_guard import ScopeGuard


@dataclass
class CookieRecord:
    name: str
    value: str
    http_only: bool = False
    secure: bool = False
    same_site: Optional[str] = None
    domain: Optional[str] = None
    path: Optional[str] = None
    raw: str = ""


@dataclass
class CookieCollectorResult:
    target: str
    cookies: List[CookieRecord] = field(default_factory=list)
    raw_headers: List[str] = field(default_factory=list)
    status_code: int = 200
    error: Optional[str] = None


class CookieCollector:
    """Collects and parses Set-Cookie headers with Scope Guard enforcement."""

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout
        self.scope_guard = ScopeGuard()

    def parse_set_cookie_headers(self, headers_list: List[str]) -> List[CookieRecord]:
        """Parse raw Set-Cookie header strings into structured CookieRecord objects."""
        records = []
        for header_val in headers_list:
            cookie = http.cookies.SimpleCookie()
            try:
                cookie.load(header_val)
                for key, morsel in cookie.items():
                    same_site = morsel.get("samesite", None)
                    # SimpleCookie might lowercase attribute names
                    record = CookieRecord(
                        name=key,
                        value=morsel.value,
                        http_only=bool(morsel.get("httponly", False)),
                        secure=bool(morsel.get("secure", False)),
                        same_site=str(same_site) if same_site else None,
                        domain=morsel.get("domain", None) or None,
                        path=morsel.get("path", None) or None,
                        raw=header_val,
                    )
                    records.append(record)
            except Exception:
                # Fallback manual parsing if SimpleCookie fails
                parts = [p.strip() for p in header_val.split(";")]
                if parts:
                    name_val = parts[0].split("=", 1)
                    name = name_val[0]
                    val = name_val[1] if len(name_val) > 1 else ""
                    attrs = [p.lower() for p in parts[1:]]
                    same_site_val = None
                    for p in parts[1:]:
                        if p.lower().startswith("samesite="):
                            same_site_val = p.split("=", 1)[1].strip()
                    records.append(
                        CookieRecord(
                            name=name,
                            value=val,
                            http_only=any("httponly" in a for a in attrs),
                            secure=any("secure" in a for a in attrs),
                            same_site=same_site_val,
                            raw=header_val,
                        )
                    )
        return records

    def collect(self, target: str, scope_items: Optional[List[Any]] = None) -> CookieCollectorResult:
        if scope_items is not None:
            decision = self.scope_guard.evaluate_target("default", target, scope_items)
            if not decision.is_allowed:
                return CookieCollectorResult(
                    target=target,
                    error=f"Target {target} blocked by Scope Guard: {decision.reason}",
                )

        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                resp = client.get(url)
                set_cookies = resp.headers.get_list("set-cookie")
                cookies = self.parse_set_cookie_headers(set_cookies)
                return CookieCollectorResult(
                    target=target,
                    cookies=cookies,
                    raw_headers=set_cookies,
                    status_code=resp.status_code,
                )
        except Exception as e:
            return CookieCollectorResult(target=target, error=str(e))

    def collect_from_dict(self, target: str, simulated_data: Dict[str, Any]) -> CookieCollectorResult:
        raw_headers = simulated_data.get("setCookie", [])
        if isinstance(raw_headers, str):
            raw_headers = [raw_headers]
        cookies = self.parse_set_cookie_headers(raw_headers)
        return CookieCollectorResult(
            target=target,
            cookies=cookies,
            raw_headers=raw_headers,
            status_code=simulated_data.get("statusCode", 200),
        )
