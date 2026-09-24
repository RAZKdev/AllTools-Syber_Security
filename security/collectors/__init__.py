"""Collectors package."""
from security.collectors.http_header_collector import (
    HttpHeaderCollector,
    HttpHeaderCollectorResult,
    ScopeViolationError,
)
from security.collectors.tls_collector import (
    TlsCollector,
    TlsCollectorResult,
)
from security.collectors.dns_collector import (
    DnsCollector,
    DnsCollectorResult,
)

__all__ = [
    "HttpHeaderCollector",
    "HttpHeaderCollectorResult",
    "TlsCollector",
    "TlsCollectorResult",
    "DnsCollector",
    "DnsCollectorResult",
    "ScopeViolationError",
]
