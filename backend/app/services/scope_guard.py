import ipaddress
import re
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlparse
from pydantic import BaseModel, Field

from app.schemas.common import ScopeDecision
from app.schemas.scope import ScopeItem, ScopeType


class ScopeDecisionResult(BaseModel):
    """Result of evaluating a target against assessment scope rules."""
    assessmentId: str
    target: str
    decision: ScopeDecision
    reason: str
    matchedScopeItemId: Optional[str] = None
    evaluatedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_allowed(self) -> bool:
        return self.decision == ScopeDecision.ALLOW

    def format_scope_block(self) -> str:
        """Format blocked outcome according to DESIGN.md section 7."""
        if self.is_allowed:
            return f"ALLOWED: Target {self.target} is authorized under scope item {self.matchedScopeItemId}."
        return (
            "BLOCKED — OUT OF SCOPE\n\n"
            f"Target:\n{self.target}\n\n"
            f"Reason:\n{self.reason}"
        )


class ScopeGuard:
    """
    Scope Guard Engine.
    
    Non-negotiable security boundary:
    1. All target-based execution must pass through Scope Guard.
    2. Out-of-scope targets must be blocked by default (fail-closed).
    3. Explicit exclusion rules (inScope=False) take absolute precedence over inclusions.
    4. Expired rules are ignored.
    5. Detailed reason and provenance must be recorded for every decision.
    """

    @staticmethod
    def extract_host_and_ip(target: str) -> Tuple[str, Optional[int]]:
        """
        Extract host/ip string and optional port from a target string.
        Can handle URLs (https://example.com:8443/test), host:port, or bare host/IP.
        """
        target = target.strip()
        if not target:
            return "", None

        # If it looks like a URL with scheme
        if "://" in target:
            parsed = urlparse(target)
            return (parsed.hostname or "").lower(), parsed.port

        # If it looks like an IP:port or hostname:port (but not IPv6 without brackets)
        if ":" in target and not target.startswith("[") and target.count(":") == 1:
            host_part, port_part = target.split(":", 1)
            try:
                port = int(port_part)
                return host_part.lower(), port
            except ValueError:
                pass

        # If IPv6 with port [::1]:8080
        if target.startswith("[") and "]:" in target:
            m = re.match(r"^\[([a-fA-F0-9:]+)\]:(\d+)$", target)
            if m:
                return m.group(1).lower(), int(m.group(2))

        # Bare IP or hostname or CIDR
        clean_target = target.strip("[]").lower()
        return clean_target, None

    @classmethod
    def matches_ip_or_cidr(cls, target_host: str, rule_value: str, rule_type: ScopeType) -> bool:
        """Check if target host matches an IP or CIDR rule."""
        try:
            target_ip = ipaddress.ip_address(target_host)
        except ValueError:
            return False

        if rule_type == ScopeType.IP:
            try:
                rule_ip = ipaddress.ip_address(rule_value.strip())
                return target_ip == rule_ip
            except ValueError:
                return False

        if rule_type == ScopeType.CIDR:
            try:
                rule_net = ipaddress.ip_network(rule_value.strip(), strict=False)
                return target_ip in rule_net
            except ValueError:
                return False

        return False

    @classmethod
    def matches_domain_or_hostname(cls, target_host: str, rule_value: str, rule_type: ScopeType) -> bool:
        """Check if target matches a domain, subdomain, or hostname rule."""
        target_norm = target_host.lower().strip()
        rule_norm = rule_value.lower().strip()

        # Direct exact match
        if target_norm == rule_norm:
            return True

        if rule_type == ScopeType.SUBDOMAIN:
            # Handles *.example.com or example.com
            if rule_norm.startswith("*."):
                suffix = rule_norm[2:]
                return target_norm.endswith(f".{suffix}") or target_norm == suffix
            return target_norm.endswith(f".{rule_norm}") or target_norm == rule_norm

        if rule_type == ScopeType.DOMAIN:
            # Exact domain match or subdomains if allowed
            if target_norm == rule_norm:
                return True
            if target_norm.endswith(f".{rule_norm}"):
                return True

        if rule_type == ScopeType.HOSTNAME:
            return target_norm == rule_norm

        return False

    @classmethod
    def matches_url(cls, target: str, rule_value: str) -> bool:
        """Check if target matches a URL prefix or scope."""
        target_norm = target.strip().rstrip("/")
        rule_norm = rule_value.strip().rstrip("/")

        if target_norm == rule_norm:
            return True

        # Check prefix match (e.g. target is https://api.site.com/v1/auth, rule is https://api.site.com/v1)
        if target_norm.startswith(rule_norm + "/"):
            return True

        # Check hostname match within URL
        t_host, _ = cls.extract_host_and_ip(target)
        r_host, _ = cls.extract_host_and_ip(rule_value)
        if t_host and r_host and t_host == r_host:
            # If rule had no path (or just /), then matching the host is sufficient
            r_path = urlparse(rule_value).path.rstrip("/")
            if not r_path or r_path == "":
                return True

        return False

    @classmethod
    def matches_generic(cls, target: str, rule_value: str) -> bool:
        """Generic match for repository, application, log_source, file_set."""
        t = target.strip().lower()
        r = rule_value.strip().lower()
        if t == r:
            return True
        if r.endswith("*") and t.startswith(r[:-1]):
            return True
        return False

    @classmethod
    def matches_rule(cls, target: str, rule: ScopeItem) -> bool:
        """Evaluate if target matches the specific scope rule."""
        target_host, _ = cls.extract_host_and_ip(target)

        if rule.type in (ScopeType.IP, ScopeType.CIDR):
            if cls.matches_ip_or_cidr(target_host, rule.value, rule.type):
                return True

        if rule.type in (ScopeType.DOMAIN, ScopeType.SUBDOMAIN, ScopeType.HOSTNAME):
            if cls.matches_domain_or_hostname(target_host, rule.value, rule.type):
                return True

        if rule.type == ScopeType.URL:
            if cls.matches_url(target, rule.value):
                return True

        if rule.type in (ScopeType.APPLICATION, ScopeType.REPOSITORY, ScopeType.LOG_SOURCE, ScopeType.FILE_SET):
            if cls.matches_generic(target, rule.value):
                return True

        return False

    def evaluate_target(
        self,
        assessment_id: str,
        target: str,
        scope_items: List[ScopeItem],
        target_type: Optional[ScopeType] = None,
    ) -> ScopeDecisionResult:
        """
        Evaluate target authorization against assessment scope items.
        
        Algorithm:
        1. Clean and validate target input. Empty target is blocked immediately.
        2. Filter out expired scope items.
        3. Check explicit exclusions (inScope=False). If matched, BLOCK immediately.
        4. Check inclusions (inScope=True). If matched, ALLOW.
        5. If no inclusion matched, default to BLOCK (fail closed).
        """
        cleaned_target = target.strip()
        now = datetime.now(timezone.utc)

        if not cleaned_target:
            return ScopeDecisionResult(
                assessmentId=assessment_id,
                target=target,
                decision=ScopeDecision.BLOCK,
                reason="Target specification is empty or whitespace.",
                matchedScopeItemId=None,
                evaluatedAt=now,
            )

        # Separate active rules (exclude expired)
        active_rules: List[ScopeItem] = []
        for item in scope_items:
            if item.expiresAt:
                # Ensure timezone awareness for comparison
                item_expires = item.expiresAt
                if item_expires.tzinfo is None:
                    item_expires = item_expires.replace(tzinfo=timezone.utc)
                if now > item_expires:
                    continue  # Expired rule, skip
            active_rules.append(item)

        # 1. First pass: Explicit Exclusions (Blacklist priority)
        for item in active_rules:
            if not item.inScope:
                if self.matches_rule(cleaned_target, item):
                    return ScopeDecisionResult(
                        assessmentId=assessment_id,
                        target=cleaned_target,
                        decision=ScopeDecision.BLOCK,
                        reason=f"Target explicitly excluded by scope rule '{item.id}' ({item.type}: {item.value}).",
                        matchedScopeItemId=item.id,
                        evaluatedAt=now,
                    )

        # 2. Second pass: Inclusions (Whitelist)
        for item in active_rules:
            if item.inScope:
                if self.matches_rule(cleaned_target, item):
                    return ScopeDecisionResult(
                        assessmentId=assessment_id,
                        target=cleaned_target,
                        decision=ScopeDecision.ALLOW,
                        reason=f"Target authorized by scope rule '{item.id}' ({item.type}: {item.value}).",
                        matchedScopeItemId=item.id,
                        evaluatedAt=now,
                    )

        # 3. Default Deny / Fail Closed
        return ScopeDecisionResult(
            assessmentId=assessment_id,
            target=cleaned_target,
            decision=ScopeDecision.BLOCK,
            reason="Target does not match any active authorized scope rule for this assessment.",
            matchedScopeItemId=None,
            evaluatedAt=now,
        )
