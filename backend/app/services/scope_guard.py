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

    @classmethod
    def calculate_rule_specificity(cls, rule: ScopeItem) -> int:
        """
        Calculate specificity weight for scope rule to enforce deterministic precedence:
        - Domain/subdomain: number of labels * 1000 + string length
        - IP: 32000 (IPv4) or 128000 (IPv6)
        - CIDR: prefix length * 100
        - URL: length of URL string
        - Generic: length of pattern
        """
        if rule.type in (ScopeType.DOMAIN, ScopeType.SUBDOMAIN, ScopeType.HOSTNAME):
            val = rule.value.lower().strip()
            if val.startswith("*."):
                val = val[2:]
            labels = [p for p in val.split(".") if p]
            return len(labels) * 1000 + len(val)
        if rule.type == ScopeType.IP:
            try:
                ip = ipaddress.ip_address(rule.value.strip())
                return 32000 if ip.version == 4 else 128000
            except ValueError:
                return 1000
        if rule.type == ScopeType.CIDR:
            try:
                net = ipaddress.ip_network(rule.value.strip(), strict=False)
                return net.prefixlen * 100
            except ValueError:
                return 1000
        if rule.type == ScopeType.URL:
            return 5000 + len(rule.value.strip())
        return len(rule.value.strip())

    def evaluate_target(
        self,
        assessment_id: str,
        target: str,
        scope_items: List[ScopeItem],
        target_type: Optional[ScopeType] = None,
    ) -> ScopeDecisionResult:
        """
        Evaluate target authorization against assessment scope items.
        
        Deterministic Precedence Algorithm:
        1. Clean and validate target input. Empty target is blocked immediately.
        2. Partition rules into active exclusions, active inclusions, and expired rules.
        3. Check explicit active exclusions (inScope=False). If matched, BLOCK immediately.
        4. Check active inclusions. If matched:
           - Check if target also matches a more specific expired rule.
           - If a matching expired rule has specificity >= active inclusion, BLOCK (cannot inherit from broader parent).
           - Otherwise, ALLOW.
        5. If no active inclusion matched, check if an expired rule matched -> BLOCK (expired rule decision).
        6. If no rule matched, default to BLOCK (fail closed).
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

        # Partition rules: active exclusions, active inclusions, expired rules
        active_exclusions: List[ScopeItem] = []
        active_inclusions: List[ScopeItem] = []
        expired_rules: List[ScopeItem] = []

        for item in scope_items:
            is_expired = False
            if item.expiresAt:
                item_expires = item.expiresAt
                if item_expires.tzinfo is None:
                    item_expires = item_expires.replace(tzinfo=timezone.utc)
                if now > item_expires:
                    is_expired = True

            if is_expired:
                expired_rules.append(item)
            elif not item.inScope:
                active_exclusions.append(item)
            else:
                active_inclusions.append(item)

        # 1. First pass: Explicit Exclusions (Blacklist priority — ALWAYS DENIES)
        for item in active_exclusions:
            if self.matches_rule(cleaned_target, item):
                return ScopeDecisionResult(
                    assessmentId=assessment_id,
                    target=cleaned_target,
                    decision=ScopeDecision.BLOCK,
                    reason=f"Target explicitly excluded by scope rule '{item.id}' ({item.type}: {item.value}).",
                    matchedScopeItemId=item.id,
                    evaluatedAt=now,
                )

        # 2. Second pass: Active Inclusions vs Expired Rule Specificity
        matching_active_inclusions = [
            item for item in active_inclusions if self.matches_rule(cleaned_target, item)
        ]
        matching_expired_rules = [
            item for item in expired_rules if self.matches_rule(cleaned_target, item)
        ]

        if matching_active_inclusions:
            best_active = max(matching_active_inclusions, key=self.calculate_rule_specificity)
            # If an expired rule also matches this target, check specificity
            if matching_expired_rules:
                best_expired = max(matching_expired_rules, key=self.calculate_rule_specificity)
                # If the expired rule is more specific or equally specific as the active inclusion,
                # the target CANNOT inherit authorization from the broader parent inclusion!
                if self.calculate_rule_specificity(best_expired) >= self.calculate_rule_specificity(best_active):
                    exp_time = best_expired.expiresAt.isoformat() if best_expired.expiresAt else "unknown"
                    return ScopeDecisionResult(
                        assessmentId=assessment_id,
                        target=cleaned_target,
                        decision=ScopeDecision.BLOCK,
                        reason=(
                            f"Target blocked: matched expired scope rule '{best_expired.id}' "
                            f"({best_expired.type}: {best_expired.value}, expired at {exp_time}). "
                            f"Specific expired rule takes precedence over broader parent scope rule '{best_active.id}'."
                        ),
                        matchedScopeItemId=best_expired.id,
                        evaluatedAt=now,
                    )

            # Active inclusion authorized
            return ScopeDecisionResult(
                assessmentId=assessment_id,
                target=cleaned_target,
                decision=ScopeDecision.ALLOW,
                reason=f"Target authorized by scope rule '{best_active.id}' ({best_active.type}: {best_active.value}).",
                matchedScopeItemId=best_active.id,
                evaluatedAt=now,
            )

        # 3. Third pass: No active inclusion, but matched an expired rule
        if matching_expired_rules:
            best_expired = max(matching_expired_rules, key=self.calculate_rule_specificity)
            exp_time = best_expired.expiresAt.isoformat() if best_expired.expiresAt else "unknown"
            return ScopeDecisionResult(
                assessmentId=assessment_id,
                target=cleaned_target,
                decision=ScopeDecision.BLOCK,
                reason=f"Target blocked: scope authorization rule '{best_expired.id}' expired at {exp_time}.",
                matchedScopeItemId=best_expired.id,
                evaluatedAt=now,
            )

        # 4. Default Deny / Fail Closed
        return ScopeDecisionResult(
            assessmentId=assessment_id,
            target=cleaned_target,
            decision=ScopeDecision.BLOCK,
            reason="Target does not match any active authorized scope rule for this assessment.",
            matchedScopeItemId=None,
            evaluatedAt=now,
        )
