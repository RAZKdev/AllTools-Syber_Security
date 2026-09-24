from datetime import datetime, timedelta, timezone
import pytest

from app.schemas.common import ScopeDecision
from app.schemas.scope import ScopeItem, ScopeType
from app.services.scope_guard import ScopeGuard


@pytest.fixture
def scope_guard():
    return ScopeGuard()


def test_scope_guard_default_deny(scope_guard):
    """Out-of-scope targets must be blocked by default."""
    scope_items = [
        ScopeItem(
            id="SCP-01",
            engagementId="ENG-01",
            type=ScopeType.DOMAIN,
            value="lab.internal",
            inScope=True,
        )
    ]
    result = scope_guard.evaluate_target("ASM-01", "unauthorized.com", scope_items)
    assert result.decision == ScopeDecision.BLOCK
    assert not result.is_allowed
    assert "Target does not match any active authorized scope rule" in result.reason
    assert "BLOCKED — OUT OF SCOPE" in result.format_scope_block()


def test_scope_guard_domain_and_subdomain(scope_guard):
    """Authorized domain and subdomain match."""
    scope_items = [
        ScopeItem(
            id="SCP-DOM",
            engagementId="ENG-01",
            type=ScopeType.DOMAIN,
            value="lab.test",
            inScope=True,
        ),
        ScopeItem(
            id="SCP-SUB",
            engagementId="ENG-01",
            type=ScopeType.SUBDOMAIN,
            value="*.api.lab.test",
            inScope=True,
        ),
    ]

    # Exact domain
    res1 = scope_guard.evaluate_target("ASM-01", "lab.test", scope_items)
    assert res1.decision == ScopeDecision.ALLOW

    # Subdomain of domain
    res2 = scope_guard.evaluate_target("ASM-01", "sub.lab.test", scope_items)
    assert res2.decision == ScopeDecision.ALLOW

    # Subdomain wildcard match
    res3 = scope_guard.evaluate_target("ASM-01", "v1.api.lab.test", scope_items)
    assert res3.decision == ScopeDecision.ALLOW

    # Unrelated domain
    res4 = scope_guard.evaluate_target("ASM-01", "evil.com", scope_items)
    assert res4.decision == ScopeDecision.BLOCK


def test_scope_guard_ip_and_cidr(scope_guard):
    """IP and CIDR range matching."""
    scope_items = [
        ScopeItem(
            id="SCP-IP",
            engagementId="ENG-01",
            type=ScopeType.IP,
            value="192.168.1.100",
            inScope=True,
        ),
        ScopeItem(
            id="SCP-CIDR",
            engagementId="ENG-01",
            type=ScopeType.CIDR,
            value="10.10.0.0/16",
            inScope=True,
        ),
    ]

    # Exact IP
    res1 = scope_guard.evaluate_target("ASM-01", "192.168.1.100", scope_items)
    assert res1.decision == ScopeDecision.ALLOW

    # Target with port
    res2 = scope_guard.evaluate_target("ASM-01", "192.168.1.100:8443", scope_items)
    assert res2.decision == ScopeDecision.ALLOW

    # IP in CIDR
    res3 = scope_guard.evaluate_target("ASM-01", "10.10.5.24", scope_items)
    assert res3.decision == ScopeDecision.ALLOW

    # IP outside CIDR
    res4 = scope_guard.evaluate_target("ASM-01", "10.11.0.1", scope_items)
    assert res4.decision == ScopeDecision.BLOCK


def test_scope_guard_explicit_exclusion_priority(scope_guard):
    """Explicit exclusions (inScope=False) take absolute precedence over inclusions."""
    scope_items = [
        ScopeItem(
            id="SCP-INCL",
            engagementId="ENG-01",
            type=ScopeType.DOMAIN,
            value="corp.internal",
            inScope=True,
        ),
        ScopeItem(
            id="SCP-EXCL",
            engagementId="ENG-01",
            type=ScopeType.DOMAIN,
            value="billing.corp.internal",
            inScope=False,  # Explicit exclusion
            notes="Billing system is strictly out of scope",
        ),
    ]

    # General domain allowed
    res_ok = scope_guard.evaluate_target("ASM-01", "portal.corp.internal", scope_items)
    assert res_ok.decision == ScopeDecision.ALLOW

    # Excluded subdomain blocked
    res_blocked = scope_guard.evaluate_target("ASM-01", "billing.corp.internal", scope_items)
    assert res_blocked.decision == ScopeDecision.BLOCK
    assert res_blocked.matchedScopeItemId == "SCP-EXCL"
    assert "explicitly excluded" in res_blocked.reason


def test_scope_guard_expired_rule(scope_guard):
    """Expired scope items must not authorize any target."""
    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    scope_items = [
        ScopeItem(
            id="SCP-EXP",
            engagementId="ENG-01",
            type=ScopeType.DOMAIN,
            value="expired-lab.test",
            inScope=True,
            expiresAt=yesterday,
        )
    ]

    res = scope_guard.evaluate_target("ASM-01", "expired-lab.test", scope_items)
    assert res.decision == ScopeDecision.BLOCK


def test_scope_guard_empty_target(scope_guard):
    """Empty target specification is blocked immediately."""
    scope_items = [
        ScopeItem(
            id="SCP-ALL",
            engagementId="ENG-01",
            type=ScopeType.DOMAIN,
            value="test.internal",
            inScope=True,
        )
    ]
    res = scope_guard.evaluate_target("ASM-01", "   ", scope_items)
    assert res.decision == ScopeDecision.BLOCK
    assert "empty" in res.reason.lower()
