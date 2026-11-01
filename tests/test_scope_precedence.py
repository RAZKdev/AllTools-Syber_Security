import pytest
from datetime import datetime, timezone, timedelta

from app.schemas.scope import ScopeItem, ScopeType
from app.schemas.common import ScopeDecision
from app.services.scope_guard import ScopeGuard


@pytest.fixture
def scope_guard():
    return ScopeGuard()


def test_parent_inclusion_allows_parent_and_child(scope_guard):
    """Parent inclusion allows both the parent domain and subdomains."""
    rules = [
        ScopeItem(id="SCP-P1", engagementId="ENG-1", type=ScopeType.DOMAIN, value="lab.local", inScope=True),
    ]
    res_parent = scope_guard.evaluate_target("ASM-1", "lab.local", rules)
    assert res_parent.decision == ScopeDecision.ALLOW
    assert res_parent.matchedScopeItemId == "SCP-P1"

    res_child = scope_guard.evaluate_target("ASM-1", "app.lab.local", rules)
    assert res_child.decision == ScopeDecision.ALLOW
    assert res_child.matchedScopeItemId == "SCP-P1"


def test_child_inclusion_allows_only_specific_child(scope_guard):
    """Child inclusion allows only the specified subdomain, parent remains default-denied."""
    rules = [
        ScopeItem(id="SCP-C1", engagementId="ENG-1", type=ScopeType.DOMAIN, value="app.lab.local", inScope=True),
    ]
    res_child = scope_guard.evaluate_target("ASM-1", "app.lab.local", rules)
    assert res_child.decision == ScopeDecision.ALLOW
    assert res_child.matchedScopeItemId == "SCP-C1"

    res_parent = scope_guard.evaluate_target("ASM-1", "lab.local", rules)
    assert res_parent.decision == ScopeDecision.BLOCK
    assert "Target does not match any active authorized scope rule" in res_parent.reason


def test_expired_child_rule_does_not_inherit_from_parent_inclusion(scope_guard):
    """A matching, more-specific expired rule must not silently inherit from broader parent inclusion."""
    now = datetime.now(timezone.utc)
    rules = [
        ScopeItem(id="SCP-P1", engagementId="ENG-1", type=ScopeType.DOMAIN, value="lab.local", inScope=True),
        ScopeItem(
            id="SCP-C-EXP",
            engagementId="ENG-1",
            type=ScopeType.DOMAIN,
            value="expired.lab.local",
            inScope=True,
            expiresAt=now - timedelta(hours=2),
        ),
    ]
    # Target matching expired rule must be BLOCKED
    res_expired = scope_guard.evaluate_target("ASM-1", "expired.lab.local", rules)
    assert res_expired.decision == ScopeDecision.BLOCK
    assert "expired" in res_expired.reason.lower()
    assert res_expired.matchedScopeItemId == "SCP-C-EXP"

    # Deep subdomain of expired rule also blocked
    res_sub_expired = scope_guard.evaluate_target("ASM-1", "sub.expired.lab.local", rules)
    assert res_sub_expired.decision == ScopeDecision.BLOCK

    # Other active subdomains under parent must still be allowed
    res_active = scope_guard.evaluate_target("ASM-1", "active.lab.local", rules)
    assert res_active.decision == ScopeDecision.ALLOW
    assert res_active.matchedScopeItemId == "SCP-P1"


def test_explicit_exclusion_always_takes_absolute_precedence(scope_guard):
    """Explicit exclusion (inScope=False) always denies, even with active inclusion."""
    rules = [
        ScopeItem(id="SCP-P1", engagementId="ENG-1", type=ScopeType.DOMAIN, value="lab.local", inScope=True),
        ScopeItem(id="SCP-EXCL", engagementId="ENG-1", type=ScopeType.DOMAIN, value="critical.lab.local", inScope=False),
    ]
    res_excl = scope_guard.evaluate_target("ASM-1", "critical.lab.local", rules)
    assert res_excl.decision == ScopeDecision.BLOCK
    assert "explicitly excluded" in res_excl.reason.lower()
    assert res_excl.matchedScopeItemId == "SCP-EXCL"

    res_sub_excl = scope_guard.evaluate_target("ASM-1", "sub.critical.lab.local", rules)
    assert res_sub_excl.decision == ScopeDecision.BLOCK
    assert "explicitly excluded" in res_sub_excl.reason.lower()


def test_default_deny_for_unknown_targets(scope_guard):
    """Unknown targets follow fail-closed default-deny."""
    rules = [
        ScopeItem(id="SCP-P1", engagementId="ENG-1", type=ScopeType.DOMAIN, value="lab.local", inScope=True),
    ]
    res = scope_guard.evaluate_target("ASM-1", "external-evil.com", rules)
    assert res.decision == ScopeDecision.BLOCK
    assert "Target does not match any active authorized scope rule" in res.reason


def test_reauthorization_via_active_rule_succeeds(scope_guard):
    """Updating/reauthorizing an expired rule with future expiration allows target again."""
    now = datetime.now(timezone.utc)
    rules = [
        ScopeItem(id="SCP-P1", engagementId="ENG-1", type=ScopeType.DOMAIN, value="lab.local", inScope=True),
        ScopeItem(
            id="SCP-C-REAUTH",
            engagementId="ENG-1",
            type=ScopeType.DOMAIN,
            value="expired.lab.local",
            inScope=True,
            expiresAt=now + timedelta(hours=24),  # Valid in future
        ),
    ]
    res = scope_guard.evaluate_target("ASM-1", "expired.lab.local", rules)
    assert res.decision == ScopeDecision.ALLOW
    assert res.matchedScopeItemId == "SCP-C-REAUTH"
