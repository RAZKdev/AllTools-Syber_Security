import json
from pathlib import Path
import pytest

from app.schemas.common import ExecutionStatus, FindingStatus
from app.schemas.scope import ScopeItem, ScopeType
from security.collectors.dns_collector import DnsCollector
from security.collectors.http_header_collector import ScopeViolationError
from security.rules.dns.sec_dns_001 import SecDns001Rule

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sec_dns_001"


@pytest.fixture
def rule():
    return SecDns001Rule()


@pytest.fixture
def collector():
    return DnsCollector()


def test_sec_dns_001_pass_fixture(rule, collector):
    """Pass fixture: hardened SPF (-all) and DMARC (p=reject) policies."""
    with open(FIXTURES_DIR / "pass_dns.json", "r", encoding="utf-8") as f:
        records = json.load(f)

    result = collector.collect_from_dict("mail.lab.local", records)
    status, observation, finding, evidence = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.PASS
    assert finding is None
    assert observation is not None
    assert "hardened SPF and DMARC" in observation["summary"]
    assert len(evidence["sha256"]) == 64


def test_sec_dns_001_fail_fixture(rule, collector):
    """Fail fixture: missing SPF/DMARC produces FAIL and registers a Finding."""
    with open(FIXTURES_DIR / "fail_dns.json", "r", encoding="utf-8") as f:
        records = json.load(f)

    result = collector.collect_from_dict("spoofable.lab.local", records)
    status, observation, finding, evidence = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.FAIL
    assert finding is not None
    assert finding["ruleId"] == "SEC-DNS-001"
    assert finding["cwe"] == "CWE-358"
    assert finding["status"] == FindingStatus.NEEDS_REVIEW.value
    assert "missing" in observation["summary"].lower()
    assert evidence["findingId"] == finding["id"]


def test_sec_dns_001_warn_fixture(rule, collector):
    """Warn fixture: records present but with weak policies (+all, p=none)."""
    with open(FIXTURES_DIR / "warn_dns.json", "r", encoding="utf-8") as f:
        records = json.load(f)

    result = collector.collect_from_dict("weak-policy.lab.local", records)
    status, observation, finding, evidence = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.WARN
    assert finding is None
    assert observation is not None
    assert len(observation["details"]["warnings"]) == 2


def test_dns_collector_scope_guard_enforcement(collector):
    """Ensure DNS collector verifies scope before querying."""
    scope_items = [
        ScopeItem(
            id="SCP-01",
            engagementId="ENG-01",
            type=ScopeType.DOMAIN,
            value="authorized.lab",
            inScope=True,
        )
    ]

    with pytest.raises(ScopeViolationError) as exc_info:
        collector.collect_from_network(
            domain="unauthorized-external.com",
            assessment_id="ASM-001",
            scope_items=scope_items,
        )

    assert "Scope Guard blocked target" in str(exc_info.value)
