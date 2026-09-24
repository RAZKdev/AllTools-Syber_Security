import json
from pathlib import Path
import pytest

from app.schemas.common import ExecutionStatus, FindingStatus
from app.schemas.scope import ScopeItem, ScopeType
from security.collectors.http_header_collector import (
    HttpHeaderCollector,
    ScopeViolationError,
)
from security.rules.web.sec_web_001 import SecWeb001Rule

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sec_web_001"


@pytest.fixture
def rule():
    return SecWeb001Rule()


@pytest.fixture
def collector():
    return HttpHeaderCollector()


def test_sec_web_001_pass_fixture(rule, collector):
    """Pass fixture: hardened response headers with all required protections."""
    fixture_path = FIXTURES_DIR / "pass_headers.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        headers = json.load(f)

    result = collector.collect_from_dict("https://hardened.lab.local", headers)
    status, observation, finding, evidence = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.PASS
    assert finding is None
    assert observation is not None
    assert "All required HTTP security headers are present" in observation["summary"]
    assert len(evidence["sha256"]) == 64


def test_sec_web_001_fail_fixture(rule, collector):
    """Fail fixture: zero security headers returns FAIL and creates a formal Finding."""
    fixture_path = FIXTURES_DIR / "fail_headers.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        headers = json.load(f)

    result = collector.collect_from_dict("https://vulnerable.lab.local", headers)
    status, observation, finding, evidence = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.FAIL
    assert finding is not None
    assert finding["ruleId"] == "SEC-WEB-001"
    assert finding["status"] == FindingStatus.NEEDS_REVIEW.value
    assert finding["cwe"] == "CWE-693"
    assert "content-security-policy" in observation["details"]["missingRequired"]
    assert evidence["findingId"] == finding["id"]


def test_sec_web_001_warn_fixture(rule, collector):
    """Warn fixture: headers present but with security warnings (e.g. unsafe-inline)."""
    fixture_path = FIXTURES_DIR / "warn_headers.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        headers = json.load(f)

    result = collector.collect_from_dict("https://partial.lab.local", headers)
    status, observation, finding, evidence = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.WARN
    assert finding is None  # A warning is an observation, not a confirmed vulnerability finding
    assert observation is not None
    assert any("unsafe-inline" in w for w in observation["details"]["configWarnings"])


def test_collector_scope_guard_blocks_out_of_scope(collector):
    """Verify Scope Guard strictly blocks out-of-scope targets before network dispatch."""
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
            target_url="https://unauthorized-external-site.com",
            assessment_id="ASM-001",
            scope_items=scope_items,
        )

    assert "Scope Guard blocked target" in str(exc_info.value)
