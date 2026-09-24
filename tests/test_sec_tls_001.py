from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import pytest

from app.schemas.common import ExecutionStatus, FindingStatus
from app.schemas.scope import ScopeItem, ScopeType
from security.collectors.tls_collector import TlsCollector
from security.collectors.http_header_collector import ScopeViolationError
from security.rules.tls.sec_tls_001 import SecTls001Rule

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sec_tls_001"


@pytest.fixture
def rule():
    return SecTls001Rule()


@pytest.fixture
def collector():
    return TlsCollector()


def test_sec_tls_001_pass_fixture(rule, collector):
    """Pass fixture: valid certificate, matching host, modern TLS."""
    with open(FIXTURES_DIR / "pass_cert.json", "r", encoding="utf-8") as f:
        cert_data = json.load(f)

    result = collector.collect_from_dict("app.lab.local", cert_data, tls_version="TLSv1.3")
    status, observation, finding, evidence = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.PASS
    assert finding is None
    assert observation is not None
    assert "matches hostname 'app.lab.local'" in observation["summary"]
    assert len(evidence["sha256"]) == 64


def test_sec_tls_001_expired_fixture(rule, collector):
    """Fail fixture: expired certificate creates high-severity Finding (CWE-298)."""
    with open(FIXTURES_DIR / "expired_cert.json", "r", encoding="utf-8") as f:
        cert_data = json.load(f)

    result = collector.collect_from_dict("app.lab.local", cert_data, tls_version="TLSv1.3")
    status, observation, finding, evidence = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.FAIL
    assert finding is not None
    assert finding["ruleId"] == "SEC-TLS-001"
    assert finding["cwe"] == "CWE-298"
    assert finding["severity"] == "high"
    assert finding["status"] == FindingStatus.NEEDS_REVIEW.value
    assert "expired" in observation["summary"].lower()
    assert evidence["findingId"] == finding["id"]


def test_sec_tls_001_hostname_mismatch(rule, collector):
    """Fail fixture: hostname mismatch generates medium-severity Finding (CWE-297)."""
    with open(FIXTURES_DIR / "mismatch_cert.json", "r", encoding="utf-8") as f:
        cert_data = json.load(f)

    result = collector.collect_from_dict("target.different.local", cert_data, tls_version="TLSv1.3")
    status, observation, finding, evidence = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.FAIL
    assert finding is not None
    assert finding["cwe"] == "CWE-297"
    assert "hostname mismatch" in finding["title"].lower()


def test_sec_tls_001_expiring_soon_warning(rule, collector):
    """Warn: Certificate expiring in <= 14 days produces WARN observation, NOT finding."""
    soon = datetime.now(timezone.utc) + timedelta(days=7)
    cert_data = {
        "commonName": "app.lab.local",
        "subjectAltName": [["DNS", "app.lab.local"]],
        "notAfter": soon.strftime("%b %d %H:%M:%S %Y GMT"),
    }

    result = collector.collect_from_dict("app.lab.local", cert_data, tls_version="TLSv1.3")
    status, observation, finding, evidence = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.WARN
    assert finding is None
    assert observation is not None
    assert "expiring soon" in observation["summary"].lower()


def test_sec_tls_001_insecure_protocol(rule, collector):
    """Fail: Negotiating TLS 1.0 produces FAIL (CWE-326)."""
    with open(FIXTURES_DIR / "pass_cert.json", "r", encoding="utf-8") as f:
        cert_data = json.load(f)

    result = collector.collect_from_dict("app.lab.local", cert_data, tls_version="TLSv1.0")
    status, observation, finding, evidence = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.FAIL
    assert finding is not None
    assert finding["cwe"] == "CWE-326"


def test_tls_collector_scope_guard_enforcement(collector):
    """Ensure TLS collector blocks socket connection if target is out of scope."""
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
            target="unauthorized.target.com",
            assessment_id="ASM-001",
            scope_items=scope_items,
        )

    assert "Scope Guard blocked target" in str(exc_info.value)
