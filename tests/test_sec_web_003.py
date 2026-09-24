from app.schemas.common import ExecutionStatus, Severity
from security.collectors.http_header_collector import HttpHeaderCollector
from security.rules.web.sec_web_003 import SecWeb003Rule


def test_sec_web_003_pass_clean_headers():
    collector = HttpHeaderCollector()
    result = collector.collect_from_dict(
        "app.lab.local",
        {"content-type": "text/html; charset=utf-8"},
    )
    rule = SecWeb003Rule()
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.PASS
    assert fnd is None


def test_sec_web_003_warn_version_exposure():
    collector = HttpHeaderCollector()
    result = collector.collect_from_dict(
        "app.lab.local",
        {"server": "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.4.3"},
    )
    rule = SecWeb003Rule()
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.WARN
    assert fnd is not None
    assert fnd["severity"] == Severity.MEDIUM
    assert obs["details"]["versionNumberExposed"] is True
