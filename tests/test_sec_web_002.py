from app.schemas.common import ExecutionStatus, Severity
from security.collectors.cookie_collector import CookieCollector
from security.rules.web.sec_web_002 import SecWeb002Rule


def test_sec_web_002_pass():
    collector = CookieCollector()
    result = collector.collect_from_dict(
        "app.lab.local",
        {"setCookie": ["session=abc12345; Secure; HttpOnly; SameSite=Strict"]},
    )
    rule = SecWeb002Rule()
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.PASS
    assert fnd is None
    assert obs["details"]["insecureCount"] == 0


def test_sec_web_002_fail_missing_secure():
    collector = CookieCollector()
    result = collector.collect_from_dict(
        "app.lab.local",
        {"setCookie": ["session=abc12345; HttpOnly; SameSite=Lax"]},
    )
    rule = SecWeb002Rule()
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.FAIL
    assert fnd is not None
    assert fnd["severity"] == Severity.HIGH
    assert "Missing 'Secure' flag" in str(obs["details"]["insecureCookies"])
