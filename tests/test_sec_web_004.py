from app.schemas.common import ExecutionStatus, Severity
from security.collectors.cors_collector import CorsCollector
from security.rules.web.sec_web_004 import SecWeb004Rule


def test_sec_web_004_pass_safe_cors():
    collector = CorsCollector()
    result = collector.collect_from_dict(
        "app.lab.local",
        {
            "headers": {
                "access-control-allow-origin": "https://trusted-partner.lab.local",
                "access-control-allow-credentials": "true",
            },
            "testedOrigin": "https://evil.attacker.com",
        },
    )
    rule = SecWeb004Rule()
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.PASS
    assert fnd is None


def test_sec_web_004_critical_reflected_origin():
    collector = CorsCollector()
    result = collector.collect_from_dict(
        "app.lab.local",
        {
            "headers": {
                "access-control-allow-origin": "https://evil.attacker.com",
                "access-control-allow-credentials": "true",
            },
            "testedOrigin": "https://evil.attacker.com",
        },
    )
    rule = SecWeb004Rule()
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.FAIL
    assert fnd is not None
    assert fnd["severity"] == Severity.CRITICAL
