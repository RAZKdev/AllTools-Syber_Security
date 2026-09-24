from app.schemas.common import ExecutionStatus, Severity
from security.collectors.sensitive_file_collector import SensitiveFileCollector
from security.rules.web.sec_web_005 import SecWeb005Rule


def test_sec_web_005_pass_compliant():
    collector = SensitiveFileCollector()
    result = collector.collect_from_dict(
        "app.lab.local",
        {
            "paths": {
                "/.well-known/security.txt": {"statusCode": 200, "accessible": True, "snippet": "Contact: security@lab.local"},
                "/.git/HEAD": {"statusCode": 404, "accessible": False},
                "/.env": {"statusCode": 404, "accessible": False},
            }
        },
    )
    rule = SecWeb005Rule()
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.PASS
    assert fnd is None


def test_sec_web_005_critical_dotfile_exposure():
    collector = SensitiveFileCollector()
    result = collector.collect_from_dict(
        "app.lab.local",
        {
            "paths": {
                "/.well-known/security.txt": {"statusCode": 200, "accessible": True},
                "/.git/HEAD": {"statusCode": 200, "accessible": True, "snippet": "ref: refs/heads/main"},
                "/.env": {"statusCode": 200, "accessible": True, "snippet": "DB_PASSWORD=secret"},
            }
        },
    )
    rule = SecWeb005Rule()
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.FAIL
    assert fnd is not None
    assert fnd["severity"] == Severity.CRITICAL
