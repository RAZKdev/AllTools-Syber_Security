from app.schemas.common import ExecutionStatus, Severity
from security.rules.auth.sec_auth_001 import SecAuth001Rule


def test_sec_auth_001_pass_strong_passphrase():
    rule = SecAuth001Rule()
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", "Correct-Horse-Battery-Staple-2026!")

    assert status == ExecutionStatus.PASS
    assert fnd is None
    assert obs["details"]["strength"] in ("STRONG", "VERY_STRONG")


def test_sec_auth_001_fail_common_weak_password():
    rule = SecAuth001Rule()
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", "password123")

    assert status == ExecutionStatus.FAIL
    assert fnd is not None
    assert fnd["severity"] == Severity.CRITICAL
    assert obs["details"]["isCommonPattern"] is True


def test_sec_auth_001_fail_short_length():
    rule = SecAuth001Rule()
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", "aA1!")

    assert status == ExecutionStatus.FAIL
    assert fnd is not None
    assert obs["details"]["length"] < 8
