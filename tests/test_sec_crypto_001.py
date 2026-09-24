from app.schemas.common import ExecutionStatus, Severity
from security.rules.crypto.sec_crypto_001 import SecCrypto001Rule


def test_sec_crypto_001_pass_sha256():
    rule = SecCrypto001Rule()
    # 64-character valid hex SHA-256
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    assert status == ExecutionStatus.PASS
    assert fnd is None
    assert obs["details"]["detectedAlgorithm"] == "SHA-256"


def test_sec_crypto_001_pass_argon2():
    rule = SecCrypto001Rule()
    status, obs, fnd, evd = rule.evaluate(
        "ASM-001",
        "AST-001",
        "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgqlfreSAeYQ",
    )

    assert status == ExecutionStatus.PASS
    assert fnd is None
    assert obs["details"]["detectedAlgorithm"] == "Argon2"


def test_sec_crypto_001_fail_broken_md5():
    rule = SecCrypto001Rule()
    # 32-character hex MD5
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", "d41d8cd98f00b204e9800998ecf8427e")

    assert status == ExecutionStatus.FAIL
    assert fnd is not None
    assert fnd["severity"] == Severity.CRITICAL
    assert "MD5" in fnd["title"]


def test_sec_crypto_001_fail_deprecated_sha1():
    rule = SecCrypto001Rule()
    # 40-character hex SHA-1
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", "da39a3ee5e6b4b0d3255bfef95601890afd80709")

    assert status == ExecutionStatus.FAIL
    assert fnd is not None
    assert fnd["severity"] == Severity.HIGH
    assert "SHA-1" in fnd["title"]
