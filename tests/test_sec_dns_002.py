from app.schemas.common import ExecutionStatus, Severity
from security.collectors.dns_collector import DnsCollector
from security.rules.dns.sec_dns_002 import SecDns002Rule


def test_sec_dns_002_pass_caa_present():
    collector = DnsCollector()
    result = collector.collect_from_dict(
        "lab.local",
        {"CAA": ["0 issue \"letsencrypt.org\"", "0 iodef \"mailto:sec@lab.local\""]},
    )
    rule = SecDns002Rule()
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.PASS
    assert fnd is None
    assert obs["details"]["hasCaa"] is True


def test_sec_dns_002_warn_caa_missing():
    collector = DnsCollector()
    result = collector.collect_from_dict(
        "lab.local",
        {"A": ["192.168.1.10"], "CAA": []},
    )
    rule = SecDns002Rule()
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.WARN
    assert fnd is not None
    assert fnd["severity"] == Severity.LOW
