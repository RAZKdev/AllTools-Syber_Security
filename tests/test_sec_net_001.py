from app.schemas.common import ExecutionStatus, Severity
from security.collectors.port_collector import PortCollector
from security.rules.net.sec_net_001 import SecNet001Rule


def test_sec_net_001_pass_safe_ports():
    collector = PortCollector()
    result = collector.collect_from_dict(
        "app.lab.local",
        {
            "resolvedIp": "192.168.1.50",
            "openPorts": [80, 443],
            "closedPorts": [21, 23, 25, 3306, 5432, 6379, 27017, 3389],
        },
    )
    rule = SecNet001Rule()
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.PASS
    assert fnd is None
    assert obs["details"]["openCount"] == 2


def test_sec_net_001_fail_critical_database_exposed():
    collector = PortCollector()
    result = collector.collect_from_dict(
        "app.lab.local",
        {
            "resolvedIp": "192.168.1.50",
            "openPorts": [80, 443, 6379, 23],  # Redis and Telnet open!
            "closedPorts": [21, 25, 3306],
        },
    )
    rule = SecNet001Rule()
    status, obs, fnd, evd = rule.evaluate("ASM-001", "AST-001", result)

    assert status == ExecutionStatus.FAIL
    assert fnd is not None
    assert fnd["severity"] == Severity.CRITICAL
    assert "Redis" in fnd["title"] or "Telnet" in fnd["title"]
