from enum import Enum


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ExecutionStatus(str, Enum):
    # Non-terminal in-flight states
    PENDING = "PENDING"
    RUNNING = "RUNNING"

    # Terminal states
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    NOT_TESTED = "NOT_TESTED"
    ERROR = "ERROR"
    BLOCKED_OUT_OF_SCOPE = "BLOCKED_OUT_OF_SCOPE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    INTERRUPTED = "INTERRUPTED"
    UNKNOWN = "UNKNOWN"


TERMINAL_EXECUTION_STATUSES = {
    ExecutionStatus.PASS,
    ExecutionStatus.FAIL,
    ExecutionStatus.WARN,
    ExecutionStatus.NOT_TESTED,
    ExecutionStatus.ERROR,
    ExecutionStatus.BLOCKED_OUT_OF_SCOPE,
    ExecutionStatus.INSUFFICIENT_DATA,
    ExecutionStatus.INTERRUPTED,
    ExecutionStatus.UNKNOWN,
}

NON_TERMINAL_EXECUTION_STATUSES = {
    ExecutionStatus.PENDING,
    ExecutionStatus.RUNNING,
}


class FindingStatus(str, Enum):
    DETECTED = "DETECTED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    MITITGATED = "MITIGATED"
    REMEDIATION = "REMEDIATION"
    RETEST_REQUIRED = "RETEST_REQUIRED"
    RESOLVED = "RESOLVED"
    REGRESSION = "REGRESSION"


class Environment(str, Enum):
    LAB = "lab"
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    UNKNOWN = "unknown"


class Exposure(str, Enum):
    INTERNAL = "internal"
    RESTRICTED = "restricted"
    PUBLIC = "public"
    UNKNOWN = "unknown"


class ScopeDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
