-- ============================================================================
-- AllTools-CyberSec Migration 001: Initial Relational Persistence Schema
-- ============================================================================

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    description TEXT NOT NULL
);

-- Backup snapshot tracking (ADR-06)
CREATE TABLE IF NOT EXISTS backup_snapshots (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    sqlite_data_version INTEGER NOT NULL,
    evidence_count INTEGER NOT NULL,
    quarantine_count INTEGER NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    byte_size INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('IN_PROGRESS', 'COMPLETED', 'FAILED'))
);

-- Engagements: Top-level authorization boundary
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL DEFAULT 'WKP-DEFAULT',
    name TEXT NOT NULL,
    description TEXT,
    assessor TEXT,
    status TEXT NOT NULL CHECK(status IN ('draft', 'active', 'completed', 'archived')),
    starts_at TEXT,
    ends_at TEXT,
    rules_of_engagement TEXT,
    is_deleted INTEGER NOT NULL DEFAULT 0 CHECK(is_deleted IN (0, 1)),
    deleted_at TEXT,
    deletion_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Assessments: Specific security testing missions
CREATE TABLE IF NOT EXISTS assessments (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    type TEXT CHECK(type IS NULL OR LOWER(type) IN ('general', 'web', 'api', 'infrastructure', 'cloud', 'hybrid', 'code', 'dependency', 'configuration', 'log', 'incident')),
    status TEXT NOT NULL CHECK(status IN ('draft', 'running', 'in_progress', 'completed', 'failed', 'cancelled')),
    started_at TEXT,
    completed_at TEXT,
    is_deleted INTEGER NOT NULL DEFAULT 0 CHECK(is_deleted IN (0, 1)),
    deleted_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Scope Items: Strict authorization rules governing targets
CREATE TABLE IF NOT EXISTS scope_items (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE RESTRICT,
    type TEXT NOT NULL CHECK(LOWER(type) IN ('domain', 'subdomain', 'ip', 'cidr', 'hostname', 'url', 'application', 'repository', 'log_source', 'file_set', 'cloud_arn')),
    value TEXT NOT NULL,
    environment TEXT,
    in_scope INTEGER NOT NULL CHECK(in_scope IN (0, 1)),
    notes TEXT,
    expires_at TEXT,
    is_deleted INTEGER NOT NULL DEFAULT 0 CHECK(is_deleted IN (0, 1)),
    deleted_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Check Executions: Historical telemetry of automated security rule evaluations
CREATE TABLE IF NOT EXISTS check_executions (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE RESTRICT,
    rule_id TEXT NOT NULL,
    target TEXT NOT NULL,
    scope_decision TEXT NOT NULL CHECK(scope_decision IN ('ALLOW', 'BLOCK')),
    status TEXT NOT NULL CHECK(status IN ('PENDING', 'RUNNING', 'PASS', 'FAIL', 'WARN', 'ERROR', 'BLOCKED_OUT_OF_SCOPE', 'NOT_TESTED', 'INSUFFICIENT_DATA', 'INTERRUPTED', 'UNKNOWN')),
    rule_version TEXT,
    duration_ms INTEGER,
    error_code TEXT,
    error_message TEXT,
    request_fingerprint TEXT,
    executed_at TEXT NOT NULL
);

-- Findings: Discovered security vulnerabilities
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE RESTRICT,
    asset_id TEXT NOT NULL,
    rule_id TEXT,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL CHECK(UPPER(status) IN ('DETECTED', 'NEEDS_REVIEW', 'CONFIRMED', 'FALSE_POSITIVE', 'ACCEPTED_RISK', 'MITIGATED', 'REMEDIATION', 'RETEST_REQUIRED', 'RESOLVED', 'REGRESSION', 'OPEN', 'ACCEPTED', 'REMEDIATED')),
    severity TEXT NOT NULL CHECK(LOWER(severity) IN ('critical', 'high', 'medium', 'low', 'informational')),
    confidence TEXT NOT NULL CHECK(LOWER(confidence) IN ('certain', 'firm', 'tentative', 'high', 'medium', 'low')),
    cwe TEXT,
    cve TEXT,
    cvss REAL CHECK(cvss IS NULL OR (cvss >= 0.0 AND cvss <= 10.0)),
    impact TEXT,
    recommendation TEXT,
    is_deleted INTEGER NOT NULL DEFAULT 0 CHECK(is_deleted IN (0, 1)),
    deleted_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Evidence Metadata: Pointer and verification index for on-disk artifacts (ADR-03, ADR-05)
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE RESTRICT,
    finding_id TEXT REFERENCES findings(id) ON DELETE SET NULL,
    type TEXT NOT NULL CHECK(type IN ('http_request', 'http_response', 'log_snippet', 'log_excerpt', 'raw_output', 'json_result', 'screenshot', 'file', 'configuration_snapshot', 'hash', 'other')),
    source TEXT NOT NULL,
    artifact_path TEXT NOT NULL UNIQUE,
    captured_at TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    redacted INTEGER NOT NULL CHECK(redacted IN (0, 1)),
    notes TEXT,
    sync_status TEXT NOT NULL DEFAULT 'COMMITTED' CHECK(sync_status IN ('PREPARED', 'COMMITTED', 'COLLISION_ERROR', 'ORPHANED', 'MISSING_FILE', 'CORRUPTED', 'QUARANTINED', 'PURGED')),
    retention_policy TEXT NOT NULL DEFAULT 'retain_90_days' CHECK(retention_policy IN ('retain_indefinite', 'retain_90_days', 'custom')),
    purge_eligible_at TEXT,
    legal_hold INTEGER NOT NULL DEFAULT 0 CHECK(legal_hold IN (0, 1)),
    is_deleted INTEGER NOT NULL DEFAULT 0 CHECK(is_deleted IN (0, 1)),
    deleted_at TEXT
);

-- Quarantine Items: Primary ledger of isolated artifacts (ADR-02)
CREATE TABLE IF NOT EXISTS quarantine_items (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    quarantine_id TEXT NOT NULL UNIQUE,
    original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL,
    byte_size INTEGER NOT NULL,
    reason TEXT NOT NULL CHECK(reason IN ('INVALID_JSON', 'UNKNOWN_SCHEMA', 'HASH_MISMATCH', 'ORPHAN_NO_ASSESSMENT', 'TEST_ARTIFACT', 'MANUAL_QUARANTINE')),
    details TEXT,
    prev_entry_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    quarantined_at TEXT NOT NULL,
    recovered_at TEXT,
    recovery_target_id TEXT
);

-- Audit Logs: Structured Operational Audit Log
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    actor_id TEXT,
    action TEXT NOT NULL,
    object_type TEXT,
    object_id TEXT,
    before_state TEXT,
    after_state TEXT,
    occurred_at TEXT NOT NULL
);

-- ============================================================================
-- Partial Indexes for Soft Deletes and Hot Query Paths
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_engagements_active ON engagements(id) WHERE is_deleted = 0;
CREATE INDEX IF NOT EXISTS idx_assessments_active ON assessments(id, engagement_id) WHERE is_deleted = 0;
CREATE INDEX IF NOT EXISTS idx_scope_items_active ON scope_items(engagement_id) WHERE is_deleted = 0;
CREATE INDEX IF NOT EXISTS idx_check_executions_assessment ON check_executions(assessment_id);
CREATE INDEX IF NOT EXISTS idx_check_executions_target ON check_executions(target);
CREATE INDEX IF NOT EXISTS idx_findings_active ON findings(assessment_id, severity) WHERE is_deleted = 0;
CREATE INDEX IF NOT EXISTS idx_evidence_active ON evidence(assessment_id) WHERE is_deleted = 0;
CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence(sha256);
CREATE INDEX IF NOT EXISTS idx_quarantine_sha256 ON quarantine_items(sha256);
CREATE INDEX IF NOT EXISTS idx_audit_logs_occurred ON audit_logs(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_backup_snapshots_status ON backup_snapshots(status, created_at DESC);
