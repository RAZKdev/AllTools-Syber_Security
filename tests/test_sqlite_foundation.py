import os
import sqlite3
import pytest
from datetime import datetime, timezone
from pathlib import Path

from app.core.storage_paths import (
    ConfigurationError,
    StoragePaths,
    ensure_storage_directories,
    get_storage_paths,
    resolve_data_dir,
)
from app.core.database import (
    check_database_health,
    create_connection,
    get_db_connection,
    transaction,
)
from app.core.migration_runner import MigrationError, MigrationRunner
from app.core.database_init import initialize_database, seed_laboratory_fixtures
from app.repositories.sqlite_scope_repository import SqliteScopeRepository
from app.repositories.sqlite_findings_repository import SqliteFindingsRepository
from app.repositories.sqlite_execution_repository import SqliteExecutionRepository
from app.repositories.sqlite_audit_repository import SqliteAuditRepository
from app.services.scope_guard import ScopeGuard

from app.schemas.engagement import EngagementCreate, EngagementStatus
from app.schemas.assessment import AssessmentCreate, AssessmentStatus, AssessmentType
from app.schemas.scope import ScopeItemCreate, ScopeType
from app.schemas.finding import FindingCreate
from app.schemas.check_execution import CheckExecution
from app.schemas.audit_log import AuditLogCreate
from app.schemas.common import ExecutionStatus, ScopeDecision, FindingStatus


# ============================================================================
# 1. Storage Paths & Fail-Closed Tests
# ============================================================================

def test_resolve_data_dir_with_valid_override(tmp_path: Path):
    custom = tmp_path / "custom_data_dir"
    resolved = resolve_data_dir(env_override=str(custom))
    assert resolved == custom.resolve()
    assert resolved.exists()


def test_resolve_data_dir_fails_closed_on_invalid_path():
    invalid_path = "\0invalid_path"
    with pytest.raises(ConfigurationError) as exc_info:
        resolve_data_dir(env_override=invalid_path)
    assert "invalid or inaccessible" in str(exc_info.value)


def test_get_storage_paths_and_directory_creation(tmp_path: Path):
    custom = tmp_path / "app_data"
    paths = get_storage_paths(custom_data_dir=custom)

    assert paths.data_dir == custom
    assert paths.database_file == custom / "workbench.db"
    assert paths.evidence_dir == custom / "evidence"
    assert paths.quarantine_dir == custom / "quarantine"
    assert paths.backups_dir == custom / "backups"

    ensure_storage_directories(paths)
    assert paths.data_dir.is_dir()
    assert paths.evidence_dir.is_dir()
    assert paths.quarantine_dir.is_dir()
    assert paths.backups_dir.is_dir()


# ============================================================================
# 2. Connection Management & Pragma Verification
# ============================================================================

def test_connection_enforces_foreign_keys_and_pragmas(tmp_path: Path):
    db_file = tmp_path / "test.db"
    conn = create_connection(db_file)
    try:
        fk = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
        assert fk == 1, "Foreign keys must be ON"

        timeout = conn.execute("PRAGMA busy_timeout;").fetchone()[0]
        assert timeout == 5000, "Busy timeout must be 5000ms"

        journal = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert journal.lower() == "wal", "File database must use WAL mode"
    finally:
        conn.close()


# ============================================================================
# 3. Migration Runner, Health Check & Transaction Atomicity (P1)
# ============================================================================

def test_migration_runner_applies_initial_schema(tmp_path: Path):
    db_file = tmp_path / "test.db"
    runner = MigrationRunner(db_path=db_file)

    assert runner.get_current_version() == 0

    applied_version = runner.apply_pending_migrations()
    assert applied_version == 1
    assert runner.get_current_version() == 1

    # Idempotent re-run
    second_run = runner.apply_pending_migrations()
    assert second_run == 1


def test_database_health_check_healthy(tmp_path: Path):
    db_file = tmp_path / "test.db"
    initialize_database(db_path=db_file)

    health = check_database_health(db_path=db_file)
    assert health["status"] == "healthy"
    assert health["foreignKeys"] is True
    assert health["integrityCheck"] == "ok"
    assert health["schemaVersion"] == 1
    assert health["writeCapability"] is True


def test_migration_runner_rolls_back_atomically_on_error(tmp_path: Path):
    """Verify that a partially failed SQL migration leaves zero partially created tables (P1)."""
    db_file = tmp_path / "rollback_test.db"
    bad_migrations_dir = tmp_path / "migrations"
    bad_migrations_dir.mkdir()

    # Migration 001: Valid table creation
    (bad_migrations_dir / "001_valid.sql").write_text(
        "CREATE TABLE valid_table (id INT PRIMARY KEY);", encoding="utf-8"
    )

    runner = MigrationRunner(db_path=db_file, migrations_dir=bad_migrations_dir)
    # Apply migration 1 successfully
    assert runner.apply_pending_migrations() == 1

    # Migration 002: Malformed SQL (syntax error after creating partial_table)
    (bad_migrations_dir / "002_broken.sql").write_text(
        "CREATE TABLE partial_table (id INT);\nSYNTAX_ERROR_ABORT;\nCREATE TABLE never_reached (id INT);",
        encoding="utf-8",
    )

    # Apply migration 2 (must fail and rollback partial_table completely)
    with pytest.raises(MigrationError):
        runner.apply_pending_migrations()

    # Verify version remains 1 and partial_table was rolled back
    assert runner.get_current_version() == 1
    with get_db_connection(db_file) as conn:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
        assert "valid_table" in tables
        assert "partial_table" not in tables, "Partially created table must be rolled back on error!"

    # Correct migration 002 and safely retry
    (bad_migrations_dir / "002_broken.sql").write_text(
        "CREATE TABLE partial_table (id INT);\nCREATE TABLE never_reached (id INT);",
        encoding="utf-8",
    )
    final_version = runner.apply_pending_migrations()
    assert final_version == 2
    with get_db_connection(db_file) as conn:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
        assert "partial_table" in tables
        assert "never_reached" in tables


# ============================================================================
# 4. Production Initialization: Strict Default-Deny (P0)
# ============================================================================

def test_fresh_production_database_strict_default_deny(tmp_path: Path):
    """
    Verify P0 requirement: A fresh production database contains zero engagements,
    zero assessments, zero scope items, and strictly enforces Default-Deny.
    """
    db_file = tmp_path / "fresh_production.db"
    version = initialize_database(db_path=db_file)
    assert version == 1

    repo = SqliteScopeRepository(db_path=db_file)
    assert len(repo.list_engagements()) == 0
    assert len(repo.list_assessments()) == 0
    assert len(repo.list_scope_items()) == 0

    # Scope Guard evaluation against any target must strictly evaluate to BLOCK
    guard = ScopeGuard()
    decision = guard.evaluate_target(
        assessment_id="ASM-ANY",
        target="192.168.1.1",
        scope_items=repo.list_scope_items(),
    )
    assert decision.decision == ScopeDecision.BLOCK
    assert not decision.is_allowed
    assert "does not match any active authorized scope rule" in decision.reason or "Default-Deny" in decision.reason


def test_reinitializing_production_database_never_inserts_fixtures(tmp_path: Path):
    """Reinitializing a production database must never automatically inject demo/lab fixtures."""
    db_file = tmp_path / "prod.db"
    initialize_database(db_path=db_file)

    repo = SqliteScopeRepository(db_path=db_file)
    assert len(repo.list_engagements()) == 0

    # Re-run initialization
    initialize_database(db_path=db_file)
    assert len(repo.list_engagements()) == 0
    assert len(repo.list_scope_items()) == 0


def test_explicit_laboratory_fixture_seeding(tmp_path: Path):
    """Verify that seed_laboratory_fixtures works strictly when explicitly called for test harnesses."""
    db_file = tmp_path / "lab_test.db"
    initialize_database(db_path=db_file)

    repo = SqliteScopeRepository(db_path=db_file)
    assert len(repo.list_engagements()) == 0

    # Explicit call for test harness
    seed_laboratory_fixtures(db_file)

    eng = repo.get_engagement("ENG-001")
    assert eng is not None
    assert eng.name == "Laboratory Defensive Security Assessment"

    asm = repo.get_assessment("ASM-001")
    assert asm is not None
    assert asm.engagementId == "ENG-001"

    scope_items = repo.list_scope_items("ENG-001")
    assert len(scope_items) == 3

    # Idempotent: calling again does not duplicate or fail
    seed_laboratory_fixtures(db_file)
    assert len(repo.list_engagements()) == 1


# ============================================================================
# 5. Referential Integrity & Transactions
# ============================================================================

def test_foreign_key_violation_raises_error(tmp_path: Path):
    db_file = tmp_path / "test.db"
    initialize_database(db_path=db_file)

    repo = SqliteScopeRepository(db_path=db_file)

    # Attempting to create assessment for non-existent engagement
    with pytest.raises(ValueError) as exc:
        repo.create_assessment(
            AssessmentCreate(
                engagementId="ENG-NONEXISTENT",
                name="Orphan Assessment",
                type=AssessmentType.WEB,
                status=AssessmentStatus.DRAFT,
            )
        )
    assert "does not exist" in str(exc.value)


def test_transaction_rollback_on_failure(tmp_path: Path):
    db_file = tmp_path / "test.db"
    initialize_database(db_path=db_file)

    try:
        with transaction(db_path=db_file) as conn:
            conn.execute(
                """
                INSERT INTO engagements (
                    id, workspace_id, name, assessor, status,
                    rules_of_engagement, is_deleted, created_at, updated_at
                ) VALUES ('ENG-TX-TEST', 'WKS-1', 'Tx Test', 'Tester', 'active', 'None', 0, '2026-01-01', '2026-01-01');
                """
            )
            raise RuntimeError("Simulated failure inside transaction")
    except RuntimeError:
        pass

    repo = SqliteScopeRepository(db_path=db_file)
    assert repo.get_engagement("ENG-TX-TEST") is None


# ============================================================================
# 6. SqliteScopeRepository Soft Deletion & Cascading
# ============================================================================

def test_scope_repository_crud_and_soft_delete_cascade(tmp_path: Path):
    db_file = tmp_path / "test.db"
    initialize_database(db_path=db_file)
    seed_laboratory_fixtures(db_file)

    repo = SqliteScopeRepository(db_path=db_file)

    assert repo.get_engagement("ENG-001") is not None
    assert repo.get_assessment("ASM-001") is not None
    assert repo.get_scope_item("SCP-001") is not None

    # Soft delete engagement
    success = repo.soft_delete_engagement("ENG-001", reason="Engagement completed and closed")
    assert success is True

    # Engagement should now be hidden from standard lookups
    assert repo.get_engagement("ENG-001") is None
    assert len(repo.list_engagements()) == 0

    # Child assessments and scope items should also be cascade soft-deleted
    assert repo.get_assessment("ASM-001") is None
    assert len(repo.list_assessments("ENG-001")) == 0
    assert repo.get_scope_item("SCP-001") is None
    assert len(repo.list_scope_items("ENG-001")) == 0


# ============================================================================
# 7. SqliteFindingsRepository CRUD & Soft Deletion
# ============================================================================

def test_findings_repository_crud(tmp_path: Path):
    db_file = tmp_path / "test.db"
    initialize_database(db_path=db_file)
    seed_laboratory_fixtures(db_file)

    findings_repo = SqliteFindingsRepository(db_path=db_file)

    finding = findings_repo.create_finding(
        FindingCreate(
            assessmentId="ASM-001",
            assetId="AST-001",
            ruleId="SEC-WEB-001",
            title="Missing HSTS Header",
            description="Strict-Transport-Security header was not detected.",
            status=FindingStatus.CONFIRMED,
            severity="high",
            confidence="high",
            cwe="CWE-319",
            impact="Data in transit may be intercepted.",
            recommendation="Enable Strict-Transport-Security with max-age=31536000.",
        )
    )

    assert finding.id.startswith("FND-")
    assert finding.title == "Missing HSTS Header"

    retrieved = findings_repo.get_finding(finding.id)
    assert retrieved is not None
    assert retrieved.severity == "high"

    # Filtered list
    asm_findings = findings_repo.list_findings(assessment_id="ASM-001", severity="high")
    assert len(asm_findings) == 1

    # Soft delete
    deleted = findings_repo.soft_delete_finding(finding.id)
    assert deleted is True
    assert findings_repo.get_finding(finding.id) is None
    assert len(findings_repo.list_findings(assessment_id="ASM-001")) == 0


# ============================================================================
# 8. SqliteExecutionRepository Telemetry
# ============================================================================

def test_execution_repository_record_and_query(tmp_path: Path):
    db_file = tmp_path / "test.db"
    initialize_database(db_path=db_file)
    seed_laboratory_fixtures(db_file)

    exec_repo = SqliteExecutionRepository(db_path=db_file)

    record = CheckExecution(
        id="CHK-test001",
        assessmentId="ASM-001",
        ruleId="SEC-TLS-001",
        target="app.lab.local",
        scopeDecision=ScopeDecision.ALLOW,
        status=ExecutionStatus.PASS,
        ruleVersion="1.0.0",
        durationMs=120,
    )

    saved = exec_repo.record_execution(record)
    assert saved.id == "CHK-test001"
    assert saved.durationMs == 120

    retrieved = exec_repo.get_execution("CHK-test001")
    assert retrieved is not None
    assert retrieved.target == "app.lab.local"
    assert retrieved.status == ExecutionStatus.PASS

    execs = exec_repo.list_executions(assessment_id="ASM-001")
    assert len(execs) == 1


# ============================================================================
# 9. SqliteAuditRepository Operations (Structured Operational Audit Logs)
# ============================================================================

def test_audit_repository_logging(tmp_path: Path):
    db_file = tmp_path / "test.db"
    initialize_database(db_path=db_file)

    audit_repo = SqliteAuditRepository(db_path=db_file)

    log_entry = audit_repo.record_audit_log(
        AuditLogCreate(
            actorId="operator-1",
            action="SCOPE_ITEM_CREATED",
            objectType="ScopeItem",
            objectId="SCP-999",
            before=None,
            after={"target": "api.lab.local", "inScope": True},
        )
    )

    assert log_entry.id.startswith("AUD-")
    assert log_entry.action == "SCOPE_ITEM_CREATED"

    logs = audit_repo.list_audit_logs(limit=10)
    assert len(logs) == 1
    assert logs[0].actorId == "operator-1"
    assert logs[0].after["target"] == "api.lab.local"
