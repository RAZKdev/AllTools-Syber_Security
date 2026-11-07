import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from app.core.database import check_database_health, transaction
from app.core.migration_runner import MigrationRunner
from app.core.storage_paths import ensure_storage_directories, get_storage_paths

logger = logging.getLogger(__name__)


def initialize_database(
    db_path: Optional[Union[str, Path]] = None,
) -> int:
    """
    Initialize production SQLite database:
    1. Ensure storage directory structure exists with appropriate access permissions.
    2. Apply all pending schema migrations.
    3. Run post-migration database health verification.

    Production Invariant (P0):
    A fresh production database contains ZERO automatically authorized scope rules.
    No live engagements, assessments, or scope items are seeded automatically.
    The system strictly enforces fail-closed default-deny immediately after first installation.
    """
    if db_path is None:
        paths = get_storage_paths()
        ensure_storage_directories(paths)
        target_path = paths.database_file
    else:
        target_path = Path(db_path) if str(db_path) != ":memory:" else db_path

    # Apply schema migrations
    runner = MigrationRunner(db_path=target_path)
    version = runner.apply_pending_migrations()

    # Health check verification
    health = check_database_health(db_path=target_path)
    if health["status"] != "healthy":
        raise RuntimeError(
            f"Database initialized but failed post-init health check: {health}"
        )

    logger.info(f"Production database initialized at schema version {version} with strict default-deny.")
    return version


def seed_laboratory_fixtures(db_path: Optional[Union[str, Path]] = None) -> None:
    """
    Explicitly seed laboratory test fixtures (ENG-001, ASM-001, SCP-001..003).

    Safety Invariant:
    This function is strictly for isolated automated test databases and explicit
    developer testing. It is NEVER called automatically during production application startup.
    """
    now = datetime.now(timezone.utc).isoformat()

    with transaction(db_path) as conn:
        # Check if ENG-001 already exists to prevent duplicate key errors
        existing = conn.execute("SELECT id FROM engagements WHERE id = 'ENG-001';").fetchone()
        if existing:
            return

        # Seed canonical ENG-001
        conn.execute(
            """
            INSERT INTO engagements (
                id, workspace_id, name, description, assessor, status,
                rules_of_engagement, is_deleted, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?);
            """,
            (
                "ENG-001",
                "WKS-001",
                "Laboratory Defensive Security Assessment",
                "Authorized laboratory engagement for isolated evaluation and compliance checks.",
                "Lead Security Assessor",
                "active",
                "Defensive evaluation only. Strict adherence to Scope Guard boundary.",
                now,
                now,
            ),
        )

        # Seed canonical ASM-001
        conn.execute(
            """
            INSERT INTO assessments (
                id, engagement_id, name, type, status, started_at, is_deleted, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?);
            """,
            (
                "ASM-001",
                "ENG-001",
                "Comprehensive Laboratory Assessment",
                "general",
                "running",
                now,
                now,
                now,
            ),
        )

        # Seed canonical Scope Items
        conn.execute(
            """
            INSERT INTO scope_items (
                id, engagement_id, type, value, environment, in_scope, notes, is_deleted, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?);
            """,
            (
                "SCP-001",
                "ENG-001",
                "domain",
                "lab.local",
                "lab",
                1,
                "Authorized lab domain and subdomains (*.lab.local)",
                now,
                now,
            ),
        )

        conn.execute(
            """
            INSERT INTO scope_items (
                id, engagement_id, type, value, environment, in_scope, notes, is_deleted, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?);
            """,
            (
                "SCP-002",
                "ENG-001",
                "cidr",
                "192.168.1.0/24",
                "lab",
                1,
                "Internal laboratory test subnet",
                now,
                now,
            ),
        )

        conn.execute(
            """
            INSERT INTO scope_items (
                id, engagement_id, type, value, environment, in_scope, notes, is_deleted, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?);
            """,
            (
                "SCP-003",
                "ENG-001",
                "domain",
                "critical.lab.local",
                "production",
                0,
                "Explicitly excluded management host (default-deny exclusion test)",
                now,
                now,
            ),
        )
