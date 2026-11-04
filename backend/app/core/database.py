import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Generator, Optional, Union

from app.core.storage_paths import get_storage_paths


def get_default_db_path() -> Path:
    """Return the default database path according to storage configuration."""
    return get_storage_paths().database_file


def create_connection(db_path: Optional[Union[str, Path]] = None) -> sqlite3.Connection:
    """
    Create a new configured SQLite connection.
    Enforces foreign keys, busy timeout, and WAL mode (for file-based databases).
    """
    resolved_path = str(db_path) if db_path is not None else str(get_default_db_path())
    is_memory = resolved_path == ":memory:" or ":memory:" in resolved_path

    # Ensure parent directory exists for file-based databases
    if not is_memory:
        Path(resolved_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(
        resolved_path,
        timeout=5.0,
        check_same_thread=False,
        isolation_level=None,  # Autocommit mode by default; manual transactions with BEGIN
    )
    conn.row_factory = sqlite3.Row

    # Mandatory security and integrity pragmas
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA busy_timeout = 5000;")

    if not is_memory:
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA temp_store = MEMORY;")
            conn.execute("PRAGMA cache_size = -32000;")
        except sqlite3.OperationalError:
            pass  # In certain test harnesses or read-only filesystems, proceed gracefully

    return conn


@contextmanager
def get_db_connection(db_path: Optional[Union[str, Path]] = None) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for acquiring and releasing a SQLite connection."""
    conn = create_connection(db_path)
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def transaction(db_path: Optional[Union[str, Path]] = None) -> Generator[sqlite3.Connection, None, None]:
    """
    Atomic transaction context manager.
    Executes BEGIN IMMEDIATE to acquire write lock upfront.
    Commits on successful block completion; rolls back on exception.
    """
    conn = create_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE;")
        yield conn
        if conn.in_transaction:
            conn.execute("COMMIT;")
    except Exception:
        try:
            if conn.in_transaction:
                conn.execute("ROLLBACK;")
        except Exception:
            pass
        raise
    finally:
        conn.close()


def check_database_health(db_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """
    Perform runtime health check on the SQLite database.
    Verifies connectivity, foreign key status, quick_check integrity, and schema version.
    """
    with get_db_connection(db_path) as conn:
        # Check foreign keys
        fk_status = conn.execute("PRAGMA foreign_keys;").fetchone()[0] == 1

        # Check quick integrity
        quick_check_res = conn.execute("PRAGMA quick_check;").fetchone()[0]

        # Check schema version
        try:
            version_row = conn.execute("SELECT MAX(version) FROM schema_version;").fetchone()
            schema_version = version_row[0] if version_row and version_row[0] is not None else 0
        except sqlite3.OperationalError:
            schema_version = 0

        # Check write capability
        write_ok = False
        try:
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute("ROLLBACK;")
            write_ok = True
        except Exception:
            write_ok = False

    is_healthy = fk_status and quick_check_res == "ok" and write_ok

    return {
        "status": "healthy" if is_healthy else "unhealthy",
        "healthy": is_healthy,
        "foreignKeys": fk_status,
        "integrityCheck": quick_check_res,
        "schemaVersion": schema_version,
        "writeCapability": write_ok,
    }
