import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple, Union

from app.core.database import create_connection


class MigrationError(Exception):
    """Raised when database schema migration execution fails."""
    pass


def split_sql_statements(sql: str) -> List[str]:
    """
    Split a SQL script into individual executable statements using sqlite3.complete_statement.
    Preserves semicolons inside string literals and properly ignores comments.
    """
    statements: List[str] = []
    buffer = ""

    for line in sql.splitlines():
        stripped = line.strip()
        # Skip comment lines when buffer is empty
        if not buffer and (stripped.startswith("--") or not stripped):
            continue
        buffer += line + "\n"
        if sqlite3.complete_statement(buffer):
            stmt = buffer.strip()
            if stmt.endswith(";"):
                stmt = stmt[:-1].strip()
            if stmt:
                statements.append(stmt)
            buffer = ""

    if buffer.strip():
        stmt = buffer.strip()
        if stmt.endswith(";"):
            stmt = stmt[:-1].strip()
        if stmt:
            statements.append(stmt)

    return statements


class MigrationRunner:
    """
    Lightweight, zero-dependency schema migration engine for SQLite.
    Discovers SQL migration files, tracks applied versions in `schema_version`,
    and executes pending migrations sequentially inside strict atomic transactions.
    """

    def __init__(
        self,
        db_path: Optional[Union[str, Path]] = None,
        migrations_dir: Optional[Path] = None,
    ) -> None:
        self.db_path = db_path
        if migrations_dir is not None:
            self.migrations_dir = migrations_dir
        else:
            self.migrations_dir = Path(__file__).parent.parent / "migrations"

    def _ensure_version_table(self, conn: sqlite3.Connection) -> None:
        """Create schema_version table if it does not already exist."""
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL,
                description TEXT NOT NULL
            );
            """
        )

    def get_current_version(self) -> int:
        """Retrieve the currently applied schema version from the database."""
        conn = create_connection(self.db_path)
        try:
            self._ensure_version_table(conn)
            row = conn.execute("SELECT MAX(version) FROM schema_version;").fetchone()
            if row and row[0] is not None:
                return int(row[0])
            return 0
        finally:
            conn.close()

    def discover_migrations(self) -> List[Tuple[int, str, Path]]:
        """
        Scan the migrations directory for files matching <version>_<description>.sql.
        Returns a sorted list of (version_int, description, file_path).
        """
        if not self.migrations_dir.exists():
            return []

        pattern = re.compile(r"^(\d+)_(.+)\.sql$")
        migrations = []

        for p in self.migrations_dir.glob("*.sql"):
            if p.is_file():
                match = pattern.match(p.name)
                if match:
                    version = int(match.group(1))
                    description = match.group(2).replace("_", " ").title()
                    migrations.append((version, description, p))

        migrations.sort(key=lambda m: m[0])
        return migrations

    def apply_pending_migrations(self) -> int:
        """
        Apply all unapplied migrations in ascending numerical order.
        Each migration executes within a dedicated atomic transaction.
        If any statement fails, all statements from that migration are rolled back,
        preventing partially created tables or inconsistent schema versions.
        """
        current_version = self.get_current_version()
        available = self.discover_migrations()

        pending = [m for m in available if m[0] > current_version]
        if not pending:
            return current_version

        for version, desc, path in pending:
            sql = path.read_text(encoding="utf-8")
            statements = split_sql_statements(sql)
            now_iso = datetime.now(timezone.utc).isoformat()

            conn = create_connection(self.db_path)
            try:
                self._ensure_version_table(conn)

                # Begin atomic transaction for this migration
                conn.execute("BEGIN IMMEDIATE;")

                for stmt in statements:
                    # Strip any independent BEGIN/COMMIT in script that could interfere with boundary
                    clean_stmt = stmt.strip()
                    upper_stmt = clean_stmt.upper()
                    if upper_stmt in ("BEGIN", "BEGIN TRANSACTION", "BEGIN IMMEDIATE", "COMMIT", "ROLLBACK"):
                        continue
                    conn.execute(clean_stmt)

                # Record version in the exact same transaction
                conn.execute(
                    """
                    INSERT INTO schema_version (version, applied_at, description)
                    VALUES (?, ?, ?);
                    """,
                    (version, now_iso, desc),
                )

                # Commit transaction
                if conn.in_transaction:
                    conn.execute("COMMIT;")

            except Exception as e:
                try:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK;")
                except Exception:
                    pass
                raise MigrationError(
                    f"Failed applying migration {version} ({desc}) from '{path}': {str(e)}"
                ) from e
            finally:
                conn.close()

            current_version = version

        return current_version
