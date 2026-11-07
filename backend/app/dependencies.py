import os
from pathlib import Path
from typing import Optional, Set
from fastapi import Depends

from app.core.storage_paths import get_storage_paths
from app.core.database_init import initialize_database
from app.repositories.interfaces import (
    IAuditRepository,
    IBackupRepository,
    IEvidenceRepository,
    IExecutionRepository,
    IFindingsRepository,
    IQuarantineRepository,
    IScopeRepository,
)
from app.repositories.sqlite_audit_repository import SqliteAuditRepository
from app.repositories.sqlite_backup_repository import SqliteBackupRepository
from app.repositories.sqlite_evidence_repository import SqliteEvidenceRepository
from app.repositories.sqlite_execution_repository import SqliteExecutionRepository
from app.repositories.sqlite_findings_repository import SqliteFindingsRepository
from app.repositories.sqlite_quarantine_repository import SqliteQuarantineRepository
from app.repositories.sqlite_scope_repository import SqliteScopeRepository

_db_path: Optional[Path] = None
_initialized_dbs: Set[str] = set()


def get_db_path() -> Path:
    """
    Retrieve the configured SQLite database file path.
    If an explicit override is set (e.g. during testing), it is returned.
    Otherwise, resolves deterministically from StoragePaths.
    """
    global _db_path
    if _db_path is not None:
        return _db_path
    paths = get_storage_paths()
    return paths.database_file


def set_db_path(path: Optional[Path]) -> None:
    """Explicitly override database path (used by testing harnesses)."""
    global _db_path
    _db_path = path


def ensure_database_initialized(db_path: Path) -> None:
    """
    Ensure the target database has all schema migrations applied.
    Caches successful initialization per path to avoid redundant checks.
    Fails closed on error.
    """
    path_key = str(db_path.resolve())
    if path_key not in _initialized_dbs:
        initialize_database(db_path=db_path)
        _initialized_dbs.add(path_key)


def get_scope_repository(db_path: Path = Depends(get_db_path)) -> IScopeRepository:
    """
    Deterministic dependency provider for Scope Repository (Engagements, Assessments, Scope).
    Production default is SqliteScopeRepository backed by the configured database.
    """
    ensure_database_initialized(db_path)
    return SqliteScopeRepository(db_path=db_path)


def get_findings_repository(db_path: Path = Depends(get_db_path)) -> IFindingsRepository:
    """Deterministic dependency provider for Findings Repository."""
    ensure_database_initialized(db_path)
    return SqliteFindingsRepository(db_path=db_path)


def get_execution_repository(db_path: Path = Depends(get_db_path)) -> IExecutionRepository:
    """Deterministic dependency provider for Check Execution Repository."""
    ensure_database_initialized(db_path)
    return SqliteExecutionRepository(db_path=db_path)


def get_audit_repository(db_path: Path = Depends(get_db_path)) -> IAuditRepository:
    """Deterministic dependency provider for Structured Operational Audit Log Repository."""
    ensure_database_initialized(db_path)
    return SqliteAuditRepository(db_path=db_path)


def get_evidence_repository(db_path: Path = Depends(get_db_path)) -> IEvidenceRepository:
    """Deterministic dependency provider for Evidence Repository."""
    ensure_database_initialized(db_path)
    return SqliteEvidenceRepository(db_path=db_path)


def get_quarantine_repository(db_path: Path = Depends(get_db_path)) -> IQuarantineRepository:
    """Deterministic dependency provider for Quarantine Ledger Repository."""
    ensure_database_initialized(db_path)
    return SqliteQuarantineRepository(db_path=db_path)


def get_backup_repository(db_path: Path = Depends(get_db_path)) -> IBackupRepository:
    """Deterministic dependency provider for Hot Backup Repository."""
    ensure_database_initialized(db_path)
    return SqliteBackupRepository(db_path=db_path)
