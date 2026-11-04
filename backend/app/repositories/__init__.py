from app.repositories.findings_repository import (
    InMemoryFindingsRepository,
    findings_repository,
)
from app.repositories.interfaces import (
    IAuditRepository,
    IBackupRepository,
    IEvidenceRepository,
    IExecutionRepository,
    IFindingsRepository,
    IQuarantineRepository,
    IScopeRepository,
)
from app.repositories.scope_repository import (
    InMemoryScopeRepository,
    scope_repository,
)
from app.repositories.sqlite_audit_repository import SqliteAuditRepository
from app.repositories.sqlite_backup_repository import SqliteBackupRepository
from app.repositories.sqlite_evidence_repository import SqliteEvidenceRepository
from app.repositories.sqlite_execution_repository import SqliteExecutionRepository
from app.repositories.sqlite_findings_repository import SqliteFindingsRepository
from app.repositories.sqlite_quarantine_repository import SqliteQuarantineRepository
from app.repositories.sqlite_scope_repository import SqliteScopeRepository

__all__ = [
    "IScopeRepository",
    "IFindingsRepository",
    "IExecutionRepository",
    "IAuditRepository",
    "IEvidenceRepository",
    "IQuarantineRepository",
    "IBackupRepository",
    "InMemoryScopeRepository",
    "scope_repository",
    "InMemoryFindingsRepository",
    "findings_repository",
    "SqliteScopeRepository",
    "SqliteFindingsRepository",
    "SqliteExecutionRepository",
    "SqliteAuditRepository",
    "SqliteEvidenceRepository",
    "SqliteQuarantineRepository",
    "SqliteBackupRepository",
]
