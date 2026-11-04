from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional

from app.schemas.assessment import Assessment, AssessmentCreate, AssessmentStatus
from app.schemas.audit_log import AuditLog, AuditLogCreate
from app.schemas.backup import BackupSnapshot, BackupStatus
from app.schemas.check_execution import CheckExecution
from app.schemas.engagement import Engagement, EngagementCreate, EngagementStatus
from app.schemas.evidence import Evidence, EvidenceCreate
from app.schemas.finding import Finding, FindingCreate
from app.schemas.quarantine import QuarantineItem
from app.schemas.scope import ScopeItem, ScopeItemCreate


class IScopeRepository(ABC):
    """Abstract interface for Engagements, Assessments, and Scope Items persistence."""

    # Engagement operations
    @abstractmethod
    def create_engagement(self, data: EngagementCreate) -> Engagement: ...

    @abstractmethod
    def get_engagement(self, engagement_id: str) -> Optional[Engagement]: ...

    @abstractmethod
    def list_engagements(self) -> List[Engagement]: ...

    @abstractmethod
    def update_engagement_status(
        self, engagement_id: str, new_status: EngagementStatus
    ) -> Engagement: ...

    @abstractmethod
    def soft_delete_engagement(
        self, engagement_id: str, reason: Optional[str] = None
    ) -> bool: ...

    # Assessment operations
    @abstractmethod
    def create_assessment(self, data: AssessmentCreate) -> Assessment: ...

    @abstractmethod
    def get_assessment(self, assessment_id: str) -> Optional[Assessment]: ...

    @abstractmethod
    def list_assessments(self, engagement_id: Optional[str] = None) -> List[Assessment]: ...

    @abstractmethod
    def update_assessment_status(
        self,
        assessment_id: str,
        new_status: AssessmentStatus,
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
    ) -> Assessment: ...

    @abstractmethod
    def soft_delete_assessment(self, assessment_id: str) -> bool: ...

    # Scope Item operations
    @abstractmethod
    def create_scope_item(self, data: ScopeItemCreate) -> ScopeItem: ...

    @abstractmethod
    def get_scope_item(self, item_id: str) -> Optional[ScopeItem]: ...

    @abstractmethod
    def list_scope_items(self, engagement_id: Optional[str] = None) -> List[ScopeItem]: ...

    @abstractmethod
    def get_scope_for_assessment(self, assessment_id: str) -> List[ScopeItem]: ...

    @abstractmethod
    def soft_delete_scope_item(self, item_id: str) -> bool: ...


class IFindingsRepository(ABC):
    """Abstract interface for Security Findings persistence."""

    @abstractmethod
    def create_finding(self, data: FindingCreate) -> Finding: ...

    @abstractmethod
    def get_finding(self, finding_id: str) -> Optional[Finding]: ...

    @abstractmethod
    def list_findings(
        self,
        assessment_id: Optional[str] = None,
        severity: Optional[str] = None,
        confidence: Optional[str] = None,
    ) -> List[Finding]: ...

    @abstractmethod
    def update_finding_status(
        self, finding_id: str, new_status: FindingStatus
    ) -> Finding: ...

    @abstractmethod
    def soft_delete_finding(self, finding_id: str) -> bool: ...


class IExecutionRepository(ABC):
    """Abstract interface for Check Execution records persistence."""

    @abstractmethod
    def reserve_execution(self, data: CheckExecution) -> Tuple[CheckExecution, bool]: ...

    @abstractmethod
    def record_execution(self, data: CheckExecution) -> CheckExecution: ...

    @abstractmethod
    def get_execution(self, execution_id: str) -> Optional[CheckExecution]: ...

    @abstractmethod
    def list_executions(self, assessment_id: Optional[str] = None) -> List[CheckExecution]: ...

    @abstractmethod
    def reconcile_stale_executions(self) -> int: ...


class IAuditRepository(ABC):
    """Abstract interface for Audit Log persistence."""

    @abstractmethod
    def record_audit_log(self, data: AuditLogCreate) -> AuditLog: ...

    @abstractmethod
    def list_audit_logs(self, limit: int = 100, offset: int = 0) -> List[AuditLog]: ...


class IEvidenceRepository(ABC):
    """Abstract interface for Evidence metadata persistence and artifact verification."""

    @abstractmethod
    def create_evidence(
        self, data: EvidenceCreate, sync_status: str = "COMMITTED"
    ) -> Evidence: ...

    @abstractmethod
    def get_evidence(self, evidence_id: str) -> Optional[Evidence]: ...

    @abstractmethod
    def list_evidence(
        self,
        assessment_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        include_deleted: bool = False,
    ) -> List[Evidence]: ...

    @abstractmethod
    def get_by_sha256(self, sha256_digest: str) -> Optional[Evidence]: ...

    @abstractmethod
    def get_by_artifact_path(self, artifact_path: str) -> Optional[Evidence]: ...

    @abstractmethod
    def update_sync_status(self, evidence_id: str, new_status: str) -> bool: ...

    @abstractmethod
    def update_finding_id(self, evidence_id: str, finding_id: Optional[str]) -> bool: ...

    @abstractmethod
    def soft_delete_evidence(self, evidence_id: str) -> bool: ...

    @abstractmethod
    def set_legal_hold(self, evidence_id: str, hold: bool) -> bool: ...

    @abstractmethod
    def hard_delete_evidence(self, evidence_id: str) -> bool: ...


class IQuarantineRepository(ABC):
    """Abstract interface for Quarantine ledger and cryptographic integrity chain."""

    @abstractmethod
    def record_quarantine_item(
        self,
        event_id: str,
        quarantine_id: str,
        original_path: str,
        quarantine_path: str,
        sha256: str,
        byte_size: int,
        reason: str,
        details: Optional[str] = None,
    ) -> QuarantineItem: ...

    @abstractmethod
    def get_quarantine_item(self, quarantine_id: str) -> Optional[QuarantineItem]: ...

    @abstractmethod
    def list_quarantine_items(self) -> List[QuarantineItem]: ...

    @abstractmethod
    def get_last_quarantine_entry(self) -> Optional[QuarantineItem]: ...

    @abstractmethod
    def mark_recovered(self, quarantine_id: str, target_id: str) -> bool: ...


class IBackupRepository(ABC):
    """Abstract interface for Hot Backup Engine metadata tracking (ADR-06)."""

    @abstractmethod
    def record_backup_started(
        self, generation_id: str, sqlite_data_version: int
    ) -> BackupSnapshot: ...

    @abstractmethod
    def record_backup_completed(
        self,
        generation_id: str,
        manifest_sha256: str,
        byte_size: int,
        evidence_count: int,
        quarantine_count: int,
    ) -> BackupSnapshot: ...

    @abstractmethod
    def record_backup_failed(self, generation_id: str) -> bool: ...

    @abstractmethod
    def get_backup(self, generation_id: str) -> Optional[BackupSnapshot]: ...

    @abstractmethod
    def list_backups(
        self, status: Optional[BackupStatus] = None
    ) -> List[BackupSnapshot]: ...

    @abstractmethod
    def get_last_known_good_backup(self) -> Optional[BackupSnapshot]: ...

    @abstractmethod
    def delete_backup_record(self, generation_id: str) -> bool: ...
