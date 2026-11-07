from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
import uuid

from app.core.database import get_db_connection
from app.repositories.interfaces import IFindingsRepository
from app.schemas.common import FindingStatus
from app.schemas.finding import Finding, FindingCreate


class InMemoryFindingsRepository(IFindingsRepository):
    def __init__(self) -> None:
        self._findings: Dict[str, Finding] = {}
        self._deleted_ids: Set[str] = set()

    def create_finding(self, data: FindingCreate) -> Finding:
        finding_id = data.id or f"FND-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc)
        finding = Finding(
            id=finding_id,
            assessmentId=data.assessmentId,
            assetId=data.assetId,
            ruleId=data.ruleId,
            title=data.title,
            description=data.description,
            status=data.status,
            severity=data.severity,
            confidence=data.confidence,
            cwe=data.cwe,
            cve=data.cve,
            cvss=data.cvss,
            impact=data.impact,
            recommendation=data.recommendation,
            createdAt=data.createdAt or now,
            updatedAt=data.updatedAt or now,
        )
        self._findings[finding_id] = finding
        self._deleted_ids.discard(finding_id)
        return finding

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        if finding_id in self._deleted_ids:
            return None
        return self._findings.get(finding_id)

    def list_findings(
        self,
        assessment_id: Optional[str] = None,
        severity: Optional[str] = None,
        confidence: Optional[str] = None,
    ) -> List[Finding]:
        results = [
            f for fid, f in self._findings.items()
            if fid not in self._deleted_ids
        ]
        if assessment_id:
            results = [f for f in results if f.assessmentId == assessment_id]
        if severity:
            sev_lower = severity.lower()
            results = [
                f for f in results
                if (f.severity.value.lower() if hasattr(f.severity, "value") else str(f.severity).lower()) == sev_lower
            ]
        if confidence:
            conf_lower = confidence.lower()
            results = [
                f for f in results
                if (f.confidence.value.lower() if hasattr(f.confidence, "value") else str(f.confidence).lower()) == conf_lower
            ]
        # Deterministic sorting matching SQLite: newest first
        results.sort(
            key=lambda f: f.createdAt.isoformat() if f.createdAt else "",
            reverse=True,
        )
        return results

    def update_finding_status(
        self, finding_id: str, new_status: FindingStatus
    ) -> Finding:
        if finding_id in self._deleted_ids or finding_id not in self._findings:
            raise ValueError(f"Finding '{finding_id}' not found or is deleted.")
        f = self._findings[finding_id]
        updated = Finding(
            id=f.id,
            assessmentId=f.assessmentId,
            assetId=f.assetId,
            ruleId=f.ruleId,
            title=f.title,
            description=f.description,
            status=new_status,
            severity=f.severity,
            confidence=f.confidence,
            cwe=f.cwe,
            cve=f.cve,
            cvss=f.cvss,
            impact=f.impact,
            recommendation=f.recommendation,
            createdAt=f.createdAt,
            updatedAt=datetime.now(timezone.utc),
        )
        self._findings[finding_id] = updated
        return updated

    def soft_delete_finding(self, finding_id: str) -> bool:
        if finding_id in self._findings and finding_id not in self._deleted_ids:
            self._deleted_ids.add(finding_id)
            return True
        return False


class FindingsRepositoryProxy(IFindingsRepository):
    """
    Transparent proxy to active findings repository.
    Delegates to SQLite-backed repository in production while preserving
    backwards compatibility for callers importing `findings_repository`.
    """

    @property
    def _active_repo(self) -> IFindingsRepository:
        from app.dependencies import get_db_path, get_findings_repository
        return get_findings_repository(get_db_path())

    def create_finding(self, data: FindingCreate) -> Finding:
        return self._active_repo.create_finding(data)

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        return self._active_repo.get_finding(finding_id)

    def list_findings(
        self,
        assessment_id: Optional[str] = None,
        severity: Optional[str] = None,
        confidence: Optional[str] = None,
    ) -> List[Finding]:
        return self._active_repo.list_findings(
            assessment_id=assessment_id, severity=severity, confidence=confidence
        )

    def update_finding_status(
        self, finding_id: str, new_status: FindingStatus
    ) -> Finding:
        return self._active_repo.update_finding_status(finding_id, new_status)

    def soft_delete_finding(self, finding_id: str) -> bool:
        return self._active_repo.soft_delete_finding(finding_id)


findings_repository: IFindingsRepository = FindingsRepositoryProxy()
