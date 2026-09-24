from typing import Dict, List, Optional
import uuid
from app.schemas.finding import Finding, FindingCreate


class InMemoryFindingsRepository:
    def __init__(self) -> None:
        self._findings: Dict[str, Finding] = {}

    def create_finding(self, data: FindingCreate) -> Finding:
        finding_id = data.id or f"FND-{uuid.uuid4().hex[:8]}"
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
            createdAt=data.createdAt,
            updatedAt=data.updatedAt,
        )
        self._findings[finding_id] = finding
        return finding

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        return self._findings.get(finding_id)

    def list_findings(self, assessment_id: Optional[str] = None) -> List[Finding]:
        if assessment_id:
            return [f for f in self._findings.values() if f.assessmentId == assessment_id]
        return list(self._findings.values())


findings_repository = InMemoryFindingsRepository()
