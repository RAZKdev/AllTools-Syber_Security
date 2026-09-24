from datetime import datetime, timezone
import pytest

from app.schemas.assessment import Assessment, AssessmentStatus
from app.schemas.engagement import Engagement, EngagementStatus
from app.schemas.evidence import Evidence, EvidenceType
from app.schemas.finding import Finding
from app.schemas.scope import ScopeItem, ScopeType
from reports.generator import SecurityReportGenerator


@pytest.fixture
def sample_data():
    now = datetime.now(timezone.utc)
    engagement = Engagement(
        id="ENG-TEST",
        workspaceId="WKS-01",
        name="Quarterly Defensive Lab Audit",
        status=EngagementStatus.ACTIVE,
        assessor="Security Team",
        createdAt=now,
    )
    assessment = Assessment(
        id="ASM-TEST",
        engagementId="ENG-TEST",
        name="Infrastructure & Web Assessment",
        status=AssessmentStatus.COMPLETED,
        createdAt=now,
    )
    scope_items = [
        ScopeItem(
            id="SCP-01",
            engagementId="ENG-TEST",
            type=ScopeType.DOMAIN,
            value="lab.local",
            inScope=True,
        ),
        ScopeItem(
            id="SCP-02",
            engagementId="ENG-TEST",
            type=ScopeType.DOMAIN,
            value="critical.lab.local",
            inScope=False,
            notes="Excluded",
        ),
    ]
    findings = [
        Finding(
            id="FND-01",
            assessmentId="ASM-TEST",
            assetId="AST-01",
            title="Missing HTTP Security Headers",
            description="Target web service does not include CSP or HSTS.",
            severity="medium",
            cwe="CWE-693",
            recommendation="Configure reverse proxy headers.",
            createdAt=now,
        )
    ]
    evidence_list = [
        Evidence(
            id="EVD-01",
            assessmentId="ASM-TEST",
            findingId="FND-01",
            type=EvidenceType.JSON_RESULT,
            source="https://app.lab.local",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            capturedAt=now,
        )
    ]
    return engagement, assessment, scope_items, findings, evidence_list


def test_generate_markdown_report(sample_data):
    engagement, assessment, scope_items, findings, evidence_list = sample_data
    md = SecurityReportGenerator.generate_markdown(
        engagement, assessment, scope_items, findings, evidence_list
    )
    assert f"# Defensive Security Assessment Report — {engagement.name}" in md
    assert "## 1. Metadata" in md
    assert "## 3. Authorized Scope Boundary" in md
    assert "## 5. Summary of Findings" in md
    assert "## 7. Cryptographic Evidence Log" in md
    assert "FND-01" in md
    assert "EVD-01" in md
    assert "e3b0c44298fc1c14..." in md


def test_generate_html_report(sample_data):
    engagement, assessment, scope_items, findings, evidence_list = sample_data
    html = SecurityReportGenerator.generate_html(
        engagement, assessment, scope_items, findings, evidence_list
    )
    assert "<!DOCTYPE html>" in html
    assert f"<title>Security Assessment Report — {engagement.name}</title>" in html
    assert "FND-01" in html
