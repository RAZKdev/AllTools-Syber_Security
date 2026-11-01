import pytest
from datetime import datetime, timezone
from app.schemas.assessment import Assessment, AssessmentStatus, AssessmentType
from app.schemas.engagement import Engagement, EngagementStatus
from app.schemas.finding import Finding
from app.schemas.scope import ScopeItem, ScopeType
from reports.generator import SecurityReportGenerator


def test_html_report_escapes_xss_payloads():
    """Verify that user-controlled HTML tags in engagement, scope, and findings are safely escaped."""
    now = datetime.now(timezone.utc)
    eng = Engagement(
        id="ENG-XSS",
        workspaceId="WKS-1",
        name="Audit <script>alert('XSS-Name')</script>",
        status=EngagementStatus.ACTIVE,
        createdAt=now,
    )
    asm = Assessment(
        id="ASM-XSS",
        engagementId="ENG-XSS",
        name="Assessment <img src=x onerror=alert(1)>",
        type=AssessmentType.GENERAL,
        status=AssessmentStatus.RUNNING,
        createdAt=now,
    )
    scope = [
        ScopeItem(
            id="SCP-X",
            engagementId="ENG-XSS",
            type=ScopeType.DOMAIN,
            value="lab.local</pre><script>alert('XSS-Scope')</script>",
            inScope=True,
        )
    ]
    findings = [
        Finding(
            id="FND-X",
            assessmentId="ASM-XSS",
            assetId="AST-1",
            title="Finding <script>alert('XSS-Finding')</script>",
            description="Exploit description <iframe src='evil.com'></iframe>",
            status="NEEDS_REVIEW",
            severity="high",
            confidence="high",
            createdAt=now,
        )
    ]

    html_output = SecurityReportGenerator.generate_html(eng, asm, scope, findings, [])

    # Assert raw dangerous tags are NOT present
    assert "<script>" not in html_output
    assert "</script>" not in html_output
    assert "<img src=x" not in html_output
    assert "<iframe" not in html_output

    # Assert escaped entities ARE present
    assert "&lt;script&gt;alert(&#x27;XSS-Name&#x27;)&lt;/script&gt;" in html_output
    assert "&lt;script&gt;alert(&#x27;XSS-Scope&#x27;)&lt;/script&gt;" in html_output
    assert "&lt;script&gt;alert(&#x27;XSS-Finding&#x27;)&lt;/script&gt;" in html_output
    assert "&lt;iframe src=&#x27;evil.com&#x27;&gt;&lt;/iframe&gt;" in html_output

    # Assert CSP meta tag is in document head
    assert "Content-Security-Policy" in html_output
    assert "default-src 'none'" in html_output
