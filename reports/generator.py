from datetime import datetime, timezone
from typing import List, Optional
from app.schemas.assessment import Assessment
from app.schemas.engagement import Engagement
from app.schemas.evidence import Evidence
from app.schemas.finding import Finding
from app.schemas.scope import ScopeItem


class SecurityReportGenerator:
    """
    Security Report Generator compliant with DESIGN.md Section 19 and SKILL.md Section 14.
    Produces printable, audit-grade Markdown and standalone HTML reports.
    """

    @classmethod
    def generate_markdown(
        cls,
        engagement: Engagement,
        assessment: Assessment,
        scope_items: List[ScopeItem],
        findings: List[Finding],
        evidence_list: List[Evidence],
    ) -> str:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        critical_count = sum(1 for f in findings if f.severity == "critical")
        high_count = sum(1 for f in findings if f.severity == "high")
        medium_count = sum(1 for f in findings if f.severity == "medium")
        low_count = sum(1 for f in findings if f.severity == "low")
        info_count = sum(1 for f in findings if f.severity == "informational")

        md = []
        md.append(f"# Defensive Security Assessment Report — {engagement.name}")
        md.append("")
        md.append("## 1. Metadata")
        md.append(f"- **Engagement ID:** `{engagement.id}`")
        md.append(f"- **Assessment ID:** `{assessment.id}`")
        md.append(f"- **Assessment Name:** {assessment.name}")
        md.append(f"- **Assessor:** {engagement.assessor or 'Authorized Operator'}")
        md.append(f"- **Report Date:** {now_str}")
        md.append(f"- **Status:** {assessment.status.upper()}")
        md.append("")

        md.append("## 2. Executive Summary")
        md.append(
            f"This defensive security assessment was conducted under authorized rules of engagement. "
            f"A total of **{len(findings)}** finding(s) were identified across the verified scope. "
            f"Summary breakdown: **{critical_count}** Critical, **{high_count}** High, "
            f"**{medium_count}** Medium, **{low_count}** Low, and **{info_count}** Informational."
        )
        md.append("")

        md.append("## 3. Authorized Scope Boundary")
        md.append("| Rule ID | Type | Target Pattern | Policy | Environment |")
        md.append("|---|---|---|---|---|")
        for s in scope_items:
            policy = "**IN SCOPE (Allow)**" if s.inScope else "**EXCLUDED (Strict Block)**"
            md.append(f"| `{s.id}` | {s.type} | `{s.value}` | {policy} | {s.environment or 'unknown'} |")
        md.append("")

        md.append("## 4. Methodology & Scope Guard Verification")
        md.append(
            "All assessments were executed through the AllTools-CyberSec defensive workbench. "
            "Every target query passed strict `Scope Guard` pre-flight validation enforcing fail-closed "
            "default-deny behavior. Out-of-scope targets were strictly blocked before transmission."
        )
        md.append("")

        md.append("## 5. Summary of Findings")
        if not findings:
            md.append("*No security vulnerabilities were identified in the assessed scope.*")
        else:
            md.append("| ID | Severity | Title | CWE | Status |")
            md.append("|---|---|---|---|---|")
            for f in findings:
                md.append(f"| `{f.id}` | **{f.severity.upper()}** | {f.title} | {f.cwe or '—'} | {f.status} |")
        md.append("")

        md.append("## 6. Detailed Findings & Recommendations")
        for f in findings:
            md.append(f"### [{f.id}] {f.title}")
            md.append(f"- **Severity:** `{f.severity.upper()}` | **Confidence:** `{f.confidence}` | **Status:** `{f.status}`")
            if f.cwe:
                md.append(f"- **Classification:** `{f.cwe}`")
            md.append("")
            md.append("#### Observed Fact & Description")
            md.append(f.description or "No description provided.")
            md.append("")
            if f.impact:
                md.append("#### Technical Impact")
                md.append(f.impact)
                md.append("")
            if f.recommendation:
                md.append("#### Remediation Recommendation")
                md.append(f.recommendation)
                md.append("")

        md.append("## 7. Cryptographic Evidence Log")
        md.append("| Evidence ID | Type | Source Target | SHA-256 Digest | Redacted |")
        md.append("|---|---|---|---|---|")
        for ev in evidence_list:
            redacted_str = "Yes" if ev.redacted else "No"
            md.append(f"| `{ev.id}` | {ev.type} | `{ev.source or 'N/A'}` | `{ev.sha256[:16]}...` | {redacted_str} |")
        md.append("")

        md.append("## 8. Appendix & Standards References")
        md.append("- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)")
        md.append("- [RFC 7208 — Sender Policy Framework (SPF)](https://www.rfc-editor.org/rfc/rfc7208)")
        md.append("- [RFC 7489 — Domain-based Message Authentication, Reporting, and Conformance (DMARC)](https://www.rfc-editor.org/rfc/rfc7489)")
        md.append("- [NIST SP 800-52 Rev. 2 — Guidelines for the Selection and Use of TLS](https://csrc.nist.gov/)")
        md.append("")

        return "\n".join(md)

    @classmethod
    def generate_html(
        cls,
        engagement: Engagement,
        assessment: Assessment,
        scope_items: List[ScopeItem],
        findings: List[Finding],
        evidence_list: List[Evidence],
    ) -> str:
        md_content = cls.generate_markdown(engagement, assessment, scope_items, findings, evidence_list)
        # Produce a self-contained, printable, dark-first styled HTML page
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Assessment Report — {engagement.name}</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.6;
      color: #1e293b;
      max-width: 900px;
      margin: 40px auto;
      padding: 0 20px;
    }}
    h1 {{ color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 12px; }}
    h2 {{ color: #1e293b; border-bottom: 1px solid #cbd5e1; padding-bottom: 8px; margin-top: 32px; }}
    h3 {{ color: #334155; margin-top: 24px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 14px; }}
    th, td {{ padding: 10px 14px; border: 1px solid #cbd5e1; text-align: left; }}
    th {{ background-color: #f1f5f9; font-weight: 600; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 13px; }}
    pre {{ background: #f8fafc; border: 1px solid #e2e8f0; padding: 12px; border-radius: 6px; overflow-x: auto; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
    .badge-high {{ background: #fee2e2; color: #dc2626; }}
    .badge-med {{ background: #fef3c7; color: #d97706; }}
    .badge-low {{ background: #dbeafe; color: #2563eb; }}
    @media print {{
      body {{ max-width: 100%; margin: 0; padding: 20px; }}
      h2 {{ page-break-before: auto; }}
    }}
  </style>
</head>
<body>
  <div style="margin-bottom: 24px; font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em;">
    AllTools-CyberSec • Authorized Defensive Security Workbench
  </div>
  <pre style="white-space: pre-wrap; font-family: inherit; background: transparent; border: none; padding: 0;">{md_content}</pre>
</body>
</html>"""
        return html
