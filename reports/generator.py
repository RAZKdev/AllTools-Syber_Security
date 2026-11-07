import html
from datetime import datetime, timezone
from typing import List, Optional
from app.schemas.assessment import Assessment
from app.schemas.check_execution import CheckExecution
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
        executions: Optional[List[CheckExecution]] = None,
    ) -> str:
        now = datetime.now(timezone.utc)
        now_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")

        def is_expired(scope_item: ScopeItem) -> bool:
            if not scope_item.expiresAt:
                return False
            expires_at = scope_item.expiresAt
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            return expires_at <= now

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
        expired_count = 0
        for s in scope_items:
            if is_expired(s):
                policy = "**EXPIRED (Not Authorized)**"
                expired_count += 1
            elif s.inScope:
                policy = "**IN SCOPE (Allow)**"
            else:
                policy = "**EXCLUDED (Strict Block)**"
            md.append(f"| `{s.id}` | {s.type} | `{s.value}` | {policy} | {s.environment or 'unknown'} |")
        if expired_count:
            md.append("")
            md.append(
                f"*{expired_count} scope rule(s) are expired and are not active authorization. "
                "Expired rules cannot authorize a target.*"
            )
        md.append("")

        md.append("## 4. Methodology & Scope Guard Verification")
        md.append(
            "All target checks were evaluated by the backend `Scope Guard` before execution. "
            "Network targets outside the authorized scope were blocked before transmission. "
            "Local-only analysis rules do not transmit data to a target."
        )
        if executions:
            md.append("")
            md.append("### Recorded Check Executions")
            md.append("| Execution ID | Rule ID | Target | Decision | Status | Duration |")
            md.append("|---|---|---|---|---|---|")
            local_analysis_allow = False
            local_analysis_rules = {"SEC-AUTH-001", "SEC-CRYPTO-001"}
            for ex in executions:
                dur = f"{ex.durationMs}ms" if ex.durationMs is not None else "—"
                decision_val = ex.scopeDecision.value if hasattr(ex.scopeDecision, "value") else str(ex.scopeDecision)
                status_val = ex.status.value if hasattr(ex.status, "value") else str(ex.status)
                if ex.ruleId in local_analysis_rules and decision_val == "ALLOW":
                    local_analysis_allow = True
                md.append(f"| `{ex.id}` | `{ex.ruleId}` | `{ex.target}` | {decision_val} | `{status_val}` | {dur} |")
            if local_analysis_allow:
                md.append("")
                md.append(
                    "*`ALLOW` for local-analysis rules (`SEC-AUTH-001`, `SEC-CRYPTO-001`) authorizes "
                    "local input analysis only. No network transmission occurs for these checks.*"
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
        executions: Optional[List[CheckExecution]] = None,
    ) -> str:
        md_content = cls.generate_markdown(
            engagement=engagement,
            assessment=assessment,
            scope_items=scope_items,
            findings=findings,
            evidence_list=evidence_list,
            executions=executions,
        )
        safe_title = html.escape(engagement.name, quote=True)
        safe_md_content = html.escape(md_content, quote=True)

        # Produce a self-contained, printable, dark-first styled HTML page with strict CSP and escaping
        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; font-src 'none'; img-src 'none'; sandbox;">
  <meta http-equiv="X-Content-Type-Options" content="nosniff">
  <title>Security Assessment Report — {safe_title}</title>
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
  <pre style="white-space: pre-wrap; font-family: inherit; background: transparent; border: none; padding: 0;">{safe_md_content}</pre>
</body>
</html>"""
        return html_doc
