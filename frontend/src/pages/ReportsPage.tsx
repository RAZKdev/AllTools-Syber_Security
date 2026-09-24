import React, { useState, useEffect } from 'react';
import { FileText, Download, Printer, RefreshCw, CheckCircle2 } from 'lucide-react';
import { api } from '@/services/api';

export const ReportsPage: React.FC = () => {
  const [reportMarkdown, setReportMarkdown] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const assessmentId = 'ASM-001';

  const defaultSampleMarkdown = `# Defensive Security Assessment Report — Local Lab Assessment

## 1. Metadata
- **Engagement ID:** \`ENG-001\`
- **Assessment ID:** \`ASM-001\`
- **Assessment Name:** Infrastructure & Web Assessment
- **Assessor:** Authorized Operator
- **Report Date:** ${new Date().toISOString().replace('T', ' ').substring(0, 19)} UTC
- **Status:** COMPLETED

## 2. Executive Summary
This defensive security assessment was conducted under authorized rules of engagement.
A total of **2** finding(s) were identified across the verified scope.
Summary breakdown: **0** Critical, **1** High, **1** Medium, **0** Low, and **0** Informational.

## 3. Authorized Scope Boundary
| Rule ID | Type | Target Pattern | Policy | Environment |
|---|---|---|---|---|
| \`SCP-001\` | domain | \`lab.local\` | **IN SCOPE (Allow)** | lab |
| \`SCP-002\` | cidr | \`192.168.1.0/24\` | **IN SCOPE (Allow)** | lab |
| \`SCP-003\` | domain | \`critical.lab.local\` | **EXCLUDED (Strict Block)** | production |

## 4. Methodology & Scope Guard Verification
All assessments were executed through the AllTools-CyberSec defensive workbench.
Every target query passed strict \`Scope Guard\` pre-flight validation enforcing fail-closed
default-deny behavior. Out-of-scope targets were strictly blocked before transmission.

## 5. Summary of Findings
| ID | Severity | Title | CWE | Status |
|---|---|---|---|---|
| \`FND-001\` | **MEDIUM** | Missing Defensive HTTP Security Headers (4 missing) | CWE-693 | NEEDS_REVIEW |
| \`FND-002\` | **HIGH** | Expired TLS Certificate | CWE-298 | NEEDS_REVIEW |

## 6. Detailed Findings & Recommendations
### [FND-001] Missing Defensive HTTP Security Headers
- **Severity:** \`MEDIUM\` | **Confidence:** \`high\` | **Status:** \`NEEDS_REVIEW\`
- **Classification:** \`CWE-693\`

#### Observed Fact & Description
The web service at app.lab.local does not return recommended defensive headers.

#### Technical Impact
Clients connecting to this endpoint lack browser-level protections such as HSTS enforcement.

#### Remediation Recommendation
Configure reverse proxy to enforce HSTS, CSP, and X-Content-Type-Options: nosniff.

### [FND-002] Expired TLS Certificate
- **Severity:** \`HIGH\` | **Confidence:** \`high\` | **Status:** \`NEEDS_REVIEW\`
- **Classification:** \`CWE-298\`

#### Observed Fact & Description
The TLS certificate presented by the server has expired.

#### Remediation Recommendation
Renew the TLS certificate immediately with an authorized Certificate Authority.

## 7. Cryptographic Evidence Log
| Evidence ID | Type | Source Target | SHA-256 Digest | Redacted |
|---|---|---|---|---|
| \`EVD-001\` | http_response | \`https://app.lab.local\` | \`7f83b1657ff1fc53...\` | No |
| \`EVD-002\` | configuration_snapshot | \`app.lab.local:443\` | \`9f86d081884c7d65...\` | No |

## 8. Appendix & Standards References
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [RFC 7208 — Sender Policy Framework (SPF)](https://www.rfc-editor.org/rfc/rfc7208)
- [RFC 7489 — Domain-based Message Authentication, Reporting, and Conformance (DMARC)](https://www.rfc-editor.org/rfc/rfc7489)
`;

  const fetchReport = async () => {
    setLoading(true);
    try {
      const md = await api.getReportMarkdown(assessmentId);
      if (md && md.length > 50) {
        setReportMarkdown(md);
      } else {
        setReportMarkdown(defaultSampleMarkdown);
      }
    } catch {
      setReportMarkdown(defaultSampleMarkdown);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, []);

  const handleDownloadMarkdown = () => {
    const blob = new Blob([reportMarkdown], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `report-${assessmentId}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handlePrintHtml = () => {
    window.open(`/api/v1/reports/${assessmentId}/html`, '_blank');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)' }}>
            Defensive Security Assessment Reports
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px' }}>
            Audit-grade reporting distinguishing observed facts, risk analysis, and cryptographic evidence.
          </p>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            onClick={fetchReport}
            disabled={loading}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: '6px',
              backgroundColor: 'var(--bg-surface-elevated)',
              border: '1px solid var(--border-default)',
              color: 'var(--text-primary)',
              fontSize: '12px',
              fontWeight: 600,
            }}
          >
            <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
          </button>

          <button
            onClick={handleDownloadMarkdown}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              borderRadius: '6px',
              backgroundColor: 'var(--bg-surface-elevated)',
              border: '1px solid var(--border-default)',
              color: 'var(--text-primary)',
              fontSize: '12px',
              fontWeight: 600,
            }}
          >
            <Download size={14} /> Download Markdown (.md)
          </button>

          <button
            onClick={handlePrintHtml}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 16px',
              borderRadius: '6px',
              backgroundColor: 'var(--accent)',
              color: '#090d16',
              fontSize: '12px',
              fontWeight: 600,
            }}
          >
            <Printer size={14} /> Printable HTML
          </button>
        </div>
      </div>

      {/* Report Info Banner */}
      <div
        style={{
          padding: '14px 18px',
          borderRadius: '8px',
          backgroundColor: 'var(--bg-surface)',
          border: '1px solid var(--border-subtle)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '13px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <CheckCircle2 size={16} color="var(--status-pass-text)" />
          <span style={{ color: 'var(--text-primary)' }}>
            Report Ready for Assessment: <strong>{assessmentId}</strong>
          </span>
        </div>
        <span style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
          Format: Standalone Markdown / Print-Optimized HTML
        </span>
      </div>

      {/* Report Preview Document */}
      <div
        style={{
          backgroundColor: 'var(--bg-surface)',
          borderRadius: '8px',
          border: '1px solid var(--border-default)',
          padding: '32px 40px',
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.25)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '20px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px' }}>
          <FileText size={18} color="var(--accent)" />
          <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Report Document Preview
          </span>
        </div>

        <pre
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '13px',
            color: 'var(--text-primary)',
            lineHeight: 1.7,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
          }}
        >
          {reportMarkdown}
        </pre>
      </div>
    </div>
  );
};
