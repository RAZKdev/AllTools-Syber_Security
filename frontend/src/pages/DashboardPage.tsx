import React from 'react';
import { Target, CheckCircle2, ShieldAlert, AlertTriangle, ArrowRight, ShieldCheck, Globe, Lock, Cpu, Network, KeyRound } from 'lucide-react';
import { StatusBadge } from '@/components/StatusBadge';

interface DashboardPageProps {
  onNavigateToScope: () => void;
  onNavigateToExecutions: () => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  onNavigateToScope,
  onNavigateToExecutions,
}) => {
  // Sample workbench state representing local laboratory
  const metrics = [
    { title: 'Active Assessments', value: '2', subtitle: 'Web & Infrastructure', icon: CheckCircle2, color: 'var(--status-pass-text)' },
    { title: 'Defensive Security Tools', value: '11 Active', subtitle: 'Web, TLS, DNS, Net, Crypto, Auth', icon: Target, color: 'var(--accent)' },
    { title: 'Scope Blocks Prevented', value: '14', subtitle: 'Default-deny triggered', icon: ShieldAlert, color: 'var(--status-blocked-text)' },
    { title: 'Findings Pending Review', value: '3', subtitle: '1 High, 2 Medium', icon: AlertTriangle, color: 'var(--sev-high-text)' },
  ];

  const securityTools = [
    { id: 'SEC-WEB-001', name: 'HTTP Security Headers', category: 'Web', icon: Globe, desc: 'Validates HSTS, CSP, X-Frame-Options & anti-sniffing directives' },
    { id: 'SEC-WEB-002', name: 'Cookie Security Flags', category: 'Web', icon: Globe, desc: 'Audits Secure, HttpOnly, and SameSite protection flags' },
    { id: 'SEC-WEB-003', name: 'Tech Stack Disclosure', category: 'Web', icon: Globe, desc: 'Detects Server, X-Powered-By, and framework banner leaks' },
    { id: 'SEC-WEB-004', name: 'CORS Policy Auditor', category: 'Web', icon: Globe, desc: 'Flags wildcard origins with credentials & insecure headers' },
    { id: 'SEC-WEB-005', name: 'Sensitive File Exposure', category: 'Web', icon: Globe, desc: 'Probes .git, .env, and RFC 9116 security.txt posture' },
    { id: 'SEC-TLS-001', name: 'TLS & Cipher Check', category: 'Transport', icon: Lock, desc: 'Verifies certificate validity, SANs, and SSL/TLS deprecation' },
    { id: 'SEC-NET-001', name: 'Authorized Port Exposure', category: 'Network', icon: Network, desc: 'Audits accessible TCP ports against authorized profiles' },
    { id: 'SEC-DNS-001', name: 'DNS SPF & DMARC Posture', category: 'DNS', icon: ShieldCheck, desc: 'Evaluates anti-spoofing policies and mailbox authentication' },
    { id: 'SEC-DNS-002', name: 'DNS CAA Record Check', category: 'DNS', icon: ShieldCheck, desc: 'Ensures authorized Certificate Authorities are pinned' },
    { id: 'SEC-CRYPTO-001', name: 'Crypto Hash Strength', category: 'Crypto', icon: Cpu, desc: 'Identifies broken algorithms (MD5, SHA1) vs modern standards' },
    { id: 'SEC-AUTH-001', name: 'Password Policy & Entropy', category: 'Identity', icon: KeyRound, desc: 'NIST SP 800-63B Shannon entropy & dictionary audit' },
  ];

  const recentExecutions = [
    { id: 'CHK-9a2c1b', ruleId: 'SEC-WEB-001', target: 'app.lab.local', scopeDecision: 'ALLOW', status: 'PASS', time: '2 mins ago' },
    { id: 'CHK-8f4d2e', ruleId: 'SEC-TLS-001', target: '192.168.1.100:443', scopeDecision: 'ALLOW', status: 'WARN', time: '14 mins ago' },
    { id: 'CHK-7b1a99', ruleId: 'SEC-NET-001', target: 'external-site.com', scopeDecision: 'BLOCK', status: 'BLOCKED_OUT_OF_SCOPE', time: '28 mins ago' },
    { id: 'CHK-6c2e4f', ruleId: 'SEC-DNS-001', target: 'ns1.lab.local', scopeDecision: 'ALLOW', status: 'PASS', time: '1 hour ago' },
    { id: 'CHK-5d1f88', ruleId: 'SEC-AUTH-001', target: 'AdminPassword!2026', scopeDecision: 'ALLOW', status: 'PASS', time: '1.5 hours ago' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      {/* Top Banner / Core Flow */}
      <div
        style={{
          padding: '20px 24px',
          borderRadius: '8px',
          backgroundColor: 'var(--bg-surface)',
          border: '1px solid var(--border-default)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <div>
            <h1 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)' }}>
              Practical Defensive Security Workbench
            </h1>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Authorized assessment workflow under strict Scope Guard enforcement.
            </p>
          </div>
          <button
            onClick={onNavigateToScope}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '8px 14px',
              backgroundColor: 'var(--accent-muted)',
              border: '1px solid var(--accent)',
              borderRadius: '6px',
              color: 'var(--accent)',
              fontSize: '12px',
              fontWeight: 600,
            }}
          >
            Manage Scope <ArrowRight size={14} />
          </button>
        </div>

        {/* Workflow breadcrumbs */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            fontSize: '11px',
            color: 'var(--text-muted)',
            fontFamily: 'var(--font-mono)',
            overflowX: 'auto',
            paddingTop: '6px',
          }}
        >
          <span style={{ color: 'var(--accent)', fontWeight: 600 }}>Engagement</span> →
          <span style={{ color: 'var(--accent)', fontWeight: 600 }}>Scope</span> →
          <span>Assets</span> →
          <span>Assessment</span> →
          <span>Checks</span> →
          <span>Observation</span> →
          <span>Finding</span> →
          <span>Evidence</span> →
          <span>Risk</span> →
          <span>Remediation</span> →
          <span>Retest</span> →
          <span>Report</span>
        </div>
      </div>

      {/* Metrics Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
        {metrics.map((m, idx) => {
          const Icon = m.icon;
          return (
            <div
              key={idx}
              style={{
                padding: '20px',
                borderRadius: '8px',
                backgroundColor: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span style={{ fontSize: '13px', color: 'var(--text-secondary)', fontWeight: 500 }}>{m.title}</span>
                <Icon size={18} color={m.color} />
              </div>
              <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                {m.value}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                {m.subtitle}
              </div>
            </div>
          );
        })}
      </div>

      {/* Defensive Tool Catalog Grid */}
      <div
        style={{
          borderRadius: '8px',
          backgroundColor: 'var(--bg-surface)',
          border: '1px solid var(--border-subtle)',
          padding: '20px 24px',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <h2 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Defensive Security Tools Catalog ({securityTools.length} Modules)
            </h2>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Standardized defensive analyzers aligned with OWASP ASVS, NIST SP 800-63B, and CIS benchmarks.
            </p>
          </div>
          <button
            onClick={onNavigateToExecutions}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '6px 12px',
              backgroundColor: 'var(--bg-surface-elevated)',
              border: '1px solid var(--border-default)',
              borderRadius: '6px',
              color: 'var(--text-primary)',
              fontSize: '12px',
              fontWeight: 500,
            }}
          >
            Launch in Workbench <ArrowRight size={14} />
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '12px' }}>
          {securityTools.map((tool) => {
            const Icon = tool.icon;
            return (
              <div
                key={tool.id}
                onClick={onNavigateToExecutions}
                style={{
                  padding: '14px 16px',
                  borderRadius: '6px',
                  backgroundColor: 'var(--bg-canvas)',
                  border: '1px solid var(--border-subtle)',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '11px',
                      fontWeight: 700,
                      color: 'var(--accent)',
                    }}
                  >
                    {tool.id}
                  </span>
                  <span
                    style={{
                      fontSize: '10px',
                      padding: '2px 6px',
                      borderRadius: '4px',
                      backgroundColor: 'var(--bg-surface-elevated)',
                      color: 'var(--text-secondary)',
                      fontWeight: 500,
                    }}
                  >
                    {tool.category}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Icon size={16} color="var(--text-primary)" />
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {tool.name}
                  </div>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', lineHeight: '1.4' }}>
                  {tool.desc}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Recent Executions Table */}
      <div
        style={{
          borderRadius: '8px',
          backgroundColor: 'var(--bg-surface)',
          border: '1px solid var(--border-subtle)',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            padding: '16px 20px',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <div>
            <h2 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Recent Check Executions & Scope Decisions
            </h2>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Every check is validated against Scope Guard before target execution.
            </p>
          </div>
          <button
            onClick={onNavigateToExecutions}
            style={{
              fontSize: '12px',
              color: 'var(--accent)',
              fontWeight: 600,
            }}
          >
            View All Executions
          </button>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
            <thead>
              <tr style={{ backgroundColor: 'var(--bg-surface-elevated)', color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-subtle)' }}>
                <th style={{ padding: '12px 20px', fontWeight: 600 }}>Execution ID</th>
                <th style={{ padding: '12px 20px', fontWeight: 600 }}>Rule</th>
                <th style={{ padding: '12px 20px', fontWeight: 600 }}>Target</th>
                <th style={{ padding: '12px 20px', fontWeight: 600 }}>Scope Decision</th>
                <th style={{ padding: '12px 20px', fontWeight: 600 }}>Status</th>
                <th style={{ padding: '12px 20px', fontWeight: 600 }}>Time</th>
              </tr>
            </thead>
            <tbody>
              {recentExecutions.map((row) => (
                <tr key={row.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '12px 20px', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                    {row.id}
                  </td>
                  <td style={{ padding: '12px 20px', fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>
                    {row.ruleId}
                  </td>
                  <td style={{ padding: '12px 20px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                    {row.target}
                  </td>
                  <td style={{ padding: '12px 20px' }}>
                    <span
                      style={{
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: 700,
                        fontFamily: 'var(--font-mono)',
                        backgroundColor: row.scopeDecision === 'ALLOW' ? 'var(--status-pass-bg)' : 'var(--status-blocked-bg)',
                        color: row.scopeDecision === 'ALLOW' ? 'var(--status-pass-text)' : 'var(--status-blocked-text)',
                      }}
                    >
                      {row.scopeDecision}
                    </span>
                  </td>
                  <td style={{ padding: '12px 20px' }}>
                    <StatusBadge status={row.status} size="sm" />
                  </td>
                  <td style={{ padding: '12px 20px', color: 'var(--text-muted)', fontSize: '12px' }}>
                    {row.time}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
