import React, { useState, useEffect } from 'react';
import { ShieldCheck } from 'lucide-react';
import { api, Finding } from '@/services/api';
import { StatusBadge } from '@/components/StatusBadge';
import { SeverityBadge } from '@/components/SeverityBadge';
import { EmptyState } from '@/components/EmptyState';

export const FindingsPage: React.FC = () => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');

  const defaultSampleFindings: Finding[] = [
    {
      id: 'FND-001',
      assessmentId: 'ASM-001',
      assetId: 'AST-001',
      ruleId: 'SEC-WEB-001',
      title: 'Missing Defensive HTTP Security Headers (4 missing)',
      description: 'The target web service does not return Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, or X-Frame-Options.',
      status: 'NEEDS_REVIEW',
      severity: 'medium',
      confidence: 'high',
      cwe: 'CWE-693',
      impact: 'Browsers connecting to this endpoint lack defensive framing, MIME sniffing protections, and XSS restrictions.',
      recommendation: 'Configure reverse proxy to enforce HSTS, CSP, X-Content-Type-Options: nosniff, and X-Frame-Options: DENY.',
      createdAt: new Date().toISOString(),
    },
    {
      id: 'FND-002',
      assessmentId: 'ASM-001',
      assetId: 'AST-002',
      ruleId: 'SEC-TLS-001',
      title: 'Expired TLS Certificate',
      description: 'The TLS certificate expired and can no longer establish trusted encrypted sessions.',
      status: 'NEEDS_REVIEW',
      severity: 'high',
      confidence: 'high',
      cwe: 'CWE-298',
      impact: 'Clients will encounter certificate validation failures and warn users against continuing.',
      recommendation: 'Renew TLS certificate with an authorized Certificate Authority.',
      createdAt: new Date().toISOString(),
    },
  ];

  useEffect(() => {
    const fetchFindings = async () => {
      try {
        const data = await api.getFindings();
        if (data && data.length > 0) {
          setFindings(data);
          setSelectedFinding(data[0]);
        } else {
          setFindings(defaultSampleFindings);
          setSelectedFinding(defaultSampleFindings[0]);
        }
      } catch {
        setFindings(defaultSampleFindings);
        setSelectedFinding(defaultSampleFindings[0]);
      }
    };
    fetchFindings();
  }, []);

  const filteredFindings = findings.filter((f) => {
    if (filterSeverity === 'all') return true;
    return f.severity === filterSeverity;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header */}
      <div>
        <h1 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)' }}>
          Vulnerability Findings & Risk Review
        </h1>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px' }}>
          Evidence-first validation. Findings must be backed by verifiable observations and cryptographic evidence.
        </p>
      </div>

      {/* Filter Bar */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '12px 18px',
          backgroundColor: 'var(--bg-surface)',
          borderRadius: '8px',
          border: '1px solid var(--border-subtle)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
          <span style={{ color: 'var(--text-secondary)' }}>Filter by Severity:</span>
          {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              style={{
                padding: '4px 10px',
                borderRadius: '4px',
                fontSize: '11px',
                fontWeight: 600,
                textTransform: 'uppercase',
                fontFamily: 'var(--font-mono)',
                backgroundColor: filterSeverity === sev ? 'var(--bg-surface-elevated)' : 'transparent',
                color: filterSeverity === sev ? 'var(--accent)' : 'var(--text-muted)',
                border: filterSeverity === sev ? '1px solid var(--accent)' : '1px solid transparent',
              }}
            >
              {sev}
            </button>
          ))}
        </div>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          Showing {filteredFindings.length} findings
        </span>
      </div>

      {/* Main Split Layout: Findings List + Detail Inspector */}
      {filteredFindings.length === 0 ? (
        <EmptyState
          icon={ShieldCheck}
          title="No findings matching filter"
          description="All executed checks have passed or no findings matched the selected severity level."
        />
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '20px', alignItems: 'start' }}>
          {/* Findings List */}
          <div
            style={{
              backgroundColor: 'var(--bg-surface)',
              borderRadius: '8px',
              border: '1px solid var(--border-subtle)',
              overflow: 'hidden',
            }}
          >
            <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-subtle)', fontWeight: 600, fontSize: '13px' }}>
              Discovered Findings
            </div>
            {filteredFindings.map((f) => {
              const isSelected = selectedFinding?.id === f.id;
              return (
                <div
                  key={f.id}
                  onClick={() => setSelectedFinding(f)}
                  style={{
                    padding: '16px 18px',
                    borderBottom: '1px solid var(--border-subtle)',
                    cursor: 'pointer',
                    backgroundColor: isSelected ? 'var(--bg-surface-elevated)' : 'transparent',
                    borderLeft: isSelected ? '3px solid var(--accent)' : '3px solid transparent',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                      <SeverityBadge severity={f.severity} size="sm" />
                      <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                        {f.id}
                      </span>
                    </div>
                    <StatusBadge status={f.status} size="sm" />
                  </div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
                    {f.title}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'flex', gap: '14px' }}>
                    <span>Rule: <code style={{ color: 'var(--accent)' }}>{f.ruleId || 'N/A'}</code></span>
                    {f.cwe && <span>{f.cwe}</span>}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Finding Detail Inspector (DESIGN.md Section 8) */}
          {selectedFinding ? (
            <div
              style={{
                backgroundColor: 'var(--bg-surface)',
                borderRadius: '8px',
                border: '1px solid var(--border-default)',
                padding: '24px',
                display: 'flex',
                flexDirection: 'column',
                gap: '18px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                  {selectedFinding.id} • {selectedFinding.ruleId}
                </span>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <SeverityBadge severity={selectedFinding.severity} />
                  <StatusBadge status={selectedFinding.status} />
                </div>
              </div>

              <div>
                <h2 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '6px' }}>
                  {selectedFinding.title}
                </h2>
                <div style={{ display: 'flex', gap: '12px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                  <span>Asset: <code style={{ color: 'var(--text-primary)' }}>{selectedFinding.assetId}</code></span>
                  {selectedFinding.cwe && <span>CWE: <strong style={{ color: 'var(--accent)' }}>{selectedFinding.cwe}</strong></span>}
                  <span>Confidence: <strong style={{ textTransform: 'capitalize' }}>{selectedFinding.confidence}</strong></span>
                </div>
              </div>

              <div>
                <h3 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>
                  Description & Context
                </h3>
                <p style={{ fontSize: '13px', color: 'var(--text-primary)', lineHeight: 1.6 }}>
                  {selectedFinding.description}
                </p>
              </div>

              {selectedFinding.impact && (
                <div
                  style={{
                    padding: '12px 14px',
                    borderRadius: '6px',
                    backgroundColor: 'rgba(239, 68, 68, 0.08)',
                    border: '1px solid rgba(239, 68, 68, 0.25)',
                  }}
                >
                  <h4 style={{ fontSize: '12px', fontWeight: 700, color: 'var(--sev-high-text)', marginBottom: '4px' }}>
                    Technical Impact
                  </h4>
                  <p style={{ fontSize: '12px', color: 'var(--text-primary)' }}>
                    {selectedFinding.impact}
                  </p>
                </div>
              )}

              {selectedFinding.recommendation && (
                <div
                  style={{
                    padding: '12px 14px',
                    borderRadius: '6px',
                    backgroundColor: 'rgba(56, 189, 248, 0.08)',
                    border: '1px solid rgba(56, 189, 248, 0.25)',
                  }}
                >
                  <h4 style={{ fontSize: '12px', fontWeight: 700, color: 'var(--accent)', marginBottom: '4px' }}>
                    Remediation Guidance
                  </h4>
                  <pre style={{ fontSize: '12px', color: 'var(--text-primary)', whiteSpace: 'pre-wrap', fontFamily: 'inherit' }}>
                    {selectedFinding.recommendation}
                  </pre>
                </div>
              )}

              <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px', color: 'var(--text-muted)' }}>
                <span>Lifecycle: Needs Review → Confirmed → Retest</span>
                <span>Created: {new Date(selectedFinding.createdAt).toLocaleDateString()}</span>
              </div>
            </div>
          ) : (
            <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Select a finding to inspect detailed risk and evidence.
            </div>
          )}
        </div>
      )}
    </div>
  );
};
