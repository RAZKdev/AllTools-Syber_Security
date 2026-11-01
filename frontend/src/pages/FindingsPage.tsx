import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Search,
  Filter,
  RefreshCw,
  FileCode,
} from 'lucide-react';
import {
  api,
  Finding,
  Evidence,
} from '@/services/api';
import { DEMO_FINDINGS, DEMO_EVIDENCE } from '@/demo/fixtures';
import { DataTable, DataTableColumn } from '@/components/DataTable';
import { SeverityBadge } from '@/components/SeverityBadge';
import { StatusBadge } from '@/components/StatusBadge';
import { DetailPanel, DetailTab } from '@/components/DetailPanel';
import { StatePanel } from '@/components/StatePanel';
import { DemoBadge } from '@/components/DemoBadge';
import { KeyValue } from '@/components/KeyValue';
import { FilterTabs } from '@/components/FilterTabs';

interface FindingsPageProps {
  isDemoMode: boolean;
}

export const FindingsPage: React.FC<FindingsPageProps> = ({ isDemoMode }) => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [evidenceList, setEvidenceList] = useState<Evidence[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const loadData = async () => {
    setLoading(true);
    setError(null);
    setSelectedFinding(null);

    if (isDemoMode) {
      setFindings(DEMO_FINDINGS);
      setEvidenceList(DEMO_EVIDENCE);
      setSelectedFinding(DEMO_FINDINGS[0] || null);
      setLoading(false);
      return;
    }

    try {
      const [fndRes, evdRes] = await Promise.all([
        api.getFindings().catch(() => []),
        api.getEvidence().catch(() => []),
      ]);

      setFindings(fndRes);
      setEvidenceList(evdRes);
      setSelectedFinding(fndRes.length > 0 ? fndRes[0] : null);
    } catch (err: any) {
      setError(err?.message || 'Failed to retrieve findings from backend');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [isDemoMode]);

  const filteredFindings = findings.filter((f) => {
    if (filterSeverity !== 'all' && f.severity !== filterSeverity) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        (f.description && f.description.toLowerCase().includes(q)) ||
        (f.ruleId && f.ruleId.toLowerCase().includes(q)) ||
        (f.cwe && f.cwe.toLowerCase().includes(q)) ||
        f.id.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const matchedEvidence = selectedFinding
    ? evidenceList.filter((e) => e.findingId === selectedFinding.id)
    : [];

  const columns: DataTableColumn<Finding>[] = [
    {
      key: 'severity',
      label: 'Severity',
      width: '100px',
      render: (row) => <SeverityBadge severity={row.severity} size="sm" />,
    },
    {
      key: 'id',
      label: 'Finding ID',
      width: '110px',
      render: (row) => (
        <code style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
          {row.id}
        </code>
      ),
    },
    {
      key: 'title',
      label: 'Vulnerability Title',
      render: (row) => (
        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
          {row.title}
        </span>
      ),
    },
    {
      key: 'ruleId',
      label: 'Rule Module',
      width: '110px',
      render: (row) => (
        <code style={{ color: 'var(--accent)', fontSize: '11px' }}>
          {row.ruleId || '—'}
        </code>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      width: '120px',
      render: (row) => <StatusBadge status={row.status} size="sm" />,
    },
    {
      key: 'assetId',
      label: 'Asset',
      width: '100px',
      render: (row) => (
        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
          {row.assetId}
        </span>
      ),
    },
  ];

  // Multi-tab detail inspector
  const inspectorTabs: DetailTab[] = selectedFinding
    ? [
        {
          id: 'advisory',
          label: 'Advisory Overview',
          content: (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '6px' }}>
                  <SeverityBadge severity={selectedFinding.severity} />
                  <StatusBadge status={selectedFinding.status} />
                  {selectedFinding.cwe && (
                    <span className="wb-chip" style={{ background: 'var(--bg-surface-elevated)' }}>
                      {selectedFinding.cwe}
                    </span>
                  )}
                </div>
                <h2 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                  {selectedFinding.title}
                </h2>
              </div>

              <div>
                <div
                  style={{
                    fontSize: '10px',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    color: 'var(--text-muted)',
                    marginBottom: '4px',
                  }}
                >
                  Technical Description & Vulnerability Details
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-primary)', lineHeight: 1.6 }}>
                  {selectedFinding.description || 'No description recorded.'}
                </div>
              </div>

              {selectedFinding.impact && (
                <div
                  style={{
                    padding: '10px 12px',
                    background: 'var(--sev-high-bg)',
                    border: '1px solid var(--sev-high-border)',
                    borderRadius: '4px',
                  }}
                >
                  <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--sev-high-text)', marginBottom: '2px' }}>
                    Technical Impact
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-primary)', lineHeight: 1.5 }}>
                    {selectedFinding.impact}
                  </div>
                </div>
              )}
            </div>
          ),
        },
        {
          id: 'remediation',
          label: 'Remediation',
          content: (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <div
                style={{
                  fontSize: '10px',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  color: 'var(--accent)',
                }}
              >
                Actionable Remediation Guidance
              </div>
              <pre
                style={{
                  fontSize: '12px',
                  fontFamily: 'inherit',
                  color: 'var(--text-primary)',
                  lineHeight: 1.6,
                  whiteSpace: 'pre-wrap',
                  background: 'var(--bg-table-zebra)',
                  padding: '12px',
                  border: '1px solid var(--border-default)',
                  borderRadius: '4px',
                }}
              >
                {selectedFinding.recommendation || 'No specific remediation recommendation provided.'}
              </pre>
            </div>
          ),
        },
        {
          id: 'evidence',
          label: `Evidence (${matchedEvidence.length})`,
          content: (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {matchedEvidence.length > 0 ? (
                matchedEvidence.map((evd) => (
                  <div
                    key={evd.id}
                    style={{
                      background: 'var(--bg-table-zebra)',
                      border: '1px solid var(--border-default)',
                      padding: '12px',
                      borderRadius: '4px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '6px',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <code style={{ fontWeight: 700, color: 'var(--accent)' }}>
                        {evd.id}
                      </code>
                      <span className="wb-chip" style={{ background: 'var(--bg-surface-elevated)' }}>
                        {evd.type}
                      </span>
                    </div>

                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      Source Target: <code>{evd.source || '—'}</code>
                    </div>

                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      SHA-256 Digest:
                      <code
                        style={{
                          display: 'block',
                          color: 'var(--text-primary)',
                          background: 'var(--bg-surface)',
                          padding: '4px 6px',
                          marginTop: '2px',
                          wordBreak: 'break-all',
                        }}
                      >
                        {evd.sha256}
                      </code>
                    </div>

                    {evd.notes && (
                      <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                        Notes: {evd.notes}
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <FileCode size={24} style={{ margin: '0 auto 8px auto', display: 'block', opacity: 0.5 }} />
                  No cryptographic evidence attachments recorded for finding {selectedFinding.id}.
                </div>
              )}
            </div>
          ),
        },
        {
          id: 'metadata',
          label: 'Metadata & Audit',
          content: (
            <KeyValue
              items={[
                { key: 'Finding ID', value: selectedFinding.id },
                { key: 'Assessment ID', value: selectedFinding.assessmentId },
                { key: 'Asset ID', value: selectedFinding.assetId },
                { key: 'Rule Module', value: selectedFinding.ruleId || 'N/A' },
                { key: 'Classification', value: selectedFinding.cwe || 'None' },
                { key: 'CVE Reference', value: selectedFinding.cve || 'None' },
                { key: 'CVSS Score', value: selectedFinding.cvss ?? 'Not scored' },
                { key: 'Confidence', value: selectedFinding.confidence.toUpperCase() },
                { key: 'Status', value: selectedFinding.status },
                {
                  key: 'Discovered (UTC)',
                  value: new Date(selectedFinding.createdAt).toUTCString(),
                },
              ]}
            />
          ),
        },
      ]
    : [
        {
          id: 'none',
          label: 'Advisory Overview',
          content: (
            <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Select a finding from the table to inspect details and cryptographic evidence.
            </div>
          ),
        },
      ];

  if (loading && !isDemoMode) {
    return <StatePanel kind="loading" title="Retrieving Discovered Findings..." />;
  }

  if (error && !isDemoMode) {
    return (
      <StatePanel
        kind="offline"
        title="Findings Repository Offline"
        description="Could not query vulnerability findings from local backend API."
        errorMessage={error}
        onRetry={loadData}
      />
    );
  }

  return (
    <div className="wb-split-h">
      {/* =========================================================================
          Left Pane: Findings Table with Search & Filter Tabs
          ========================================================================= */}
      <div className="wb-panel">
        <div className="wb-panel-header">
          <div className="wb-panel-title">
            <AlertTriangle size={14} color="var(--sev-high-text)" />
            <span>Discovered Vulnerability Findings</span>
            <span className="wb-panel-count">{filteredFindings.length}</span>
            {isDemoMode && <DemoBadge />}
          </div>
          <button
            onClick={loadData}
            className="wb-btn wb-btn-sm"
            title="Refresh findings from backend"
          >
            <RefreshCw size={10} />
            Refresh
          </button>
        </div>

        <div className="wb-toolbar">
          <div className="wb-toolbar-group">
            <Filter size={12} color="var(--text-muted)" />
            <FilterTabs
              options={[
                { id: 'all', label: 'All', count: findings.length },
                {
                  id: 'critical',
                  label: 'Critical',
                  count: findings.filter((f) => f.severity === 'critical').length,
                },
                {
                  id: 'high',
                  label: 'High',
                  count: findings.filter((f) => f.severity === 'high').length,
                },
                {
                  id: 'medium',
                  label: 'Medium',
                  count: findings.filter((f) => f.severity === 'medium').length,
                },
                {
                  id: 'low',
                  label: 'Low',
                  count: findings.filter((f) => f.severity === 'low').length,
                },
              ]}
              activeId={filterSeverity}
              onChange={setFilterSeverity}
            />
          </div>

          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <Search size={12} color="var(--text-muted)" />
            <input
              type="text"
              className="wb-input"
              placeholder="Search title, CWE, rule..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ width: '160px', padding: '3px 6px', fontSize: '11px' }}
            />
          </div>
        </div>

        <div className="wb-panel-body">
          <DataTable
            columns={columns}
            data={filteredFindings}
            keyExtractor={(row) => row.id}
            selectedId={selectedFinding?.id}
            onSelectRow={(row) => setSelectedFinding(row)}
            emptyMessage={
              searchQuery || filterSeverity !== 'all'
                ? 'No findings match the current filter criteria.'
                : 'No vulnerability findings recorded. Execute checks from the Check Executions tab.'
            }
          />
        </div>
      </div>

      {/* =========================================================================
          Right Pane: Multi-Tab Detail Inspector
          ========================================================================= */}
      <div style={{ height: '100%', overflow: 'hidden' }}>
        <DetailPanel
          title={
            selectedFinding
              ? `Finding Inspector: ${selectedFinding.id}`
              : 'Finding Inspector'
          }
          tabs={inspectorTabs}
        />
      </div>
    </div>
  );
};
