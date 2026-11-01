import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Search,
  RefreshCw,
  FileCode,
} from 'lucide-react';
import { api, Finding, Evidence } from '@/services/api';
import { DEMO_FINDINGS, DEMO_EVIDENCE } from '@/demo/fixtures';
import { DataTable, DataTableColumn } from '@/components/DataTable';
import { SeverityBadge } from '@/components/SeverityBadge';
import { StatusBadge } from '@/components/StatusBadge';
import { DetailPanel, DetailTab } from '@/components/DetailPanel';
import { StatePanel } from '@/components/StatePanel';
import { DemoBadge } from '@/components/DemoBadge';
import { KeyValue } from '@/components/KeyValue';
import { FilterTabs } from '@/components/FilterTabs';
import { PageHeader } from '@/components/PageHeader';
import { ContextSidebar } from '@/components/ContextSidebar';
import { BackendConnectionState } from '@/components/ConnectionStatus';

interface FindingsPageProps {
  isDemoMode: boolean;
  assessmentId: string | null;
  connectionState: BackendConnectionState;
  contextLoading?: boolean;
  refreshToken?: number;
}

export const FindingsPage: React.FC<FindingsPageProps> = ({
  isDemoMode,
  assessmentId,
  connectionState,
  contextLoading = false,
  refreshToken = 0,
}) => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [evidenceLoading, setEvidenceLoading] = useState<boolean>(false);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);

  const isOffline =
    connectionState === 'offline' || connectionState === 'api_error';

  const loadFindings = useCallback(async () => {
    setLoading(true);
    setError(null);
    setSelectedFinding(null);
    setEvidence([]);
    setEvidenceError(null);

    if (isDemoMode) {
      setFindings(DEMO_FINDINGS);
      setSelectedFinding(DEMO_FINDINGS[0] || null);
      setLoading(false);
      return;
    }

    if (!assessmentId) {
      setFindings([]);
      setLoading(false);
      return;
    }

    try {
      const result = await api.getFindings(assessmentId);
      setFindings(result);
      setSelectedFinding(result[0] || null);
    } catch (err: any) {
      setFindings([]);
      setError(
        err?.message || 'Failed to retrieve findings from the backend API.',
      );
    } finally {
      setLoading(false);
    }
  }, [assessmentId, isDemoMode]);

  useEffect(() => {
    loadFindings();
  }, [loadFindings, refreshToken]);

  // Evidence is fetched only for the selected finding, with its own state.
  useEffect(() => {
    if (!selectedFinding) {
      setEvidence([]);
      setEvidenceError(null);
      setEvidenceLoading(false);
      return;
    }

    if (isDemoMode) {
      setEvidence(
        DEMO_EVIDENCE.filter(
          (item) => item.findingId === selectedFinding.id,
        ),
      );
      setEvidenceError(null);
      setEvidenceLoading(false);
      return;
    }

    let cancelled = false;
    setEvidenceLoading(true);
    setEvidenceError(null);
    setEvidence([]);
    api
      .getEvidence(assessmentId || undefined, selectedFinding.id)
      .then((result) => {
        if (!cancelled) setEvidence(result);
      })
      .catch((err: any) => {
        if (!cancelled) {
          setEvidence([]);
          setEvidenceError(
            err?.message || 'Evidence request failed. No evidence is shown.',
          );
        }
      })
      .finally(() => {
        if (!cancelled) setEvidenceLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [assessmentId, isDemoMode, selectedFinding]);

  const statuses = useMemo(
    () => Array.from(new Set(findings.map((finding) => finding.status))).sort(),
    [findings],
  );

  const severityCount = (severity: string) =>
    findings.filter((finding) => finding.severity === severity).length;

  const filteredFindings = findings.filter((finding) => {
    if (filterSeverity !== 'all') {
      const target =
        filterSeverity === 'info' ? 'informational' : filterSeverity;
      if (finding.severity !== target) return false;
    }
    if (filterStatus !== 'all' && finding.status !== filterStatus) return false;
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      return (
        finding.title.toLowerCase().includes(query) ||
        (finding.description || '').toLowerCase().includes(query) ||
        (finding.ruleId || '').toLowerCase().includes(query) ||
        (finding.cwe || '').toLowerCase().includes(query) ||
        (finding.cve || '').toLowerCase().includes(query) ||
        finding.id.toLowerCase().includes(query) ||
        finding.assetId.toLowerCase().includes(query)
      );
    }
    return true;
  });

  const columns: DataTableColumn<Finding>[] = [
    {
      key: 'severity',
      label: 'Severity',
      width: '105px',
      render: (row) => <SeverityBadge severity={row.severity} size="sm" />,
    },
    {
      key: 'id',
      label: 'Finding ID',
      width: '110px',
      render: (row) => (
        <code style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{row.id}</code>
      ),
    },
    {
      key: 'title',
      label: 'Title',
      render: (row) => (
        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
          {row.title}
        </span>
      ),
    },
    {
      key: 'ruleId',
      label: 'Rule',
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
      width: '135px',
      render: (row) => <StatusBadge status={row.status} size="sm" />,
    },
    {
      key: 'assetId',
      label: 'Asset',
      width: '110px',
      render: (row) => (
        <span className="wb-mono-muted">{row.assetId}</span>
      ),
    },
    {
      key: 'createdAt',
      label: 'Discovered',
      width: '120px',
      render: (row) => (
        <span className="wb-mono-muted">
          {new Date(row.createdAt).toLocaleDateString()}
        </span>
      ),
    },
  ];

  const evidenceContent = (() => {
    if (evidenceLoading) {
      return (
        <div className="wb-inline-loading">
          <RefreshCw size={13} className="spin" /> Loading evidence…
        </div>
      );
    }
    if (evidenceError) {
      return (
        <div className="wb-alert error" role="alert">
          <strong>Evidence unavailable.</strong> {evidenceError}
        </div>
      );
    }
    if (evidence.length === 0) {
      return (
        <div className="wb-no-selection">
          <FileCode
            size={22}
            style={{ margin: '0 auto 8px auto', display: 'block', opacity: 0.5 }}
          />
          No evidence attachments are recorded for this finding.
        </div>
      );
    }
    return (
      <div className="wb-evidence-list">
        {evidence.map((item) => (
          <div key={item.id} className="wb-evidence-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '8px' }}>
              <code style={{ fontWeight: 700, color: 'var(--accent)' }}>{item.id}</code>
              <span className="wb-chip" style={{ background: 'var(--bg-surface-elevated)' }}>
                {item.type}
              </span>
            </div>
            <KeyValue
              items={[
                { key: 'Source', value: item.source || '—' },
                { key: 'Captured', value: new Date(item.capturedAt).toUTCString() },
                { key: 'SHA-256', value: item.sha256 },
                { key: 'Redacted', value: item.redacted ? 'Yes' : 'No' },
              ]}
            />
            {item.notes && <div className="wb-detail-text">{item.notes}</div>}
          </div>
        ))}
      </div>
    );
  })();

  const detailTabs: DetailTab[] = selectedFinding
    ? [
        {
          id: 'advisory',
          label: 'Advisory',
          content: (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '6px', flexWrap: 'wrap' }}>
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
                <div className="wb-section-label">Description</div>
                <div className="wb-detail-text">
                  {selectedFinding.description || 'No description recorded.'}
                </div>
              </div>

              {selectedFinding.impact && (
                <div className="wb-impact-box">
                  <div className="wb-section-label" style={{ color: 'var(--sev-high-text)' }}>
                    Technical impact
                  </div>
                  <div className="wb-detail-text">{selectedFinding.impact}</div>
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
              <div className="wb-section-label" style={{ color: 'var(--accent)' }}>
                Actionable remediation guidance
              </div>
              <pre className="wb-remediation-pre">
                {selectedFinding.recommendation ||
                  'No specific remediation recommendation provided.'}
              </pre>
            </div>
          ),
        },
        {
          id: 'evidence',
          label: `Evidence (${evidenceLoading ? '…' : evidence.length})`,
          content: evidenceContent,
        },
        {
          id: 'metadata',
          label: 'Metadata',
          content: (
            <KeyValue
              items={[
                { key: 'Finding ID', value: selectedFinding.id },
                { key: 'Assessment ID', value: selectedFinding.assessmentId },
                { key: 'Asset ID', value: selectedFinding.assetId },
                { key: 'Rule', value: selectedFinding.ruleId || 'N/A' },
                { key: 'CWE', value: selectedFinding.cwe || 'None' },
                { key: 'CVE', value: selectedFinding.cve || 'None' },
                { key: 'CVSS', value: selectedFinding.cvss ?? 'Not scored' },
                { key: 'Confidence', value: selectedFinding.confidence.toUpperCase() },
                { key: 'Status', value: selectedFinding.status },
                { key: 'Discovered (UTC)', value: new Date(selectedFinding.createdAt).toUTCString() },
                ...(selectedFinding.updatedAt
                  ? [{ key: 'Updated (UTC)', value: new Date(selectedFinding.updatedAt).toUTCString() }]
                  : []),
                { key: 'Source', value: isDemoMode ? 'DEMO fixture' : 'Backend API' },
              ]}
            />
          ),
        },
      ]
    : [
        {
          id: 'none',
          label: 'Advisory',
          content: (
            <div className="wb-no-selection">
              Select a finding from the table to inspect details and evidence.
            </div>
          ),
        },
      ];

  if (contextLoading && !isDemoMode) {
    return <StatePanel kind="loading" title="Loading workspace context…" />;
  }

  if (!assessmentId && !isDemoMode) {
    return (
      <StatePanel
        kind="empty"
        title="No assessment available"
        description="Findings require an active assessment from the backend. Create or select an assessment to continue."
      />
    );
  }

  if (loading) {
    return <StatePanel kind="loading" title="Retrieving findings…" />;
  }

  if (error) {
    return (
      <StatePanel
        kind={isOffline ? 'offline' : 'error'}
        title={isOffline ? 'Findings backend unreachable' : 'Findings request failed'}
        description="No findings are shown because the backend request did not succeed."
        errorMessage={error}
        onRetry={loadFindings}
      />
    );
  }

  return (
    <div className="wb-page-layout">
      <ContextSidebar
        title="Findings & Risks"
        footer={
          <span>
            Evidence-first: an empty list is not proof that checks passed.
          </span>
        }
      >
        <div className="wb-context-section">
          <div className="wb-section-label">Severity</div>
          <div className="wb-sidebar-filters">
            <FilterTabs
              options={[
                { id: 'all', label: 'All', count: findings.length },
                { id: 'critical', label: 'Critical', count: severityCount('critical') },
                { id: 'high', label: 'High', count: severityCount('high') },
                { id: 'medium', label: 'Medium', count: severityCount('medium') },
                { id: 'low', label: 'Low', count: severityCount('low') },
                { id: 'info', label: 'Info', count: severityCount('informational') },
              ]}
              activeId={filterSeverity}
              onChange={(id) => {
                setFilterSeverity(id);
                setSelectedFinding(null);
              }}
            />
          </div>
        </div>

        <div className="wb-context-section">
          <div className="wb-section-label">Status</div>
          <div className="wb-sidebar-filters">
            <FilterTabs
              options={[
                { id: 'all', label: 'All', count: findings.length },
                ...statuses.map((status) => ({
                  id: status,
                  label: status,
                  count: findings.filter((finding) => finding.status === status).length,
                })),
              ]}
              activeId={filterStatus}
              onChange={(id) => {
                setFilterStatus(id);
                setSelectedFinding(null);
              }}
            />
          </div>
        </div>

        <div className="wb-context-section">
          <div className="wb-section-label">Result count</div>
          <KeyValue
            items={[
              { key: 'Matched', value: filteredFindings.length },
              { key: 'Total', value: findings.length },
              { key: 'Source', value: isDemoMode ? 'DEMO fixture' : 'Backend API' },
            ]}
          />
        </div>
      </ContextSidebar>

      <div className="wb-page-main">
        <PageHeader
          title="Findings & Risks"
          description="Evidence-first review of recorded findings. Empty is not the same as PASS."
          isDemoMode={isDemoMode}
          meta={
            <>
              <span>
                Assessment: <strong>{assessmentId || 'No assessment'}</strong>
              </span>
              <span>
                Findings: <strong>{findings.length}</strong>
              </span>
            </>
          }
        />

        <div className="wb-page-body wb-split-h">
          <div className="wb-panel">
            <div className="wb-panel-header">
              <div className="wb-panel-title">
                <AlertTriangle size={14} color="var(--sev-high-text)" />
                <span>Recorded findings</span>
                <span className="wb-panel-count">{filteredFindings.length}</span>
                {isDemoMode && <DemoBadge />}
              </div>
              <button
                type="button"
                onClick={loadFindings}
                className="wb-btn wb-btn-sm"
                title="Refetch findings from the backend"
              >
                <RefreshCw size={10} /> Refresh
              </button>
            </div>

            <div className="wb-toolbar">
              <div className="wb-toolbar-group" style={{ flex: 1 }}>
                <Search size={12} color="var(--text-muted)" />
                <label className="wb-sr-only" htmlFor="findings-search">
                  Search findings
                </label>
                <input
                  id="findings-search"
                  type="text"
                  className="wb-input"
                  placeholder="Search ID, title, rule, asset, CWE, CVE…"
                  value={searchQuery}
                  onChange={(event) => {
                    setSearchQuery(event.target.value);
                    setSelectedFinding(null);
                  }}
                  style={{ width: '100%', maxWidth: '320px' }}
                />
              </div>
              <span className="wb-toolbar-hint">
                {isDemoMode ? 'DEMO fixture' : 'GET /findings?assessmentId=…'}
              </span>
            </div>

            <div className="wb-panel-body">
              <DataTable
                columns={columns}
                data={filteredFindings}
                keyExtractor={(row) => row.id}
                selectedId={selectedFinding?.id}
                onSelectRow={(row) => setSelectedFinding(row)}
                emptyMessage={
                  findings.length === 0
                    ? 'No vulnerability findings recorded for this assessment.'
                    : 'No findings match the current filters. Empty is not PASS.'
                }
              />
            </div>
          </div>

          <DetailPanel
            title={selectedFinding ? `Finding: ${selectedFinding.id}` : 'Finding inspector'}
            tabs={detailTabs}
            actions={isDemoMode ? <DemoBadge /> : undefined}
          />
        </div>
      </div>
    </div>
  );
};
