import React, { useCallback, useEffect, useState } from 'react';
import {
  PlayCircle,
  AlertTriangle,
  FileText,
  Target,
  RefreshCw,
  ExternalLink,
  ShieldCheck,
  Database,
} from 'lucide-react';
import {
  api,
  Finding,
  CheckExecutionRecord,
  SecurityRuleMetadata,
  ScopeItem,
  Assessment,
  Engagement,
} from '@/services/api';
import {
  DEMO_FINDINGS,
  DEMO_CHECK_EXECUTIONS,
  DEMO_RULES,
  DEMO_SCOPE_ITEMS,
} from '@/demo/fixtures';
import { DataTable, DataTableColumn } from '@/components/DataTable';
import { SeverityBadge } from '@/components/SeverityBadge';
import { StatusBadge } from '@/components/StatusBadge';
import { StatePanel } from '@/components/StatePanel';
import { DemoBadge } from '@/components/DemoBadge';
import { DetailPanel, DetailTab } from '@/components/DetailPanel';
import { KeyValue } from '@/components/KeyValue';
import { PageHeader } from '@/components/PageHeader';
import { ContextSidebar } from '@/components/ContextSidebar';
import { ActiveTab } from '@/components/AppShell';
import { BackendConnectionState } from '@/components/ConnectionStatus';

interface DashboardPageProps {
  isDemoMode: boolean;
  assessmentId: string | null;
  engagementId: string | null;
  engagement: Engagement | null;
  assessment: Assessment | null;
  connectionState: BackendConnectionState;
  contextLoading?: boolean;
  refreshToken?: number;
  onNavigateTab: (tab: ActiveTab) => void;
}

interface AreaErrors {
  rules?: string;
  findings?: string;
  executions?: string;
  scope?: string;
}

function isExpired(expiresAt?: string): boolean {
  if (!expiresAt) return false;
  const timestamp = Date.parse(expiresAt);
  return Number.isFinite(timestamp) && timestamp <= Date.now();
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  isDemoMode,
  assessmentId,
  engagementId,
  engagement,
  assessment,
  connectionState,
  contextLoading = false,
  refreshToken = 0,
  onNavigateTab,
}) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [fatalError, setFatalError] = useState<string | null>(null);
  const [areaErrors, setAreaErrors] = useState<AreaErrors>({});

  const [rules, setRules] = useState<SecurityRuleMetadata[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [executions, setExecutions] = useState<CheckExecutionRecord[]>([]);
  const [scopeItems, setScopeItems] = useState<ScopeItem[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const isOffline =
    connectionState === 'offline' || connectionState === 'api_error';

  const loadData = useCallback(async () => {
    setLoading(true);
    setFatalError(null);
    setAreaErrors({});
    setRules([]);
    setFindings([]);
    setExecutions([]);
    setScopeItems([]);
    setSelectedFinding(null);

    if (isDemoMode) {
      setRules(DEMO_RULES);
      setFindings(DEMO_FINDINGS);
      setExecutions(DEMO_CHECK_EXECUTIONS);
      setScopeItems(DEMO_SCOPE_ITEMS);
      setSelectedFinding(DEMO_FINDINGS[0] || null);
      setLoading(false);
      return;
    }

    if (!assessmentId || !engagementId) {
      setLoading(false);
      return;
    }

    const results = await Promise.allSettled([
      api.getRules(),
      api.getFindings(assessmentId),
      api.getExecutions(assessmentId),
      api.getScopeItems(engagementId),
    ]);

    const nextErrors: AreaErrors = {};
    const [rulesResult, findingsResult, executionsResult, scopeResult] = results;

    if (rulesResult.status === 'fulfilled') {
      setRules(rulesResult.value);
    } else {
      nextErrors.rules =
        rulesResult.reason?.message || 'Rule catalog request failed.';
    }

    if (findingsResult.status === 'fulfilled') {
      setFindings(findingsResult.value);
      setSelectedFinding(findingsResult.value[0] || null);
    } else {
      nextErrors.findings =
        findingsResult.reason?.message || 'Findings request failed.';
    }

    if (executionsResult.status === 'fulfilled') {
      setExecutions(executionsResult.value);
    } else {
      nextErrors.executions =
        executionsResult.reason?.message || 'Executions request failed.';
    }

    if (scopeResult.status === 'fulfilled') {
      setScopeItems(scopeResult.value);
    } else {
      nextErrors.scope =
        scopeResult.reason?.message || 'Scope request failed.';
    }

    setAreaErrors(nextErrors);
    if (Object.keys(nextErrors).length === results.length) {
      setFatalError('All dashboard API requests failed. No data is being shown.');
    }
    setLoading(false);
  }, [assessmentId, engagementId, isDemoMode]);

  useEffect(() => {
    loadData();
  }, [loadData, refreshToken]);

  const findingColumns: DataTableColumn<Finding>[] = [
    {
      key: 'severity',
      label: 'Severity',
      width: '100px',
      render: (row) => <SeverityBadge severity={row.severity} size="sm" />,
    },
    {
      key: 'title',
      label: 'Issue type / title',
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
      width: '115px',
      render: (row) => <StatusBadge status={row.status} size="sm" />,
    },
    {
      key: 'assetId',
      label: 'Asset',
      width: '100px',
      render: (row) => <span className="wb-mono-muted">{row.assetId}</span>,
    },
  ];

  const executionColumns: DataTableColumn<CheckExecutionRecord>[] = [
    {
      key: 'executedAt',
      label: 'Time',
      width: '115px',
      render: (row) => (
        <span className="wb-mono-muted">
          {new Date(row.executedAt).toLocaleTimeString()}
        </span>
      ),
    },
    {
      key: 'id',
      label: 'Execution ID',
      width: '115px',
      render: (row) => (
        <code style={{ color: 'var(--text-primary)' }}>{row.id}</code>
      ),
    },
    {
      key: 'ruleId',
      label: 'Module',
      width: '110px',
      render: (row) => (
        <code style={{ color: 'var(--accent)' }}>{row.ruleId}</code>
      ),
    },
    {
      key: 'target',
      label: 'Target',
      render: (row) => (
        <span style={{ fontFamily: 'var(--font-mono)' }}>{row.target}</span>
      ),
    },
    {
      key: 'scopeDecision',
      label: 'Scope',
      width: '85px',
      render: (row) => (
        <span
          className="wb-chip"
          style={{
            background:
              row.scopeDecision === 'ALLOW'
                ? 'var(--status-pass-bg)'
                : 'var(--status-blocked-bg)',
            color:
              row.scopeDecision === 'ALLOW'
                ? 'var(--status-pass-text)'
                : 'var(--status-blocked-text)',
            border: `1px solid ${
              row.scopeDecision === 'ALLOW'
                ? 'var(--status-pass-border)'
                : 'var(--status-blocked-border)'
            }`,
          }}
        >
          {row.scopeDecision}
        </span>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      width: '145px',
      render: (row) => <StatusBadge status={row.status} size="sm" />,
    },
  ];

  const inspectorTabs: DetailTab[] = selectedFinding
    ? [
        {
          id: 'advisory',
          label: 'Advisory',
          content: (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div>
                <h3
                  style={{
                    fontSize: '13px',
                    fontWeight: 700,
                    color: 'var(--text-primary)',
                    marginBottom: '4px',
                  }}
                >
                  {selectedFinding.title}
                </h3>
                <div className="wb-page-meta">
                  <span>Severity: <strong>{selectedFinding.severity.toUpperCase()}</strong></span>
                  <span>Confidence: <strong>{selectedFinding.confidence.toUpperCase()}</strong></span>
                  {selectedFinding.cwe && (
                    <span>CWE: <code style={{ color: 'var(--accent)' }}>{selectedFinding.cwe}</code></span>
                  )}
                </div>
              </div>
              <div>
                <div className="wb-section-label">Description</div>
                <div className="wb-detail-text">
                  {selectedFinding.description || 'No detailed description provided.'}
                </div>
              </div>
              {selectedFinding.impact && (
                <div>
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
          id: 'metadata',
          label: 'Metadata',
          content: (
            <KeyValue
              items={[
                { key: 'Finding ID', value: selectedFinding.id },
                { key: 'Assessment', value: selectedFinding.assessmentId },
                { key: 'Asset ID', value: selectedFinding.assetId },
                { key: 'Rule', value: selectedFinding.ruleId || '—' },
                { key: 'Status', value: selectedFinding.status },
                { key: 'Source', value: isDemoMode ? 'DEMO fixture' : 'Backend API' },
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
          label: 'Advisory',
          content: (
            <div className="wb-no-selection">
              Select an issue from Issue Activity to view its advisory.
            </div>
          ),
        },
      ];

  const activeScopeCount = scopeItems.filter(
    (item) => item.inScope && !isExpired(item.expiresAt),
  ).length;

  const areaState = (
    areaError: string | undefined,
    content: React.ReactNode,
  ) => {
    if (areaError) {
      return (
        <StatePanel
          kind={isOffline ? 'offline' : 'error'}
          title={isOffline ? 'Backend unreachable' : 'API request failed'}
          description="This area shows no data because its request failed."
          errorMessage={areaError}
          onRetry={loadData}
        />
      );
    }
    return content;
  };

  if (contextLoading && !isDemoMode) {
    return <StatePanel kind="loading" title="Loading workspace context…" />;
  }

  if (!assessmentId && !isDemoMode) {
    return (
      <StatePanel
        kind="empty"
        title="No assessment available"
        description="The dashboard needs an active assessment from the backend. Create or select one to continue."
      />
    );
  }

  if (loading) {
    return <StatePanel kind="loading" title="Loading dashboard telemetry…" />;
  }

  if (fatalError) {
    return (
      <StatePanel
        kind={isOffline ? 'offline' : 'error'}
        title={isOffline ? 'Dashboard backend unreachable' : 'Dashboard request failed'}
        description="No dashboard data is shown because the backend requests did not succeed."
        errorMessage={fatalError}
        onRetry={loadData}
      />
    );
  }

  return (
    <div className="wb-page-layout">
      <ContextSidebar
        title="Assessment context"
        footer={
          <span>
            Session data is in-memory and resets when the backend restarts.
          </span>
        }
      >
        <div className="wb-context-section">
          <div className="wb-section-label">Workspace</div>
          <KeyValue
            items={[
              { key: 'Engagement', value: engagement?.name || 'No engagement' },
              { key: 'Assessment', value: assessment?.name || 'No assessment' },
              { key: 'Assessor', value: engagement?.assessor || '—' },
              { key: 'Status', value: assessment?.status || '—' },
              { key: 'Source', value: isDemoMode ? 'DEMO fixture' : 'Backend API' },
            ]}
          />
        </div>

        <div className="wb-context-section">
          <div className="wb-section-label">Workflow</div>
          <ol className="wb-workflow-list">
            <li>Engagement</li>
            <li>Scope</li>
            <li>Assessment</li>
            <li>Check</li>
            <li>Finding</li>
            <li>Evidence</li>
            <li>Report</li>
          </ol>
        </div>

        <div className="wb-context-section">
          <div className="wb-section-label">Session note</div>
          <div className="wb-context-note wb-context-note-row">
            <Database size={12} />
            <span>In-memory only. Do not treat as permanent storage.</span>
          </div>
        </div>
      </ContextSidebar>

      <div className="wb-page-main">
        <PageHeader
          title="Dashboard"
          description="Assessment context and defensive workbench entry points, backed by the local API."
          isDemoMode={isDemoMode}
          meta={
            <>
              <span>
                Assessment: <strong>{assessmentId || 'No assessment'}</strong>
              </span>
              <span>{assessment?.name || 'No assessment name'}</span>
              <span>{engagement?.name || 'No engagement'}</span>
            </>
          }
          actions={
            <>
              <button
                type="button"
                onClick={() => onNavigateTab('scope')}
                className="wb-btn wb-btn-sm"
              >
                <Target size={12} /> Review scope
              </button>
              <button
                type="button"
                onClick={() => onNavigateTab('executions')}
                className="wb-btn wb-btn-primary wb-btn-sm"
              >
                <PlayCircle size={12} /> Run check
              </button>
            </>
          }
        />

        <div className="wb-page-body wb-dashboard-body">
          <div className="wb-metric-strip">
            {[
              {
                label: 'Scope rules (active)',
                value: areaErrors.scope ? '—' : activeScopeCount,
                area: 'scope',
              },
              {
                label: 'Findings',
                value: areaErrors.findings ? '—' : findings.length,
                area: 'findings',
              },
              {
                label: 'Session executions',
                value: areaErrors.executions ? '—' : executions.length,
                area: 'executions',
              },
              {
                label: 'Rules available',
                value: areaErrors.rules ? '—' : rules.length,
                area: 'rules',
              },
            ].map((metric) => (
              <div key={metric.label} className="wb-metric">
                <span className="wb-metric-label">{metric.label}</span>
                <span className="wb-metric-value">{metric.value}</span>
                <span className="wb-metric-source">
                  {isDemoMode ? 'DEMO' : areaErrors[metric.area as keyof AreaErrors] ? 'ERROR' : 'API'}
                </span>
              </div>
            ))}
            <div className="wb-metric-note">
              <ShieldCheck size={12} />
              Metrics are counts from the current source only.
            </div>
          </div>

          <div className="wb-quad-grid">
            <div className="wb-panel">
              <div className="wb-panel-header">
                <div className="wb-panel-title">
                  <PlayCircle size={14} color="var(--accent)" />
                  <span>Defensive modules</span>
                  <span className="wb-panel-count">{rules.length}</span>
                  {isDemoMode && <DemoBadge />}
                </div>
                <span className="wb-toolbar-hint">GET /executions/rules</span>
              </div>
              <div className="wb-panel-body">
                {areaState(
                  areaErrors.rules,
                  rules.length === 0 ? (
                    <StatePanel
                      kind="empty"
                      title="No rules returned"
                      description="The backend did not return any defensive security rules."
                    />
                  ) : (
                    <div className="wb-rule-list">
                      {rules.map((rule) => (
                        <button
                          key={rule.ruleId}
                          type="button"
                          className="wb-rule-row"
                          onClick={() => onNavigateTab('executions')}
                          title={`Open Check Executions for ${rule.ruleId}`}
                        >
                          <code className="wb-rule-id">{rule.ruleId}</code>
                          <span className="wb-rule-title">{rule.title}</span>
                          <span className="wb-rule-meta">{rule.category}</span>
                          <code className="wb-rule-cwe">{rule.cwe}</code>
                        </button>
                      ))}
                    </div>
                  ),
                )}
              </div>
            </div>

            <div className="wb-panel">
              <div className="wb-panel-header">
                <div className="wb-panel-title">
                  <AlertTriangle size={14} color="var(--sev-high-text)" />
                  <span>Issue activity</span>
                  <span className="wb-panel-count">{findings.length}</span>
                  {isDemoMode && <DemoBadge />}
                </div>
                <button
                  type="button"
                  onClick={() => onNavigateTab('findings')}
                  className="wb-btn wb-btn-sm"
                >
                  <span>View all</span>
                  <ExternalLink size={10} />
                </button>
              </div>
              <div className="wb-panel-body">
                {areaState(
                  areaErrors.findings,
                  <DataTable
                    columns={findingColumns}
                    data={findings}
                    keyExtractor={(row) => row.id}
                    selectedId={selectedFinding?.id}
                    onSelectRow={(row) => setSelectedFinding(row)}
                    emptyMessage="No vulnerability findings recorded for this assessment."
                  />,
                )}
              </div>
            </div>

            <div className="wb-panel">
              <div className="wb-panel-header">
                <div className="wb-panel-title">
                  <FileText size={14} color="var(--text-secondary)" />
                  <span>Recent executions</span>
                  <span className="wb-panel-count">{executions.length}</span>
                  {isDemoMode && <DemoBadge />}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span className="wb-toolbar-hint">Session only</span>
                  <button
                    type="button"
                    onClick={loadData}
                    className="wb-btn wb-btn-sm"
                    title="Refresh dashboard data"
                  >
                    <RefreshCw size={10} /> Refresh
                  </button>
                </div>
              </div>
              <div className="wb-panel-body">
                {areaState(
                  areaErrors.executions,
                  <DataTable
                    columns={executionColumns}
                    data={executions}
                    keyExtractor={(row) => row.id}
                    emptyMessage="No execution records in this backend session."
                  />,
                )}
              </div>
            </div>

            <div className="wb-panel" style={{ overflow: 'hidden' }}>
              <DetailPanel
                title={
                  selectedFinding
                    ? `Advisory: ${selectedFinding.id}`
                    : 'Advisory inspector'
                }
                tabs={inspectorTabs}
                actions={
                  selectedFinding ? (
                    <button
                      type="button"
                      onClick={() => onNavigateTab('findings')}
                      className="wb-btn wb-btn-sm"
                    >
                      <span>Full evidence</span>
                      <ExternalLink size={10} />
                    </button>
                  ) : isDemoMode ? (
                    <DemoBadge />
                  ) : undefined
                }
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
