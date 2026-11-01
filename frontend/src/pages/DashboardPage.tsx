import React, { useState, useEffect } from 'react';
import {
  PlayCircle,
  AlertTriangle,
  FileText,
  Target,
  RefreshCw,
  ExternalLink,
} from 'lucide-react';
import {
  api,
  Finding,
  CheckExecutionRecord,
  SecurityRuleMetadata,
  ScopeItem,
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
import { ActiveTab } from '@/components/AppShell';

interface DashboardPageProps {
  isDemoMode: boolean;
  onNavigateTab: (tab: ActiveTab) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  isDemoMode,
  onNavigateTab,
}) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [rules, setRules] = useState<SecurityRuleMetadata[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [executions, setExecutions] = useState<CheckExecutionRecord[]>([]);
  const [scopeItems, setScopeItems] = useState<ScopeItem[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);

    if (isDemoMode) {
      // Load strictly from demo fixtures
      setRules(DEMO_RULES);
      setFindings(DEMO_FINDINGS);
      setExecutions(DEMO_CHECK_EXECUTIONS);
      setScopeItems(DEMO_SCOPE_ITEMS);
      setSelectedFinding(DEMO_FINDINGS[0] || null);
      setLoading(false);
      return;
    }

    try {
      // In Live Mode: strictly call real backend APIs
      const [rulesRes, findingsRes, execsRes, scopeRes] = await Promise.all([
        api.getRules().catch(() => []),
        api.getFindings().catch(() => []),
        api.getExecutions().catch(() => []),
        api.getScopeItems().catch(() => []),
      ]);

      setRules(rulesRes);
      setFindings(findingsRes);
      setExecutions(execsRes);
      setScopeItems(scopeRes);
      setSelectedFinding(findingsRes.length > 0 ? findingsRes[0] : null);
    } catch (err: any) {
      setError(err?.message || 'Failed to fetch operational data from backend');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [isDemoMode]);

  // If loading in live mode
  if (loading && !isDemoMode) {
    return <StatePanel kind="loading" title="Connecting to Workbench API..." />;
  }

  // If live mode failed
  if (error && !isDemoMode) {
    return (
      <StatePanel
        kind="offline"
        title="Workbench Backend Offline"
        description="Could not load dashboard telemetry from local API. Ensure the backend is running at http://127.0.0.1:8000."
        errorMessage={error}
        onRetry={loadData}
      />
    );
  }

  // Issue Activity Columns (Burp Suite Style)
  const findingColumns: DataTableColumn<Finding>[] = [
    {
      key: 'severity',
      label: 'Severity',
      width: '100px',
      render: (row) => <SeverityBadge severity={row.severity} size="sm" />,
    },
    {
      key: 'title',
      label: 'Issue Type / Title',
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
      width: '110px',
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

  // Event Log Columns (Recent executions)
  const executionColumns: DataTableColumn<CheckExecutionRecord>[] = [
    {
      key: 'executedAt',
      label: 'Time',
      width: '120px',
      render: (row) => (
        <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          {new Date(row.executedAt).toLocaleTimeString()}
        </span>
      ),
    },
    {
      key: 'id',
      label: 'Execution ID',
      width: '110px',
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
      label: 'Scope Guard',
      width: '95px',
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
      width: '100px',
      render: (row) => <StatusBadge status={row.status} size="sm" />,
    },
  ];

  // Advisory tabs for selected finding
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
                <div style={{ display: 'flex', gap: '10px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                  <span>Severity: <strong style={{ color: 'var(--text-primary)' }}>{selectedFinding.severity.toUpperCase()}</strong></span>
                  <span>Confidence: <strong style={{ color: 'var(--text-primary)' }}>{selectedFinding.confidence.toUpperCase()}</strong></span>
                  {selectedFinding.cwe && <span>CWE: <code style={{ color: 'var(--accent)' }}>{selectedFinding.cwe}</code></span>}
                </div>
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
                  Issue Detail & Context
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-primary)', lineHeight: 1.5 }}>
                  {selectedFinding.description || 'No detailed description provided.'}
                </div>
              </div>

              {selectedFinding.impact && (
                <div>
                  <div
                    style={{
                      fontSize: '10px',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      color: 'var(--sev-high-text)',
                      marginBottom: '4px',
                    }}
                  >
                    Technical Impact
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-primary)', lineHeight: 1.5 }}>
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
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div
                style={{
                  fontSize: '10px',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  color: 'var(--accent)',
                }}
              >
                Defensive Guidance
              </div>
              <pre
                style={{
                  fontSize: '11px',
                  fontFamily: 'inherit',
                  color: 'var(--text-primary)',
                  lineHeight: 1.6,
                  whiteSpace: 'pre-wrap',
                }}
              >
                {selectedFinding.recommendation || 'No remediation guidance recorded.'}
              </pre>
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
                { key: 'Assessment ID', value: selectedFinding.assessmentId },
                { key: 'Asset ID', value: selectedFinding.assetId },
                { key: 'Rule ID', value: selectedFinding.ruleId || '—' },
                { key: 'Classification', value: selectedFinding.cwe || 'None' },
                { key: 'Status', value: selectedFinding.status },
                {
                  key: 'Discovered At',
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
            <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Select an issue from Issue Activity to view defensive advisory details.
            </div>
          ),
        },
      ];

  const inScopeCount = scopeItems.filter((s) => s.inScope).length;
  const excludedCount = scopeItems.filter((s) => !s.inScope).length;
  const blockedExecCount = executions.filter((e) => e.scopeDecision === 'BLOCK').length;

  return (
    <div className="wb-quad-grid">
      {/* =========================================================================
          Quadrant 1 (Top Left): Tasks & Defensive Modules
          ========================================================================= */}
      <div className="wb-panel">
        <div className="wb-panel-header">
          <div className="wb-panel-title">
            <PlayCircle size={14} color="var(--accent)" />
            <span>Defensive Security Modules & Scope Guard</span>
            {isDemoMode && <DemoBadge />}
          </div>
          <div style={{ display: 'flex', gap: '6px' }}>
            <button
              onClick={() => onNavigateTab('executions')}
              className="wb-btn wb-btn-primary wb-btn-sm"
              title="Launch check execution wizard"
            >
              <PlayCircle size={12} />
              Execute Check
            </button>
            <button
              onClick={() => onNavigateTab('scope')}
              className="wb-btn wb-btn-sm"
              title="Configure authorized target scope"
            >
              <Target size={12} />
              Scope
            </button>
          </div>
        </div>

        <div className="wb-toolbar">
          <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
            Modules: <strong style={{ color: 'var(--text-primary)' }}>{rules.length} Active</strong>
          </span>
          <span style={{ color: 'var(--border-strong)' }}>|</span>
          <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
            Scope Rules: <strong style={{ color: 'var(--status-pass-text)' }}>{inScopeCount} In-Scope</strong> /{' '}
            <strong style={{ color: 'var(--status-blocked-text)' }}>{excludedCount} Excluded</strong>
          </span>
          <span style={{ color: 'var(--border-strong)' }}>|</span>
          <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
            Blocks: <strong style={{ color: 'var(--status-blocked-text)' }}>{blockedExecCount} Prevented</strong>
          </span>
        </div>

        <div className="wb-panel-body">
          <div style={{ padding: '8px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {rules.map((rule) => (
              <div
                key={rule.ruleId}
                onClick={() => onNavigateTab('executions')}
                style={{
                  padding: '7px 10px',
                  background: 'var(--bg-table-zebra)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '3px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '8px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                  <code style={{ color: 'var(--accent)', fontWeight: 700, fontSize: '11px' }}>
                    {rule.ruleId}
                  </code>
                  <span
                    style={{
                      fontSize: '11px',
                      color: 'var(--text-primary)',
                      fontWeight: 600,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {rule.title}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexShrink: 0 }}>
                  <span
                    style={{
                      fontSize: '10px',
                      color: 'var(--text-muted)',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    {rule.cwe}
                  </span>
                  <span className="wb-chip" style={{ background: 'var(--bg-surface-elevated)' }}>
                    {rule.category}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* =========================================================================
          Quadrant 2 (Top Right): Issue Activity (Findings Table)
          ========================================================================= */}
      <div className="wb-panel">
        <div className="wb-panel-header">
          <div className="wb-panel-title">
            <AlertTriangle size={14} color="var(--sev-high-text)" />
            <span>Issue Activity</span>
            <span className="wb-panel-count">{findings.length}</span>
            {isDemoMode && <DemoBadge />}
          </div>
          <button
            onClick={() => onNavigateTab('findings')}
            className="wb-btn wb-btn-sm"
            title="Open comprehensive findings & evidence review"
          >
            <span>View All</span>
            <ExternalLink size={10} />
          </button>
        </div>

        <div className="wb-panel-body">
          <DataTable
            columns={findingColumns}
            data={findings}
            keyExtractor={(row) => row.id}
            selectedId={selectedFinding?.id}
            onSelectRow={(row) => setSelectedFinding(row)}
            emptyMessage="No vulnerability findings recorded. Run defensive checks against authorized targets."
          />
        </div>
      </div>

      {/* =========================================================================
          Quadrant 3 (Bottom Left): Event Log & Audit Trail
          ========================================================================= */}
      <div className="wb-panel">
        <div className="wb-panel-header">
          <div className="wb-panel-title">
            <FileText size={14} color="var(--text-secondary)" />
            <span>Event Log / Execution Trail</span>
            <span className="wb-panel-count">{executions.length}</span>
            {isDemoMode && <DemoBadge />}
          </div>
          <button
            onClick={loadData}
            className="wb-btn wb-btn-sm"
            title="Refresh event log from backend"
          >
            <RefreshCw size={10} />
            Refresh
          </button>
        </div>

        <div className="wb-panel-body">
          <DataTable
            columns={executionColumns}
            data={executions}
            keyExtractor={(row) => row.id}
            emptyMessage="No execution events logged in current session. Execute a check from the top-left panel."
          />
        </div>
      </div>

      {/* =========================================================================
          Quadrant 4 (Bottom Right): Advisory / Detail Inspector
          ========================================================================= */}
      <div style={{ height: '100%', overflow: 'hidden' }}>
        <DetailPanel
          title={
            selectedFinding
              ? `Advisory Inspector: ${selectedFinding.id}`
              : 'Advisory Inspector'
          }
          tabs={inspectorTabs}
          actions={
            selectedFinding && (
              <button
                onClick={() => onNavigateTab('findings')}
                className="wb-btn wb-btn-sm"
              >
                <span>Full Evidence</span>
                <ExternalLink size={10} />
              </button>
            )
          }
        />
      </div>
    </div>
  );
};
