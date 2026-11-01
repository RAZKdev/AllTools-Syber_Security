import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  PlayCircle,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  Terminal,
  Info,
} from 'lucide-react';
import {
  api,
  CheckExecutionRecord,
  SecurityRuleMetadata,
  RunCheckResponse,
} from '@/services/api';
import { DEMO_CHECK_EXECUTIONS, DEMO_RULES } from '@/demo/fixtures';
import { DataTable, DataTableColumn } from '@/components/DataTable';
import { StatusBadge } from '@/components/StatusBadge';
import { SeverityBadge } from '@/components/SeverityBadge';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { StatePanel } from '@/components/StatePanel';
import { DemoBadge } from '@/components/DemoBadge';
import { KeyValue } from '@/components/KeyValue';
import { FilterTabs } from '@/components/FilterTabs';
import { PageHeader } from '@/components/PageHeader';
import { ContextSidebar } from '@/components/ContextSidebar';
import { BackendConnectionState } from '@/components/ConnectionStatus';

interface ExecutionsPageProps {
  isDemoMode: boolean;
  assessmentId: string | null;
  connectionState: BackendConnectionState;
  contextLoading?: boolean;
  refreshToken?: number;
  onExecutionsChanged?: () => void;
}

const OFFLINE_ANALYSIS_RULES = new Set(['SEC-AUTH-001', 'SEC-CRYPTO-001']);

export const ExecutionsPage: React.FC<ExecutionsPageProps> = ({
  isDemoMode,
  assessmentId,
  connectionState,
  contextLoading = false,
  refreshToken = 0,
  onExecutionsChanged,
}) => {
  const [rules, setRules] = useState<SecurityRuleMetadata[]>([]);
  const [executions, setExecutions] = useState<CheckExecutionRecord[]>([]);
  const [selectedExec, setSelectedExec] = useState<CheckExecutionRecord | null>(
    null,
  );
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('all');

  // Execution form
  const [ruleId, setRuleId] = useState<string>('');
  const [target, setTarget] = useState<string>('');
  const [running, setRunning] = useState<boolean>(false);
  const [lastResult, setLastResult] = useState<RunCheckResponse | null>(null);
  const [resultAt, setResultAt] = useState<Date | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const [showConfirmModal, setShowConfirmModal] = useState<boolean>(false);

  const isOffline =
    connectionState === 'offline' || connectionState === 'api_error';
  const runDisabledReason = isDemoMode
    ? 'Check execution is disabled in Demo Mode. No request is sent to any target.'
    : isOffline
      ? 'Check execution is disabled while the backend is offline or has an API error.'
      : !assessmentId
        ? 'Select an assessment before running a check.'
        : '';

  const fetchExecutions = useCallback(
    async (showLoading = true) => {
      if (showLoading) setLoading(true);
      setError(null);

      if (isDemoMode) {
        setRules(DEMO_RULES);
        setExecutions(DEMO_CHECK_EXECUTIONS);
        setSelectedExec(DEMO_CHECK_EXECUTIONS[0] || null);
        setLoading(false);
        return;
      }

      try {
        const [ruleList, executionList] = await Promise.all([
          api.getRules(),
          assessmentId ? api.getExecutions(assessmentId) : Promise.resolve([]),
        ]);
        setRules(ruleList);
        setExecutions(executionList);
        setSelectedExec(executionList[0] || null);
      } catch (err: any) {
        setRules([]);
        setExecutions([]);
        setSelectedExec(null);
        setError(
          err?.message || 'Failed to load execution data from the backend.',
        );
      } finally {
        setLoading(false);
      }
    },
    [assessmentId, isDemoMode],
  );

  useEffect(() => {
    setLastResult(null);
    setResultAt(null);
    setRunError(null);
    setTarget('');
    fetchExecutions();
  }, [fetchExecutions, refreshToken]);

  useEffect(() => {
    if (rules.length === 0) {
      setRuleId('');
      return;
    }
    setRuleId((current) =>
      rules.some((rule) => rule.ruleId === current)
        ? current
        : rules[0].ruleId,
    );
  }, [rules]);

  const selectedRuleMeta = rules.find((rule) => rule.ruleId === ruleId);

  const groupedRules = useMemo(() => {
    const grouped: Record<string, SecurityRuleMetadata[]> = {};
    for (const rule of rules) {
      if (!grouped[rule.category]) grouped[rule.category] = [];
      grouped[rule.category].push(rule);
    }
    return grouped;
  }, [rules]);

  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const execution of executions) {
      counts[execution.status] = (counts[execution.status] || 0) + 1;
    }
    return counts;
  }, [executions]);

  const filteredExecutions =
    statusFilter === 'all'
      ? executions
      : executions.filter((execution) => execution.status === statusFilter);

  const getTargetPlaceholder = () => {
    if (ruleId === 'SEC-CRYPTO-001') {
      return 'e.g. 5d41402abc4b2a76b9719d911017c592 or a SHA-256 string';
    }
    if (ruleId === 'SEC-AUTH-001') return 'e.g. a password sample to analyze locally';
    if (ruleId === 'SEC-NET-001') return 'e.g. 192.168.1.50 or app.lab.local';
    return 'e.g. app.lab.local, lab.local, 192.168.1.100';
  };

  const handleOpenConfirm = (event: React.FormEvent) => {
    event.preventDefault();
    if (!target.trim() || runDisabledReason || !assessmentId) return;
    setShowConfirmModal(true);
  };

  const handleExecuteCheck = async () => {
    setShowConfirmModal(false);
    if (!target.trim() || !assessmentId || isDemoMode || isOffline) return;

    setRunning(true);
    setRunError(null);
    setLastResult(null);
    setResultAt(null);

    try {
      const response = await api.runCheck(assessmentId, ruleId, target.trim());
      setLastResult(response);
      setResultAt(new Date());
      // Refetch the audit trail instead of prepending a local record.
      await fetchExecutions(false);
      onExecutionsChanged?.();
    } catch (err: any) {
      setLastResult(null);
      setRunError(
        err?.message ||
          'The execution request failed. No result was produced by the backend.',
      );
    } finally {
      setRunning(false);
    }
  };

  const columns: DataTableColumn<CheckExecutionRecord>[] = [
    {
      key: 'executedAt',
      label: 'Executed',
      width: '125px',
      render: (row) => (
        <span className="wb-mono-muted">
          {new Date(row.executedAt).toLocaleTimeString()}
        </span>
      ),
    },
    {
      key: 'id',
      label: 'Execution ID',
      width: '125px',
      render: (row) => (
        <code style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{row.id}</code>
      ),
    },
    {
      key: 'ruleId',
      label: 'Rule',
      width: '115px',
      render: (row) => (
        <code style={{ color: 'var(--accent)', fontWeight: 600 }}>{row.ruleId}</code>
      ),
    },
    {
      key: 'target',
      label: 'Target',
      render: (row) => (
        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
          {row.target}
        </span>
      ),
    },
    {
      key: 'scopeDecision',
      label: 'Scope',
      width: '90px',
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
      width: '150px',
      render: (row) => <StatusBadge status={row.status} size="sm" />,
    },
    {
      key: 'durationMs',
      label: 'Duration',
      width: '85px',
      render: (row) => (
        <span className="wb-mono-muted">
          {row.durationMs !== undefined ? `${row.durationMs}ms` : '—'}
        </span>
      ),
    },
  ];

  if (contextLoading && !isDemoMode) {
    return <StatePanel kind="loading" title="Loading workspace context…" />;
  }

  if (loading) {
    return <StatePanel kind="loading" title="Loading execution data…" />;
  }

  if (error) {
    return (
      <StatePanel
        kind={isOffline ? 'offline' : 'error'}
        title={isOffline ? 'Execution backend unreachable' : 'Execution request failed'}
        description="No execution data is shown because the backend request did not succeed."
        errorMessage={error}
        onRetry={() => fetchExecutions()}
      />
    );
  }

  return (
    <div className="wb-page-layout">
      <ContextSidebar
        title="Check Executions"
        footer={
          <span>
            Execution records are in-memory session data and reset when the
            backend restarts.
          </span>
        }
      >
        <div className="wb-context-section">
          <div className="wb-section-label">Assessment context</div>
          <KeyValue
            items={[
              { key: 'Assessment', value: assessmentId || 'No assessment' },
              { key: 'Rules available', value: rules.length },
              { key: 'Session executions', value: executions.length },
              {
                key: 'Source',
                value: isDemoMode ? 'DEMO fixture' : 'Backend API',
              },
            ]}
          />
        </div>

        <div className="wb-context-section">
          <div className="wb-section-label">Rule categories</div>
          {Object.keys(groupedRules).length === 0 ? (
            <p className="wb-context-note">No rules returned by the backend.</p>
          ) : (
            <div className="wb-category-list">
              {Object.entries(groupedRules).map(([category, categoryRules]) => (
                <div key={category} className="wb-category-row">
                  <span>{category}</span>
                  <strong>{categoryRules.length}</strong>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="wb-context-section">
          <div className="wb-section-label">Execution status</div>
          <div className="wb-sidebar-filters">
            <FilterTabs
              options={[
                { id: 'all', label: 'All', count: executions.length },
                ...Object.entries(statusCounts).map(([status, count]) => ({
                  id: status,
                  label: status,
                  count,
                })),
              ]}
              activeId={statusFilter}
              onChange={setStatusFilter}
            />
          </div>
        </div>
      </ContextSidebar>

      <div className="wb-page-main">
        <PageHeader
          title="Check Executions"
          description="Run defensive checks with confirmation. The backend re-validates every target against Scope Guard."
          isDemoMode={isDemoMode}
          meta={
            <>
              <span>
                Assessment: <strong>{assessmentId || 'No assessment'}</strong>
              </span>
              <span>
                Rules: <strong>{rules.length}</strong>
              </span>
              <span>Mode: {isDemoMode ? 'DEMO fixture' : 'LIVE backend'}</span>
            </>
          }
        />

        <div className="wb-page-body wb-executions-workspace">
          <div className="wb-panel">
            <div className="wb-panel-header">
              <div className="wb-panel-title">
                <PlayCircle size={14} color="var(--accent)" />
                <span>Execution launcher</span>
                {isDemoMode && <DemoBadge />}
              </div>
              <span className="wb-toolbar-hint">
                Scope Guard → Collector → Normalizer → Rule → Observation →
                Finding → Evidence
              </span>
            </div>

            <div className="wb-panel-body wb-launcher-body">
              {isDemoMode && (
                <div className="wb-inline-note">
                  <Info size={12} />
                  Demo Mode: the launcher is disabled. Fixture records are shown
                  for visual exploration only; nothing is sent to a target.
                </div>
              )}

              <form className="wb-launcher-form" onSubmit={handleOpenConfirm}>
                <div>
                  <label className="wb-form-label" htmlFor="execution-rule">
                    Security rule module ({rules.length} available)
                  </label>
                  <select
                    id="execution-rule"
                    className="wb-select"
                    value={ruleId}
                    onChange={(event) => setRuleId(event.target.value)}
                    disabled={isDemoMode || rules.length === 0}
                    style={{ fontFamily: 'var(--font-mono)', width: '100%' }}
                  >
                    {Object.entries(groupedRules).map(([category, categoryRules]) => (
                      <optgroup key={category} label={category}>
                        {categoryRules.map((rule) => (
                          <option key={rule.ruleId} value={rule.ruleId}>
                            {rule.ruleId}: {rule.title}
                          </option>
                        ))}
                      </optgroup>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="wb-form-label" htmlFor="execution-target">
                    Target identifier / test sample
                  </label>
                  <input
                    id="execution-target"
                    type="text"
                    required
                    className="wb-input font-mono"
                    placeholder={getTargetPlaceholder()}
                    value={target}
                    onChange={(event) => setTarget(event.target.value)}
                    disabled={isDemoMode || !assessmentId}
                  />
                  {OFFLINE_ANALYSIS_RULES.has(ruleId) && (
                    <div className="wb-field-hint">
                      Local input analysis — no external network transmission.
                    </div>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={
                    isDemoMode ||
                    isOffline ||
                    !assessmentId ||
                    running ||
                    !target.trim()
                  }
                  className="wb-btn wb-btn-primary"
                  title={runDisabledReason || 'Review and run this check'}
                >
                  {running ? (
                    <>
                      <RefreshCw size={13} className="spin" /> Running…
                    </>
                  ) : (
                    <>
                      <PlayCircle size={14} /> Review &amp; Run
                    </>
                  )}
                </button>
              </form>

              {runDisabledReason && (
                <div className="wb-inline-note muted">{runDisabledReason}</div>
              )}

              {selectedRuleMeta && !isDemoMode && (
                <div className="wb-rule-hint">
                  <strong>{selectedRuleMeta.title}</strong>
                  <span>
                    Classification:{' '}
                    <code style={{ color: 'var(--accent)' }}>
                      {selectedRuleMeta.cwe}
                    </code>
                  </span>
                  <span>{selectedRuleMeta.description}</span>
                </div>
              )}

              {runError && (
                <div className="wb-alert error" role="alert">
                  <strong>Execution error — no result was produced.</strong>{' '}
                  {runError}
                </div>
              )}

              {lastResult && (
                <div
                  className="wb-result-banner"
                  style={{
                    backgroundColor: lastResult.allowed
                      ? lastResult.executionRecord.status === 'FAIL'
                        ? 'var(--status-fail-bg)'
                        : 'var(--status-pass-bg)'
                      : 'var(--status-blocked-bg)',
                    border: `1px solid ${
                      lastResult.allowed
                        ? lastResult.executionRecord.status === 'FAIL'
                          ? 'var(--status-fail-border)'
                          : 'var(--status-pass-border)'
                        : 'var(--status-blocked-border)'
                    }`,
                  }}
                  role="status"
                >
                  <div className="wb-result-head">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      {lastResult.allowed ? (
                        lastResult.executionRecord.status === 'FAIL' ? (
                          <AlertTriangle size={16} color="var(--status-fail-text)" />
                        ) : (
                          <ShieldCheck size={16} color="var(--status-pass-text)" />
                        )
                      ) : (
                        <ShieldAlert size={16} color="var(--status-blocked-text)" />
                      )}
                      <span className="wb-result-title">
                        {lastResult.allowed
                          ? `Backend result: ${lastResult.executionRecord.status}`
                          : 'Scope violation — blocked by backend'}
                      </span>
                    </div>
                    <StatusBadge status={lastResult.executionRecord.status} size="sm" />
                  </div>

                  <div className="wb-result-message">{lastResult.message}</div>

                  <KeyValue
                    items={[
                      { key: 'Execution ID', value: lastResult.executionRecord.id },
                      {
                        key: 'Scope decision',
                        value: lastResult.executionRecord.scopeDecision,
                      },
                      {
                        key: 'Duration',
                        value:
                          lastResult.executionRecord.durationMs !== undefined
                            ? `${lastResult.executionRecord.durationMs} ms`
                            : '—',
                      },
                      {
                        key: 'Received at',
                        value: resultAt ? resultAt.toLocaleString() : '—',
                      },
                    ]}
                  />

                  {lastResult.observation && (
                    <div className="wb-result-extra">
                      <div className="wb-section-label">Observation</div>
                      <div className="wb-detail-text">
                        {lastResult.observation.summary}
                      </div>
                    </div>
                  )}

                  {lastResult.finding && (
                    <div className="wb-result-extra">
                      <div className="wb-section-label">Finding</div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <SeverityBadge severity={lastResult.finding.severity} size="sm" />
                        <span className="wb-detail-text">{lastResult.finding.title}</span>
                        {lastResult.finding.cwe && (
                          <code style={{ fontSize: '10px', color: 'var(--accent)' }}>
                            {lastResult.finding.cwe}
                          </code>
                        )}
                      </div>
                    </div>
                  )}

                  {lastResult.evidence && (
                    <div className="wb-result-extra">
                      <div className="wb-section-label">Evidence</div>
                      <div className="wb-detail-text">
                        <code>{lastResult.evidence.id}</code> ·{' '}
                        {lastResult.evidence.type} · SHA-256{' '}
                        <code className="wb-break-all">
                          {lastResult.evidence.sha256}
                        </code>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          <div className="wb-split-h wb-executions-bottom">
            <div className="wb-panel">
              <div className="wb-panel-header">
                <div className="wb-panel-title">
                  <Terminal size={14} color="var(--text-secondary)" />
                  <span>Execution audit trail</span>
                  <span className="wb-panel-count">{filteredExecutions.length}</span>
                  {isDemoMode && <DemoBadge />}
                </div>
                <button
                  type="button"
                  onClick={() => fetchExecutions()}
                  className="wb-btn wb-btn-sm"
                  title="Refetch executions from the backend"
                >
                  <RefreshCw size={10} /> Refresh
                </button>
              </div>
              <div className="wb-panel-body">
                <DataTable
                  columns={columns}
                  data={filteredExecutions}
                  keyExtractor={(row) => row.id}
                  selectedId={selectedExec?.id}
                  onSelectRow={(row) => setSelectedExec(row)}
                  emptyMessage={
                    executions.length === 0
                      ? 'No checks have been recorded in this backend session.'
                      : 'No executions match the selected status filter.'
                  }
                />
              </div>
            </div>

            <div className="wb-panel">
              <div className="wb-panel-header">
                <div className="wb-panel-title">
                  <span>Execution details: {selectedExec?.id || 'None'}</span>
                  {isDemoMode && <DemoBadge />}
                </div>
              </div>
              <div className="wb-panel-body" style={{ padding: '12px' }}>
                {selectedExec ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    <KeyValue
                      items={[
                        { key: 'Execution ID', value: selectedExec.id },
                        { key: 'Assessment', value: selectedExec.assessmentId },
                        { key: 'Rule', value: selectedExec.ruleId },
                        { key: 'Target', value: selectedExec.target },
                        { key: 'Scope decision', value: selectedExec.scopeDecision },
                        {
                          key: 'Outcome',
                          value: <StatusBadge status={selectedExec.status} size="sm" />,
                        },
                        {
                          key: 'Duration',
                          value:
                            selectedExec.durationMs !== undefined
                              ? `${selectedExec.durationMs} ms`
                              : '—',
                        },
                        {
                          key: 'Executed (UTC)',
                          value: new Date(selectedExec.executedAt).toUTCString(),
                        },
                      ]}
                    />

                    {selectedExec.errorMessage && (
                      <div>
                        <div className="wb-section-label">Error / scope message</div>
                        <pre className="wb-error-pre">{selectedExec.errorMessage}</pre>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="wb-no-selection">
                    Select an execution record to inspect its backend telemetry.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      <ConfirmDialog
        isOpen={showConfirmModal}
        title="Confirm defensive security check execution"
        message={
          <div>
            <p style={{ marginBottom: '8px' }}>
              You are about to ask the backend to execute this check:
            </p>
            <div className="wb-confirm-summary">
              <div><strong>Rule:</strong> {ruleId} ({selectedRuleMeta?.title})</div>
              <div><strong>Target:</strong> {target}</div>
              <div><strong>Assessment:</strong> {assessmentId}</div>
              <div><strong>Mode:</strong> LIVE</div>
            </div>
            <p className="wb-confirm-note">
              The backend will re-validate this target against Scope Guard
              immediately before execution. A BLOCK result cannot be bypassed.
            </p>
          </div>
        }
        confirmLabel="Confirm &amp; Run"
        onConfirm={handleExecuteCheck}
        onCancel={() => setShowConfirmModal(false)}
      />
    </div>
  );
};
