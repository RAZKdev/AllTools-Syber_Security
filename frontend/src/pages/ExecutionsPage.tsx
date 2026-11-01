import React, { useState, useEffect } from 'react';
import {
  PlayCircle,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  Terminal,
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

interface ExecutionsPageProps {
  isDemoMode: boolean;
}

export const ExecutionsPage: React.FC<ExecutionsPageProps> = ({ isDemoMode }) => {
  const [rules, setRules] = useState<SecurityRuleMetadata[]>([]);
  const [executions, setExecutions] = useState<CheckExecutionRecord[]>([]);
  const [selectedExec, setSelectedExec] = useState<CheckExecutionRecord | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Execution Form State
  const [ruleId, setRuleId] = useState<string>('SEC-WEB-001');
  const [target, setTarget] = useState<string>('app.lab.local');
  const [running, setRunning] = useState<boolean>(false);
  const [lastResult, setLastResult] = useState<RunCheckResponse | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const [showConfirmModal, setShowConfirmModal] = useState<boolean>(false);

  const assessmentId = isDemoMode ? 'DEMO-ASM-001' : 'ASM-001';

  const loadData = async () => {
    setLoading(true);
    setError(null);
    setLastResult(null);
    setRunError(null);
    setSelectedExec(null);

    if (isDemoMode) {
      setRules(DEMO_RULES);
      setExecutions(DEMO_CHECK_EXECUTIONS);
      setSelectedExec(DEMO_CHECK_EXECUTIONS[0] || null);
      setLoading(false);
      return;
    }

    try {
      const [rulesRes, execsRes] = await Promise.all([
        api.getRules().catch(() => []),
        api.getExecutions().catch(() => []),
      ]);

      setRules(rulesRes);
      setExecutions(execsRes);
      setSelectedExec(execsRes.length > 0 ? execsRes[0] : null);
    } catch (err: any) {
      setError(err?.message || 'Failed to load check execution telemetry from backend');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [isDemoMode]);

  const selectedRuleMeta = rules.find((r) => r.ruleId === ruleId);

  const getTargetPlaceholder = () => {
    if (ruleId === 'SEC-CRYPTO-001') return 'e.g. 5d41402abc4b2a76b9719d911017c592 or SHA256 string';
    if (ruleId === 'SEC-AUTH-001') return 'e.g. AdminPassword!2026';
    if (ruleId === 'SEC-NET-001') return 'e.g. 192.168.1.50 or app.lab.local';
    return 'e.g. app.lab.local, lab.local, 192.168.1.100';
  };

  const handleOpenConfirm = (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;
    setShowConfirmModal(true);
  };

  const handleExecuteCheck = async () => {
    setShowConfirmModal(false);
    if (!target.trim()) return;

    setRunning(true);
    setRunError(null);
    setLastResult(null);

    if (isDemoMode) {
      // Offline deterministic simulation for demo fixtures
      const cleanTarget = target.trim().toLowerCase();
      const isAllowed =
        ruleId === 'SEC-AUTH-001' ||
        ruleId === 'SEC-CRYPTO-001' ||
        (cleanTarget.includes('lab.local') && !cleanTarget.includes('database'));

      const demoRecord: RunCheckResponse = {
        allowed: isAllowed,
        executionRecord: {
          id: `DEMO-CHK-${Math.floor(1000 + Math.random() * 9000)}`,
          assessmentId,
          ruleId,
          target: target.trim(),
          scopeDecision: isAllowed ? 'ALLOW' : 'BLOCK',
          status: isAllowed ? 'PASS' : 'BLOCKED_OUT_OF_SCOPE',
          durationMs: isAllowed ? 38 : 2,
          errorCode: isAllowed ? undefined : 'SCOPE_VIOLATION',
          errorMessage: isAllowed
            ? undefined
            : 'Target excluded by scope policy rule DEMO-SCP-003.',
          executedAt: new Date().toISOString(),
        },
        observation: isAllowed
          ? {
              id: 'DEMO-OBS-01',
              summary: `Target ${target} passed defensive parameter validation for ${ruleId}.`,
              observedAt: new Date().toISOString(),
            }
          : undefined,
        message: isAllowed
          ? `Check ${ruleId} completed with status PASS.`
          : 'BLOCKED — OUT OF SCOPE. Target is not authorized under active scope policy.',
      };

      setLastResult(demoRecord);
      setExecutions([demoRecord.executionRecord, ...executions]);
      setSelectedExec(demoRecord.executionRecord);
      setRunning(false);
      return;
    }

    try {
      const res = await api.runCheck(assessmentId, ruleId, target.trim());
      setLastResult(res);
      setExecutions([res.executionRecord, ...executions]);
      setSelectedExec(res.executionRecord);
    } catch (err: any) {
      setRunError(err?.message || 'Check execution request failed on backend API');
    } finally {
      setRunning(false);
    }
  };

  const columns: DataTableColumn<CheckExecutionRecord>[] = [
    {
      key: 'executedAt',
      label: 'Executed At',
      width: '120px',
      render: (row) => (
        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
          {new Date(row.executedAt).toLocaleTimeString()}
        </span>
      ),
    },
    {
      key: 'id',
      label: 'Execution ID',
      width: '120px',
      render: (row) => (
        <code style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
          {row.id}
        </code>
      ),
    },
    {
      key: 'ruleId',
      label: 'Rule Module',
      width: '110px',
      render: (row) => (
        <code style={{ color: 'var(--accent)', fontWeight: 600 }}>
          {row.ruleId}
        </code>
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
      label: 'Scope Guard',
      width: '100px',
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
      width: '110px',
      render: (row) => <StatusBadge status={row.status} size="sm" />,
    },
    {
      key: 'durationMs',
      label: 'Duration',
      width: '90px',
      render: (row) => (
        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
          {row.durationMs !== undefined ? `${row.durationMs}ms` : '—'}
        </span>
      ),
    },
  ];

  // Group rules by category for select dropdown
  const groupedRules: Record<string, SecurityRuleMetadata[]> = {};
  for (const r of rules) {
    if (!groupedRules[r.category]) {
      groupedRules[r.category] = [];
    }
    groupedRules[r.category].push(r);
  }

  if (loading && !isDemoMode) {
    return <StatePanel kind="loading" title="Loading Execution Telemetry..." />;
  }

  if (error && !isDemoMode) {
    return (
      <StatePanel
        kind="offline"
        title="Check Execution Service Offline"
        description="Could not query available security rules or past execution records from backend."
        errorMessage={error}
        onRetry={loadData}
      />
    );
  }

  return (
    <div className="wb-split-v">
      {/* =========================================================================
          Top Pane: Execution Launcher Form & Real-Time Output Banner
          ========================================================================= */}
      <div className="wb-panel" style={{ overflow: 'visible' }}>
        <div className="wb-panel-header">
          <div className="wb-panel-title">
            <PlayCircle size={14} color="var(--accent)" />
            <span>Defensive Security Check Execution Pipeline</span>
            {isDemoMode && <DemoBadge />}
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Scope Guard: <strong>Enforcing Default-Deny</strong>
          </span>
        </div>

        <div className="wb-panel-body" style={{ padding: '16px' }}>
          <form
            onSubmit={handleOpenConfirm}
            style={{
              display: 'grid',
              gridTemplateColumns: '1.2fr 2fr auto',
              gap: '10px',
              alignItems: 'flex-end',
            }}
          >
            <div>
              <label
                style={{
                  display: 'block',
                  fontSize: '11px',
                  color: 'var(--text-muted)',
                  marginBottom: '4px',
                  fontWeight: 600,
                }}
              >
                Security Rule Module ({rules.length} Available)
              </label>
              <select
                className="wb-select"
                value={ruleId}
                onChange={(e) => setRuleId(e.target.value)}
                style={{ width: '100%', fontFamily: 'var(--font-mono)' }}
              >
                {Object.entries(groupedRules).map(([cat, catRules]) => (
                  <optgroup key={cat} label={cat}>
                    {catRules.map((r) => (
                      <option key={r.ruleId} value={r.ruleId}>
                        {r.ruleId}: {r.title}
                      </option>
                    ))}
                  </optgroup>
                ))}
              </select>
            </div>

            <div>
              <label
                style={{
                  display: 'block',
                  fontSize: '11px',
                  color: 'var(--text-muted)',
                  marginBottom: '4px',
                  fontWeight: 600,
                }}
              >
                Target Identifier / Test Sample
              </label>
              <input
                type="text"
                required
                className="wb-input font-mono"
                placeholder={getTargetPlaceholder()}
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                style={{ width: '100%' }}
              />
            </div>

            <button
              type="submit"
              disabled={running || !target.trim()}
              className="wb-btn wb-btn-primary"
              style={{ padding: '6px 14px' }}
            >
              {running ? (
                <>
                  <RefreshCw size={13} className="spin" />
                  Running...
                </>
              ) : (
                <>
                  <PlayCircle size={14} />
                  Execute Check
                </>
              )}
            </button>
          </form>

          {/* Selected Rule Documentation Hint */}
          {selectedRuleMeta && (
            <div
              style={{
                marginTop: '10px',
                padding: '8px 12px',
                borderRadius: '3px',
                background: 'var(--bg-table-zebra)',
                border: '1px solid var(--border-subtle)',
                fontSize: '11px',
                color: 'var(--text-secondary)',
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
              }}
            >
              <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                {selectedRuleMeta.title}
              </span>
              <span>Classification: <code style={{ color: 'var(--accent)' }}>{selectedRuleMeta.cwe}</code></span>
              <span style={{ color: 'var(--text-muted)' }}>{selectedRuleMeta.description}</span>
            </div>
          )}

          {/* Execution Error Banner */}
          {runError && (
            <div
              style={{
                marginTop: '12px',
                padding: '10px 14px',
                borderRadius: '4px',
                background: 'var(--status-error-bg)',
                border: '1px solid var(--status-error-border)',
                color: 'var(--status-error-text)',
                fontSize: '11px',
              }}
            >
              <strong>Check Execution Error:</strong> {runError}
            </div>
          )}

          {/* Last Result Live Output Banner */}
          {lastResult && (
            <div
              style={{
                marginTop: '12px',
                padding: '12px 14px',
                borderRadius: '4px',
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
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
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
                  <span
                    style={{
                      fontWeight: 700,
                      fontFamily: 'var(--font-mono)',
                      fontSize: '12px',
                      color: lastResult.allowed
                        ? lastResult.executionRecord.status === 'FAIL'
                          ? 'var(--status-fail-text)'
                          : 'var(--status-pass-text)'
                        : 'var(--status-blocked-text)',
                    }}
                  >
                    {lastResult.allowed
                      ? `CHECK RESULT: ${lastResult.executionRecord.status}`
                      : 'SCOPE VIOLATION — BLOCKED'}
                  </span>
                </div>
                <StatusBadge status={lastResult.executionRecord.status} size="sm" />
              </div>

              <div
                style={{
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--text-primary)',
                  whiteSpace: 'pre-wrap',
                }}
              >
                {lastResult.message}
              </div>

              {lastResult.finding && (
                <div
                  style={{
                    marginTop: '8px',
                    padding: '8px 10px',
                    background: 'var(--bg-surface)',
                    border: '1px solid var(--border-default)',
                    borderRadius: '3px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                  }}
                >
                  <SeverityBadge severity={lastResult.finding.severity} size="sm" />
                  <span style={{ fontWeight: 600, fontSize: '11px', color: 'var(--text-primary)' }}>
                    {lastResult.finding.title}
                  </span>
                  {lastResult.finding.cwe && (
                    <code style={{ fontSize: '10px', color: 'var(--accent)' }}>
                      {lastResult.finding.cwe}
                    </code>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* =========================================================================
          Bottom Pane: Split Table of Past Executions & Inspector
          ========================================================================= */}
      <div className="wb-split-h">
        {/* Executions Table */}
        <div className="wb-panel">
          <div className="wb-panel-header">
            <div className="wb-panel-title">
              <Terminal size={14} color="var(--text-secondary)" />
              <span>Execution Audit Log</span>
              <span className="wb-panel-count">{executions.length}</span>
            </div>
            <button
              onClick={loadData}
              className="wb-btn wb-btn-sm"
              title="Refresh executions from backend"
            >
              <RefreshCw size={10} />
              Refresh
            </button>
          </div>

          <div className="wb-panel-body">
            <DataTable
              columns={columns}
              data={executions}
              keyExtractor={(row) => row.id}
              selectedId={selectedExec?.id}
              onSelectRow={(row) => setSelectedExec(row)}
              emptyMessage="No execution records recorded. Run a check above."
            />
          </div>
        </div>

        {/* Selected Execution Inspector */}
        <div className="wb-panel">
          <div className="wb-panel-header">
            <div className="wb-panel-title">
              <span>Execution Details: {selectedExec?.id || 'None'}</span>
            </div>
          </div>

          <div className="wb-panel-body" style={{ padding: '12px' }}>
            {selectedExec ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <KeyValue
                  items={[
                    { key: 'Execution ID', value: selectedExec.id },
                    { key: 'Assessment ID', value: selectedExec.assessmentId },
                    { key: 'Rule Module', value: selectedExec.ruleId },
                    { key: 'Target', value: selectedExec.target },
                    {
                      key: 'Scope Guard',
                      value: (
                        <span
                          className="wb-chip"
                          style={{
                            background:
                              selectedExec.scopeDecision === 'ALLOW'
                                ? 'var(--status-pass-bg)'
                                : 'var(--status-blocked-bg)',
                            color:
                              selectedExec.scopeDecision === 'ALLOW'
                                ? 'var(--status-pass-text)'
                                : 'var(--status-blocked-text)',
                          }}
                        >
                          {selectedExec.scopeDecision}
                        </span>
                      ),
                    },
                    {
                      key: 'Outcome Status',
                      value: <StatusBadge status={selectedExec.status} size="sm" />,
                    },
                    {
                      key: 'Execution Time',
                      value: `${selectedExec.durationMs ?? '—'} ms`,
                    },
                    {
                      key: 'Timestamp (UTC)',
                      value: new Date(selectedExec.executedAt).toUTCString(),
                    },
                  ]}
                />

                {selectedExec.errorMessage && (
                  <div>
                    <div
                      style={{
                        fontSize: '10px',
                        fontWeight: 700,
                        textTransform: 'uppercase',
                        color: 'var(--status-blocked-text)',
                        marginBottom: '4px',
                      }}
                    >
                      Error / Scope Message
                    </div>
                    <pre
                      style={{
                        padding: '8px',
                        background: 'var(--status-blocked-bg)',
                        border: '1px solid var(--status-blocked-border)',
                        color: 'var(--status-blocked-text)',
                        fontSize: '11px',
                        borderRadius: '3px',
                        whiteSpace: 'pre-wrap',
                      }}
                    >
                      {selectedExec.errorMessage}
                    </pre>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
                Select an execution record to view complete operational telemetry.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Confirmation Modal Before Execution */}
      <ConfirmDialog
        isOpen={showConfirmModal}
        title="Confirm Defensive Security Check Execution"
        message={
          <div>
            <p style={{ marginBottom: '8px' }}>
              You are about to execute the defensive security analyzer against target:
            </p>
            <div
              style={{
                background: 'var(--bg-table-zebra)',
                border: '1px solid var(--border-subtle)',
                padding: '8px 12px',
                borderRadius: '3px',
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
              }}
            >
              <div><strong>Rule:</strong> {ruleId} ({selectedRuleMeta?.title})</div>
              <div><strong>Target:</strong> {target}</div>
              <div><strong>Assessment ID:</strong> {assessmentId}</div>
            </div>
            <p style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-muted)' }}>
              Scope Guard will evaluate this target before any socket connection or network transmission.
              Out-of-scope targets will be blocked immediately without touching the target.
            </p>
          </div>
        }
        confirmLabel="Execute Now"
        onConfirm={handleExecuteCheck}
        onCancel={() => setShowConfirmModal(false)}
      />
    </div>
  );
};
