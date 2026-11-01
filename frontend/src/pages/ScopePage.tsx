import React, { useCallback, useEffect, useState } from 'react';
import {
  Target,
  Plus,
  ShieldCheck,
  RefreshCw,
  Filter,
  Info,
} from 'lucide-react';
import {
  api,
  ScopeItem,
  ScopeEvaluationResult,
  EnforcementStatus,
} from '@/services/api';
import { DEMO_SCOPE_ITEMS } from '@/demo/fixtures';
import { DataTable, DataTableColumn } from '@/components/DataTable';
import { ScopeIndicator } from '@/components/ScopeIndicator';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { StatePanel } from '@/components/StatePanel';
import { DemoBadge } from '@/components/DemoBadge';
import { FilterTabs } from '@/components/FilterTabs';
import { PageHeader } from '@/components/PageHeader';
import { ContextSidebar } from '@/components/ContextSidebar';
import { DetailPanel, DetailTab } from '@/components/DetailPanel';
import { KeyValue } from '@/components/KeyValue';
import { BackendConnectionState } from '@/components/ConnectionStatus';

interface ScopePageProps {
  isDemoMode: boolean;
  assessmentId: string | null;
  engagementId: string | null;
  connectionState: BackendConnectionState;
  contextLoading?: boolean;
  refreshToken?: number;
  enforcementStatus?: EnforcementStatus;
  onScopeUpdated?: () => void;
}

function isExpired(expiresAt?: string): boolean {
  if (!expiresAt) return false;
  const timestamp = Date.parse(expiresAt);
  return Number.isFinite(timestamp) && timestamp <= Date.now();
}

function policyOf(item: ScopeItem): 'IN SCOPE' | 'EXCLUDED' | 'EXPIRED' {
  if (isExpired(item.expiresAt)) return 'EXPIRED';
  return item.inScope ? 'IN SCOPE' : 'EXCLUDED';
}

function formatTimestamp(value?: string): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

export const ScopePage: React.FC<ScopePageProps> = ({
  isDemoMode,
  assessmentId,
  engagementId,
  connectionState,
  contextLoading = false,
  refreshToken = 0,
  enforcementStatus = 'not_checked',
  onScopeUpdated,
}) => {
  const [scopeItems, setScopeItems] = useState<ScopeItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [filterPolicy, setFilterPolicy] = useState<string>('all');
  const [selectedRule, setSelectedRule] = useState<ScopeItem | null>(null);

  // Target evaluator (read-only backend call)
  const [testTarget, setTestTarget] = useState<string>('');
  const [evaluating, setEvaluating] = useState<boolean>(false);
  const [evalResult, setEvalResult] = useState<ScopeEvaluationResult | null>(null);
  const [evalError, setEvalError] = useState<string | null>(null);

  // Add scope rule (add-only; backend has no edit/delete endpoint)
  const [showAddModal, setShowAddModal] = useState<boolean>(false);
  const [showConfirmModal, setShowConfirmModal] = useState<boolean>(false);
  const [newType, setNewType] = useState<string>('domain');
  const [newValue, setNewValue] = useState<string>('');
  const [newInScope, setNewInScope] = useState<boolean>(true);
  const [newEnvironment, setNewEnvironment] = useState<string>('lab');
  const [newNotes, setNewNotes] = useState<string>('');
  const [actionError, setActionError] = useState<string | null>(null);

  const isOffline =
    connectionState === 'offline' || connectionState === 'api_error';
  const cannotUseBackend =
    isDemoMode || isOffline || connectionState !== 'connected' || !assessmentId;

  const fetchScope = useCallback(async () => {
    setLoading(true);
    setError(null);
    setEvalResult(null);
    setEvalError(null);
    setActionError(null);
    setSelectedRule(null);

    if (isDemoMode) {
      setScopeItems(DEMO_SCOPE_ITEMS);
      setLoading(false);
      return;
    }

    if (!engagementId) {
      setScopeItems([]);
      setLoading(false);
      return;
    }

    try {
      const items = await api.getScopeItems(engagementId);
      setScopeItems(items);
    } catch (err: any) {
      setScopeItems([]);
      setError(err?.message || 'Failed to fetch scope items from the backend API.');
    } finally {
      setLoading(false);
    }
  }, [engagementId, isDemoMode]);

  useEffect(() => {
    fetchScope();
  }, [fetchScope, refreshToken]);

  const expiredCount = scopeItems.filter((item) => isExpired(item.expiresAt)).length;
  const inScopeCount = scopeItems.filter(
    (item) => item.inScope && !isExpired(item.expiresAt),
  ).length;
  const excludedCount = scopeItems.filter(
    (item) => !item.inScope && !isExpired(item.expiresAt),
  ).length;

  const filteredItems = scopeItems.filter((item) => {
    const policy = policyOf(item);
    if (filterPolicy === 'in_scope') return policy === 'IN SCOPE';
    if (filterPolicy === 'excluded') return policy === 'EXCLUDED';
    if (filterPolicy === 'expired') return policy === 'EXPIRED';
    return true;
  });

  const handleEvaluate = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!testTarget.trim() || cannotUseBackend || !assessmentId) return;

    setEvaluating(true);
    setEvalResult(null);
    setEvalError(null);

    try {
      const result = await api.evaluateScope(assessmentId, testTarget.trim());
      setEvalResult(result);
    } catch (err: any) {
      setEvalError(
        err?.message ||
          'Evaluation unavailable — no decision was made by the backend.',
      );
    } finally {
      setEvaluating(false);
    }
  };

  const handleOpenAdd = () => {
    setNewValue('');
    setNewNotes('');
    setActionError(null);
    setShowAddModal(true);
  };

  const handleSubmitAddForm = (event: React.FormEvent) => {
    event.preventDefault();
    if (!newValue.trim() || isDemoMode) return;
    setShowAddModal(false);
    setShowConfirmModal(true);
  };

  const handleConfirmAdd = async () => {
    setShowConfirmModal(false);
    if (!newValue.trim() || !engagementId || isDemoMode) return;

    setActionError(null);
    try {
      await api.createScopeItem({
        engagementId,
        type: newType,
        value: newValue.trim(),
        environment: newEnvironment,
        inScope: newInScope,
        notes: newNotes.trim() || undefined,
      });
      // Refetch rather than appending a local record.
      await fetchScope();
      onScopeUpdated?.();
    } catch (err: any) {
      setActionError(
        `Failed to create scope rule: ${err?.message || 'Backend API error'}`,
      );
    }
  };

  const columns: DataTableColumn<ScopeItem>[] = [
    {
      key: 'id',
      label: 'Rule ID',
      width: '110px',
      render: (row) => (
        <code style={{ color: 'var(--text-primary)', fontWeight: 700 }}>
          {row.id}
        </code>
      ),
    },
    {
      key: 'type',
      label: 'Type',
      width: '100px',
      render: (row) => (
        <code style={{ color: 'var(--accent)', fontSize: '11px' }}>{row.type}</code>
      ),
    },
    {
      key: 'value',
      label: 'Value',
      render: (row) => (
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontWeight: 600,
            color: 'var(--text-primary)',
          }}
        >
          {row.value}
        </span>
      ),
    },
    {
      key: 'policy',
      label: 'Policy',
      width: '115px',
      render: (row) => {
        const policy = policyOf(row);
        const tone =
          policy === 'IN SCOPE'
            ? ['var(--status-pass-bg)', 'var(--status-pass-text)', 'var(--status-pass-border)']
            : policy === 'EXCLUDED'
              ? ['var(--status-blocked-bg)', 'var(--status-blocked-text)', 'var(--status-blocked-border)']
              : ['var(--status-warn-bg)', 'var(--status-warn-text)', 'var(--status-warn-border)'];
        return (
          <span
            className="wb-chip"
            style={{ background: tone[0], color: tone[1], border: `1px solid ${tone[2]}` }}
          >
            {policy}
          </span>
        );
      },
    },
    {
      key: 'environment',
      label: 'Environment',
      width: '110px',
      render: (row) => (
        <span style={{ color: 'var(--text-secondary)' }}>
          {row.environment || '—'}
        </span>
      ),
    },
    {
      key: 'expiresAt',
      label: 'Expires',
      width: '145px',
      render: (row) => (
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            color: isExpired(row.expiresAt)
              ? 'var(--status-warn-text)'
              : 'var(--text-muted)',
          }}
        >
          {formatTimestamp(row.expiresAt)}
        </span>
      ),
    },
    {
      key: 'notes',
      label: 'Notes',
      render: (row) => (
        <span style={{ color: 'var(--text-muted)' }}>{row.notes || '—'}</span>
      ),
    },
  ];

  const detailTabs: DetailTab[] = selectedRule
    ? [
        {
          id: 'rule',
          label: 'Rule',
          content: (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <KeyValue
                items={[
                  { key: 'Rule ID', value: selectedRule.id },
                  { key: 'Engagement', value: selectedRule.engagementId },
                  { key: 'Type', value: selectedRule.type },
                  { key: 'Value', value: selectedRule.value },
                  { key: 'Environment', value: selectedRule.environment || '—' },
                  { key: 'Policy', value: policyOf(selectedRule) },
                  { key: 'Expires', value: formatTimestamp(selectedRule.expiresAt) },
                  { key: 'Source', value: isDemoMode ? 'Demo fixture' : 'Backend API' },
                ]}
              />
              <div>
                <div className="wb-section-label">Notes</div>
                <div className="wb-detail-text">
                  {selectedRule.notes || 'No notes recorded for this rule.'}
                </div>
              </div>
            </div>
          ),
        },
      ]
    : [
        {
          id: 'none',
          label: 'Rule',
          content: (
            <div className="wb-no-selection">
              Select a scope rule to inspect its boundary details.
            </div>
          ),
        },
      ];

  if (contextLoading && !isDemoMode) {
    return <StatePanel kind="loading" title="Loading workspace context…" />;
  }

  if (loading) {
    return <StatePanel kind="loading" title="Retrieving scope rules…" />;
  }

  if (error) {
    return (
      <StatePanel
        kind={isOffline ? 'offline' : 'error'}
        title={isOffline ? 'Scope backend unreachable' : 'Scope request failed'}
        description="No scope data is shown because the backend request did not succeed."
        errorMessage={error}
        onRetry={fetchScope}
      />
    );
  }

  const demoDisabledReason =
    'Disabled in Demo Mode. Demo fixtures cannot authorize or modify scope.';
  const offlineDisabledReason =
    'Disabled while the backend is offline or has an API error.';

  return (
    <div className="wb-page-layout">
      <ContextSidebar
        title="Scope Guard"
        footer={
          <span>
            {isDemoMode
              ? 'Demo fixture — not live'
              : 'Scope comes from the backend. Add-only; no edit/delete API.'}
          </span>
        }
      >
        <div className="wb-context-section">
          <div className="wb-section-label">Policy filter</div>
          <div className="wb-sidebar-filters">
            <FilterTabs
              options={[
                { id: 'all', label: 'All', count: scopeItems.length },
                { id: 'in_scope', label: 'In scope', count: inScopeCount },
                { id: 'excluded', label: 'Excluded', count: excludedCount },
                { id: 'expired', label: 'Expired', count: expiredCount },
              ]}
              activeId={filterPolicy}
              onChange={setFilterPolicy}
            />
          </div>
        </div>

        <div className="wb-context-section">
          <div className="wb-section-label">Boundary summary</div>
          <KeyValue
            items={[
              { key: 'Active in-scope', value: inScopeCount },
              { key: 'Excluded', value: excludedCount },
              { key: 'Expired', value: expiredCount },
              { key: 'Total rules', value: scopeItems.length },
            ]}
          />
          <p className="wb-context-note">
            Expired rules are never counted as active or authorized. Default-deny
            is enforced by the backend, not by this table.
          </p>
        </div>

        <div className="wb-context-section">
          <button
            type="button"
            className="wb-btn wb-btn-primary wb-btn-sm"
            onClick={handleOpenAdd}
            disabled={isDemoMode || isOffline || !engagementId}
            title={
              isDemoMode
                ? demoDisabledReason
                : isOffline
                  ? offlineDisabledReason
                  : 'Add a scope rule (confirmation required)'
            }
          >
            <Plus size={12} /> Add scope rule
          </button>
          <p className="wb-context-note">
            Adding a rule is a high-impact action and requires confirmation.
            The backend remains the final authority.
          </p>
        </div>
      </ContextSidebar>

      <div className="wb-page-main">
        <PageHeader
          title="Scope Guard"
          description="Backend enforcement; default deny. Inspect authorized boundaries without simulating a decision."
          isDemoMode={isDemoMode}
          meta={
            <>
              <span>
                Assessment: <strong>{assessmentId || 'No assessment'}</strong>
              </span>
              <span>
                Enforcement:{' '}
                <strong>
                  {enforcementStatus === 'default_deny_verified'
                    ? 'Default-deny verified'
                    : enforcementStatus === 'demo'
                      ? 'n/a (demo)'
                      : enforcementStatus === 'unavailable'
                        ? 'Unavailable'
                        : 'Not verified'}
                </strong>
              </span>
            </>
          }
        />

        <div className="wb-page-body wb-scope-workspace">
          {actionError && (
            <div className="wb-alert error" role="alert">
              <strong>Scope action failed:</strong> {actionError}
            </div>
          )}

          <div className="wb-split-h wb-scope-main">
            <div className="wb-panel">
              <div className="wb-panel-header">
                <div className="wb-panel-title">
                  <Target size={14} color="var(--accent)" />
                  <span>Authorized scope rules</span>
                  <span className="wb-panel-count">{filteredItems.length}</span>
                  {isDemoMode && <DemoBadge />}
                </div>
                <button
                  type="button"
                  onClick={fetchScope}
                  className="wb-btn wb-btn-sm"
                  title="Refresh scope rules from the backend"
                  disabled={isOffline}
                >
                  <RefreshCw size={10} /> Refresh
                </button>
              </div>
              <div className="wb-toolbar">
                <div className="wb-toolbar-group">
                  <Filter size={12} color="var(--text-muted)" />
                  <span className="wb-toolbar-label">
                    {filterPolicy === 'all'
                      ? 'All rules'
                      : filterPolicy === 'in_scope'
                        ? 'In-scope rules'
                        : filterPolicy === 'excluded'
                          ? 'Excluded rules'
                          : 'Expired rules'}
                  </span>
                </div>
                <span className="wb-toolbar-spacer" />
                <span className="wb-toolbar-hint">
                  Backend source: {isDemoMode ? 'DEMO fixture' : 'GET /scope/items'}
                </span>
              </div>
              <div className="wb-panel-body">
                <DataTable
                  columns={columns}
                  data={filteredItems}
                  keyExtractor={(row) => row.id}
                  selectedId={selectedRule?.id}
                  onSelectRow={(row) => setSelectedRule(row)}
                  emptyMessage={
                    filterPolicy === 'all'
                      ? 'No scope rules for this engagement.'
                      : 'No scope rules match the selected filter.'
                  }
                />
              </div>
            </div>

            <DetailPanel
              title={selectedRule ? `Rule: ${selectedRule.id}` : 'Rule inspector'}
              tabs={detailTabs}
              actions={isDemoMode ? <DemoBadge /> : undefined}
            />
          </div>

          <div className="wb-panel wb-evaluator-panel">
            <div className="wb-panel-header">
              <div className="wb-panel-title">
                <ShieldCheck size={14} color="var(--accent)" />
                <span>Evaluate a target against the backend</span>
              </div>
              <span className="wb-toolbar-hint">
                POST /scope/evaluate · read-only
              </span>
            </div>

            <div className="wb-panel-body wb-evaluator-body">
              <p className="wb-evaluator-description">
                Decisions are returned by the backend Scope Guard. This workbench
                never computes an ALLOW/BLOCK result in the browser.
              </p>

              <form className="wb-evaluator-form" onSubmit={handleEvaluate}>
                <label className="wb-sr-only" htmlFor="scope-target-input">
                  Target to evaluate
                </label>
                <input
                  id="scope-target-input"
                  type="text"
                  className="wb-input font-mono"
                  placeholder="e.g. app.lab.local, 192.168.1.50, external-target.com"
                  value={testTarget}
                  onChange={(event) => {
                    setTestTarget(event.target.value);
                    setEvalResult(null);
                    setEvalError(null);
                  }}
                  disabled={cannotUseBackend || evaluating}
                />
                <button
                  type="submit"
                  disabled={
                    cannotUseBackend || evaluating || !testTarget.trim()
                  }
                  className="wb-btn wb-btn-primary"
                  title={
                    isDemoMode
                      ? demoDisabledReason
                      : isOffline
                        ? offlineDisabledReason
                        : 'Evaluate against backend Scope Guard'
                  }
                >
                  {evaluating ? (
                    <>
                      <RefreshCw size={12} className="spin" /> Evaluating…
                    </>
                  ) : (
                    <>
                      <ShieldCheck size={13} /> Evaluate against backend
                    </>
                  )}
                </button>
              </form>

              {isDemoMode && (
                <div className="wb-inline-note">
                  <Info size={12} />
                  Demo Mode: evaluation is disabled. The sample decision shown in
                  fixtures is static and cannot authorize any action.
                </div>
              )}

              {evalError && (
                <div className="wb-alert error" role="alert">
                  <strong>Evaluation unavailable — no decision was made.</strong>{' '}
                  {evalError}
                </div>
              )}

              {evalResult && (
                <ScopeIndicator
                  decision={evalResult.decision}
                  target={evalResult.target}
                  reason={evalResult.reason}
                  matchedRuleId={evalResult.matchedScopeItemId}
                  evaluatedAt={evalResult.evaluatedAt}
                />
              )}
            </div>
          </div>
        </div>
      </div>

      {showAddModal && (
        <div className="wb-modal-backdrop" onClick={() => setShowAddModal(false)}>
          <div
            className="wb-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="add-scope-title"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="wb-modal-header">
              <span id="add-scope-title" style={{ fontWeight: 700 }}>
                Add authorized scope rule
              </span>
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                className="wb-btn wb-btn-sm"
              >
                Cancel
              </button>
            </div>
            <form onSubmit={handleSubmitAddForm}>
              <div className="wb-modal-body wb-form-stack">
                <div>
                  <label className="wb-form-label" htmlFor="new-scope-type">
                    Scope rule type
                  </label>
                  <select
                    id="new-scope-type"
                    className="wb-select"
                    value={newType}
                    onChange={(event) => setNewType(event.target.value)}
                  >
                    <option value="domain">domain (e.g. lab.local)</option>
                    <option value="subdomain">subdomain (*.lab.local)</option>
                    <option value="ip">ip (single address)</option>
                    <option value="cidr">cidr (e.g. 192.168.1.0/24)</option>
                    <option value="url">url (e.g. https://lab.local/api)</option>
                    <option value="hostname">hostname</option>
                  </select>
                </div>

                <div>
                  <label className="wb-form-label" htmlFor="new-scope-value">
                    Target pattern / value *
                  </label>
                  <input
                    id="new-scope-value"
                    type="text"
                    required
                    className="wb-input font-mono"
                    placeholder="e.g. app.lab.local or 10.10.0.0/16"
                    value={newValue}
                    onChange={(event) => setNewValue(event.target.value)}
                  />
                </div>

                <div className="wb-form-grid">
                  <div>
                    <label className="wb-form-label" htmlFor="new-scope-policy">
                      Authorization policy
                    </label>
                    <select
                      id="new-scope-policy"
                      className="wb-select"
                      value={newInScope ? 'true' : 'false'}
                      onChange={(event) => setNewInScope(event.target.value === 'true')}
                    >
                      <option value="true">IN SCOPE (allow target)</option>
                      <option value="false">EXCLUSION (strict block)</option>
                    </select>
                  </div>

                  <div>
                    <label className="wb-form-label" htmlFor="new-scope-env">
                      Environment
                    </label>
                    <select
                      id="new-scope-env"
                      className="wb-select"
                      value={newEnvironment}
                      onChange={(event) => setNewEnvironment(event.target.value)}
                    >
                      <option value="lab">lab</option>
                      <option value="development">development</option>
                      <option value="staging">staging</option>
                      <option value="production">production</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="wb-form-label" htmlFor="new-scope-notes">
                    Assessor notes / justification
                  </label>
                  <input
                    id="new-scope-notes"
                    type="text"
                    className="wb-input"
                    placeholder="e.g. Authorized lab testing endpoint under RoE"
                    value={newNotes}
                    onChange={(event) => setNewNotes(event.target.value)}
                  />
                </div>
              </div>

              <div className="wb-modal-footer">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="wb-btn"
                >
                  Cancel
                </button>
                <button type="submit" className="wb-btn wb-btn-primary">
                  Review &amp; save
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <ConfirmDialog
        isOpen={showConfirmModal}
        title="Confirm authorized scope rule addition"
        message={
          <div>
            <p style={{ marginBottom: '8px' }}>
              Add this rule to engagement <code>{engagementId}</code>?
            </p>
            <div className="wb-confirm-summary">
              <div><strong>Pattern:</strong> {newValue}</div>
              <div><strong>Type:</strong> {newType}</div>
              <div>
                <strong>Policy:</strong>{' '}
                {newInScope ? 'IN SCOPE (allow)' : 'EXCLUSION (strict block)'}
              </div>
              <div><strong>Environment:</strong> {newEnvironment}</div>
            </div>
            <p className="wb-confirm-note">
              The backend stores this rule in its in-memory repository. It is not
              permanent and resets when the backend restarts.
            </p>
          </div>
        }
        confirmLabel="Add scope rule"
        onConfirm={handleConfirmAdd}
        onCancel={() => setShowConfirmModal(false)}
      />
    </div>
  );
};
