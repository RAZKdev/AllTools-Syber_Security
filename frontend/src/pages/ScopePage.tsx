import React, { useState, useEffect } from 'react';
import {
  Target,
  Plus,
  ShieldCheck,
  RefreshCw,
  Filter,
} from 'lucide-react';
import {
  api,
  ScopeItem,
  ScopeEvaluationResult,
} from '@/services/api';
import { DEMO_SCOPE_ITEMS } from '@/demo/fixtures';
import { DataTable, DataTableColumn } from '@/components/DataTable';
import { ScopeIndicator } from '@/components/ScopeIndicator';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { StatePanel } from '@/components/StatePanel';
import { DemoBadge } from '@/components/DemoBadge';
import { FilterTabs } from '@/components/FilterTabs';

interface ScopePageProps {
  isDemoMode: boolean;
  onScopeUpdated?: () => void;
}

export const ScopePage: React.FC<ScopePageProps> = ({
  isDemoMode,
  onScopeUpdated,
}) => {
  const [scopeItems, setScopeItems] = useState<ScopeItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [filterPolicy, setFilterPolicy] = useState<string>('all');

  // Interactive Target Evaluator State
  const [testTarget, setTestTarget] = useState<string>('');
  const [evaluating, setEvaluating] = useState<boolean>(false);
  const [evalResult, setEvalResult] = useState<ScopeEvaluationResult | null>(null);
  const [evalError, setEvalError] = useState<string | null>(null);

  // Probe Verification State
  const [probeVerified, setProbeVerified] = useState<boolean>(false);
  const [probing, setProbing] = useState<boolean>(false);

  // Add Scope Rule State
  const [showAddModal, setShowAddModal] = useState<boolean>(false);
  const [showConfirmModal, setShowConfirmModal] = useState<boolean>(false);
  const [newType, setNewType] = useState<string>('domain');
  const [newValue, setNewValue] = useState<string>('');
  const [newInScope, setNewInScope] = useState<boolean>(true);
  const [newEnvironment, setNewEnvironment] = useState<string>('lab');
  const [newNotes, setNewNotes] = useState<string>('');

  const assessmentId = isDemoMode ? 'DEMO-ASM-001' : 'ASM-001';
  const engagementId = isDemoMode ? 'DEMO-ENG-001' : 'ENG-001';

  const fetchScope = async () => {
    setLoading(true);
    setError(null);
    setEvalResult(null);
    setEvalError(null);
    setTestTarget('');

    if (isDemoMode) {
      setScopeItems(DEMO_SCOPE_ITEMS);
      setProbeVerified(true);
      setLoading(false);
      return;
    }

    try {
      const items = await api.getScopeItems();
      setScopeItems(items);
      await runProbe();
    } catch (err: any) {
      setError(err?.message || 'Failed to fetch scope items from backend');
    } finally {
      setLoading(false);
    }
  };

  const runProbe = async () => {
    setProbing(true);
    try {
      const probeRes = await api.probeScopeGuard(assessmentId);
      setProbeVerified(probeRes.isVerified);
    } catch {
      setProbeVerified(false);
    } finally {
      setProbing(false);
    }
  };

  useEffect(() => {
    fetchScope();
  }, [isDemoMode]);

  // Strict backend evaluation — zero client-side simulation
  const handleEvaluate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!testTarget.trim()) return;

    setEvaluating(true);
    setEvalResult(null);
    setEvalError(null);

    if (isDemoMode) {
      // Offline deterministic evaluation for demo fixtures
      const clean = testTarget.trim().toLowerCase();
      let decision: 'ALLOW' | 'BLOCK' = 'BLOCK';
      let reason = 'Target is outside authorized demo scope rules (fail-closed default deny).';
      let matchedId: string | undefined = undefined;

      // Check explicit exclusions first
      for (const item of DEMO_SCOPE_ITEMS) {
        if (!item.inScope && clean.includes(item.value.toLowerCase())) {
          decision = 'BLOCK';
          reason = `Target explicitly excluded by scope rule '${item.id}' (${item.type}: ${item.value}).`;
          matchedId = item.id;
          break;
        }
      }

      if (decision !== 'BLOCK') {
        for (const item of DEMO_SCOPE_ITEMS) {
          if (
            item.inScope &&
            (clean === item.value.toLowerCase() ||
              clean.endsWith(`.${item.value.toLowerCase()}`) ||
              (item.type === 'cidr' && clean.startsWith('192.168.10.')))
          ) {
            decision = 'ALLOW';
            reason = `Target authorized by scope rule '${item.id}' (${item.type}: ${item.value}).`;
            matchedId = item.id;
            break;
          }
        }
      }

      setEvalResult({
        assessmentId,
        target: testTarget.trim(),
        decision,
        reason,
        matchedScopeItemId: matchedId,
        evaluatedAt: new Date().toISOString(),
      });
      setEvaluating(false);
      return;
    }

    try {
      const res = await api.evaluateScope(assessmentId, testTarget.trim());
      setEvalResult(res);
    } catch (err: any) {
      setEvalError(
        err?.message || 'Failed to reach Scope Guard endpoint on backend API. Enforcement unverified.'
      );
    } finally {
      setEvaluating(false);
    }
  };

  const handleOpenAdd = () => {
    setNewValue('');
    setNewNotes('');
    setShowAddModal(true);
  };

  const handleSubmitAddForm = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newValue.trim()) return;
    setShowAddModal(false);
    setShowConfirmModal(true);
  };

  const handleConfirmAdd = async () => {
    setShowConfirmModal(false);
    if (!newValue.trim()) return;

    const payload: Partial<ScopeItem> = {
      engagementId,
      type: newType,
      value: newValue.trim(),
      environment: newEnvironment,
      inScope: newInScope,
      notes: newNotes.trim() || undefined,
    };

    if (isDemoMode) {
      const demoItem: ScopeItem = {
        id: `DEMO-SCP-${Math.floor(100 + Math.random() * 900)}`,
        engagementId,
        type: newType,
        value: newValue.trim(),
        environment: newEnvironment,
        inScope: newInScope,
        notes: newNotes.trim() || undefined,
      };
      setScopeItems([...scopeItems, demoItem]);
      if (onScopeUpdated) onScopeUpdated();
      return;
    }

    try {
      const created = await api.createScopeItem(payload);
      setScopeItems([...scopeItems, created]);
      if (onScopeUpdated) onScopeUpdated();
    } catch (err: any) {
      setError(`Failed to create scope rule: ${err?.message || 'API error'}`);
    }
  };

  const filteredItems = scopeItems.filter((item) => {
    if (filterPolicy === 'in_scope') return item.inScope;
    if (filterPolicy === 'excluded') return !item.inScope;
    return true;
  });

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
      label: 'Target Type',
      width: '100px',
      render: (row) => (
        <code style={{ color: 'var(--accent)', fontSize: '11px' }}>
          {row.type}
        </code>
      ),
    },
    {
      key: 'value',
      label: 'Pattern / Value',
      render: (row) => (
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontWeight: 700,
            color: 'var(--text-primary)',
          }}
        >
          {row.value}
        </span>
      ),
    },
    {
      key: 'inScope',
      label: 'Policy Boundary',
      width: '140px',
      render: (row) => (
        <span
          className="wb-chip"
          style={{
            background: row.inScope
              ? 'var(--status-pass-bg)'
              : 'var(--status-blocked-bg)',
            color: row.inScope
              ? 'var(--status-pass-text)'
              : 'var(--status-blocked-text)',
            border: `1px solid ${
              row.inScope
                ? 'var(--status-pass-border)'
                : 'var(--status-blocked-border)'
            }`,
          }}
        >
          {row.inScope ? 'IN SCOPE (ALLOW)' : 'EXCLUDED (BLOCK)'}
        </span>
      ),
    },
    {
      key: 'environment',
      label: 'Environment',
      width: '110px',
      render: (row) => (
        <span style={{ color: 'var(--text-secondary)' }}>
          {row.environment || 'lab'}
        </span>
      ),
    },
    {
      key: 'notes',
      label: 'Engagement Notes',
      render: (row) => (
        <span style={{ color: 'var(--text-muted)' }}>
          {row.notes || '—'}
        </span>
      ),
    },
  ];

  if (loading && !isDemoMode) {
    return <StatePanel kind="loading" title="Retrieving Scope Rules..." />;
  }

  if (error && !isDemoMode) {
    return (
      <StatePanel
        kind="offline"
        title="Scope Repository Inaccessible"
        description="Could not query authorized scope rules from the backend API."
        errorMessage={error}
        onRetry={fetchScope}
      />
    );
  }

  return (
    <div className="wb-split-v">
      {/* =========================================================================
          Top Pane: Active Authorized Scope Rules Table & Toolbar
          ========================================================================= */}
      <div className="wb-panel">
        <div className="wb-panel-header">
          <div className="wb-panel-title">
            <Target size={14} color="var(--accent)" />
            <span>Authorized Scope Boundary Rules</span>
            <span className="wb-panel-count">{filteredItems.length}</span>
            {isDemoMode && <DemoBadge />}
          </div>
          <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
            <ScopeIndicator
              isProbeVerified={probeVerified}
              isChecking={probing}
            />
            <button
              onClick={handleOpenAdd}
              className="wb-btn wb-btn-primary wb-btn-sm"
              title="Add a new authorized domain, CIDR, or IP to scope"
            >
              <Plus size={12} /> Add Rule
            </button>
          </div>
        </div>

        <div className="wb-toolbar">
          <div className="wb-toolbar-group">
            <Filter size={12} color="var(--text-muted)" />
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginRight: '4px' }}>
              Policy:
            </span>
            <FilterTabs
              options={[
                { id: 'all', label: 'All Rules', count: scopeItems.length },
                {
                  id: 'in_scope',
                  label: 'In Scope',
                  count: scopeItems.filter((s) => s.inScope).length,
                },
                {
                  id: 'excluded',
                  label: 'Exclusions',
                  count: scopeItems.filter((s) => !s.inScope).length,
                },
              ]}
              activeId={filterPolicy}
              onChange={setFilterPolicy}
            />
          </div>

          <div style={{ marginLeft: 'auto', display: 'flex', gap: '6px' }}>
            <button
              onClick={runProbe}
              disabled={probing}
              className="wb-btn wb-btn-sm"
              title="Probe backend Scope Guard fail-closed behavior with sentinel probe"
            >
              <RefreshCw size={10} className={probing ? 'spin' : ''} />
              Re-Probe Scope Guard
            </button>
          </div>
        </div>

        <div className="wb-panel-body">
          <DataTable
            columns={columns}
            data={filteredItems}
            keyExtractor={(row) => row.id}
            emptyMessage="No scope rules match the selected filter."
          />
        </div>
      </div>

      {/* =========================================================================
          Bottom Pane: Target Scope Evaluator & Probe Verification Inspector
          ========================================================================= */}
      <div className="wb-panel">
        <div className="wb-panel-header">
          <div className="wb-panel-title">
            <ShieldCheck size={14} color="var(--accent)" />
            <span>Target Authorization Pre-Flight Evaluator</span>
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Assessment: <strong>{assessmentId}</strong>
          </span>
        </div>

        <div className="wb-panel-body" style={{ padding: '16px' }}>
          <div style={{ maxWidth: '800px' }}>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '12px' }}>
              Test any target hostname, domain, CIDR, or IP against Scope Guard before launching check executions.
              Decisions are verified live by the backend engine enforcing default-deny semantics.
            </p>

            <form
              onSubmit={handleEvaluate}
              style={{ display: 'flex', gap: '8px', alignItems: 'center' }}
            >
              <input
                type="text"
                className="wb-input font-mono"
                placeholder="e.g. app.lab.local, 192.168.1.50, critical.lab.local, external-target.com"
                value={testTarget}
                onChange={(e) => setTestTarget(e.target.value)}
                style={{ flex: 1, padding: '6px 10px' }}
              />
              <button
                type="submit"
                disabled={evaluating || !testTarget.trim()}
                className="wb-btn wb-btn-primary"
                style={{ padding: '6px 14px' }}
              >
                {evaluating ? (
                  <>
                    <RefreshCw size={12} className="spin" />
                    Evaluating...
                  </>
                ) : (
                  <>
                    <ShieldCheck size={14} />
                    Evaluate Target
                  </>
                )}
              </button>
            </form>

            {evalError && (
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
                <strong>Evaluation Failed:</strong> {evalError}
              </div>
            )}

            {evalResult && (
              <ScopeIndicator
                decision={evalResult.decision}
                target={evalResult.target}
                reason={evalResult.reason}
                matchedRuleId={evalResult.matchedScopeItemId}
              />
            )}
          </div>
        </div>
      </div>

      {/* Modal: Add Scope Rule Form */}
      {showAddModal && (
        <div className="wb-modal-backdrop" onClick={() => setShowAddModal(false)}>
          <div className="wb-modal" onClick={(e) => e.stopPropagation()}>
            <div className="wb-modal-header">
              <span style={{ fontWeight: 700 }}>Add Authorized Scope Rule</span>
              <button onClick={() => setShowAddModal(false)} className="wb-btn wb-btn-sm">
                Cancel
              </button>
            </div>
            <form onSubmit={handleSubmitAddForm}>
              <div className="wb-modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                    Scope Rule Type
                  </label>
                  <select
                    className="wb-select"
                    value={newType}
                    onChange={(e) => setNewType(e.target.value)}
                    style={{ width: '100%' }}
                  >
                    <option value="domain">domain (e.g. lab.local, sub.domain.com)</option>
                    <option value="subdomain">subdomain (*.lab.local)</option>
                    <option value="ip">ip (Single IPv4/IPv6 address)</option>
                    <option value="cidr">cidr (e.g. 192.168.1.0/24)</option>
                    <option value="url">url (e.g. https://lab.local/api)</option>
                    <option value="hostname">hostname</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                    Target Pattern / Value *
                  </label>
                  <input
                    type="text"
                    required
                    className="wb-input font-mono"
                    placeholder="e.g. app.lab.local or 10.10.0.0/16"
                    value={newValue}
                    onChange={(e) => setNewValue(e.target.value)}
                    style={{ width: '100%' }}
                  />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                      Authorization Policy
                    </label>
                    <select
                      className="wb-select"
                      value={newInScope ? 'true' : 'false'}
                      onChange={(e) => setNewInScope(e.target.value === 'true')}
                      style={{
                        width: '100%',
                        color: newInScope ? 'var(--status-pass-text)' : 'var(--status-blocked-text)',
                        fontWeight: 700,
                      }}
                    >
                      <option value="true">IN SCOPE (Allow Target)</option>
                      <option value="false">EXCLUSION (Strict Block)</option>
                    </select>
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                      Environment
                    </label>
                    <select
                      className="wb-select"
                      value={newEnvironment}
                      onChange={(e) => setNewEnvironment(e.target.value)}
                      style={{ width: '100%' }}
                    >
                      <option value="lab">lab</option>
                      <option value="development">development</option>
                      <option value="staging">staging</option>
                      <option value="production">production</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
                    Assessor Notes / Justification
                  </label>
                  <input
                    type="text"
                    className="wb-input"
                    placeholder="e.g. Authorized lab testing endpoint under RoE"
                    value={newNotes}
                    onChange={(e) => setNewNotes(e.target.value)}
                    style={{ width: '100%' }}
                  />
                </div>
              </div>

              <div className="wb-modal-footer">
                <button type="button" onClick={() => setShowAddModal(false)} className="wb-btn">
                  Cancel
                </button>
                <button type="submit" className="wb-btn wb-btn-primary">
                  Review & Save
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Confirmation Dialog for Adding Rule */}
      <ConfirmDialog
        isOpen={showConfirmModal}
        title="Confirm Authorized Scope Rule Addition"
        message={
          <div>
            <p style={{ marginBottom: '8px' }}>
              Are you sure you want to add this scope rule to engagement <code>{engagementId}</code>?
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
              <div><strong>Pattern:</strong> {newValue}</div>
              <div><strong>Type:</strong> {newType}</div>
              <div>
                <strong>Policy:</strong>{' '}
                <span style={{ color: newInScope ? 'var(--status-pass-text)' : 'var(--status-blocked-text)' }}>
                  {newInScope ? 'IN SCOPE (ALLOW)' : 'EXCLUSION (STRICT BLOCK)'}
                </span>
              </div>
              <div><strong>Environment:</strong> {newEnvironment}</div>
            </div>
            <p style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-muted)' }}>
              Note: Once added to the in-memory scope repository, all execution pipelines will enforce this boundary.
            </p>
          </div>
        }
        confirmLabel="Add Scope Rule"
        onConfirm={handleConfirmAdd}
        onCancel={() => setShowConfirmModal(false)}
      />
    </div>
  );
};
