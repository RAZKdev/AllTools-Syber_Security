import React, { useState, useEffect } from 'react';
import { Target, Plus, ShieldCheck, RefreshCw } from 'lucide-react';
import { api, ScopeItem, ScopeEvaluationResult } from '@/services/api';
import { ScopeIndicator } from '@/components/ScopeIndicator';

export const ScopePage: React.FC = () => {
  const [scopeItems, setScopeItems] = useState<ScopeItem[]>([]);
  const assessmentId = 'ASM-001';

  // Test target state
  const [testTarget, setTestTarget] = useState('');
  const [evalResult, setEvalResult] = useState<ScopeEvaluationResult | null>(null);
  const [evaluating, setEvaluating] = useState(false);

  // New scope item state
  const [showAddForm, setShowAddForm] = useState(false);
  const [newType, setNewType] = useState('domain');
  const [newValue, setNewValue] = useState('');
  const [newInScope, setNewInScope] = useState(true);
  const [newEnvironment, setNewEnvironment] = useState('lab');
  const [newNotes, setNewNotes] = useState('');

  // Default sample items if backend empty
  const defaultItems: ScopeItem[] = [
    { id: 'SCP-001', engagementId: 'ENG-001', type: 'domain', value: 'lab.local', environment: 'lab', inScope: true, notes: 'Local laboratory domain' },
    { id: 'SCP-002', engagementId: 'ENG-001', type: 'cidr', value: '192.168.1.0/24', environment: 'lab', inScope: true, notes: 'Internal test subnet' },
    { id: 'SCP-003', engagementId: 'ENG-001', type: 'domain', value: 'critical.lab.local', environment: 'production', inScope: false, notes: 'Strictly excluded sensitive management host' },
  ];

  const fetchScope = async () => {
    try {
      const items = await api.getScopeItems();
      if (items && items.length > 0) {
        setScopeItems(items);
      } else {
        setScopeItems(defaultItems);
      }
    } catch {
      setScopeItems(defaultItems);
    }
  };

  useEffect(() => {
    fetchScope();
  }, []);

  const handleEvaluate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!testTarget.trim()) return;

    setEvaluating(true);
    try {
      const res = await api.evaluateScope(assessmentId, testTarget.trim());
      setEvalResult(res);
    } catch {
      // Local fallback simulation if backend is not running yet during hot reload
      const cleanTarget = testTarget.trim().toLowerCase();
      let decision: 'ALLOW' | 'BLOCK' = 'BLOCK';
      let reason = 'Target does not match any active authorized scope rule for this assessment.';
      let matchedId: string | undefined = undefined;

      // Check explicit exclusions first
      for (const item of scopeItems) {
        if (!item.inScope && cleanTarget.includes(item.value.toLowerCase())) {
          decision = 'BLOCK';
          reason = `Target explicitly excluded by scope rule '${item.id}' (${item.type}: ${item.value}).`;
          matchedId = item.id;
          break;
        }
      }

      if (decision !== 'BLOCK') {
        for (const item of scopeItems) {
          if (item.inScope && (cleanTarget === item.value.toLowerCase() || cleanTarget.endsWith(`.${item.value.toLowerCase()}`))) {
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
    } finally {
      setEvaluating(false);
    }
  };

  const handleAddItem = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newValue.trim()) return;

    const newItem: Partial<ScopeItem> = {
      engagementId: 'ENG-001',
      type: newType,
      value: newValue.trim(),
      environment: newEnvironment,
      inScope: newInScope,
      notes: newNotes.trim() || undefined,
    };

    try {
      const created = await api.createScopeItem(newItem);
      setScopeItems([...scopeItems, created]);
    } catch {
      // Local add fallback
      const localCreated: ScopeItem = {
        id: `SCP-${Math.floor(100 + Math.random() * 900)}`,
        engagementId: 'ENG-001',
        type: newType,
        value: newValue.trim(),
        environment: newEnvironment,
        inScope: newInScope,
        notes: newNotes.trim() || undefined,
      };
      setScopeItems([...scopeItems, localCreated]);
    }

    setNewValue('');
    setNewNotes('');
    setShowAddForm(false);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      {/* Header */}
      <div>
        <h1 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)' }}>
          Scope Guard Enforcement Engine
        </h1>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px' }}>
          Defines authorized assessment boundaries. Out-of-scope executions are blocked by default (fail-closed).
        </p>
      </div>

      {/* Target Evaluation Interactive Sandbox */}
      <div
        style={{
          padding: '24px',
          borderRadius: '8px',
          backgroundColor: 'var(--bg-surface)',
          border: '1px solid var(--border-default)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '14px' }}>
          <Target size={18} color="var(--accent)" />
          <h2 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Live Target Scope Simulator
          </h2>
        </div>
        <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
          Verify whether an IP, domain, URL, or host will pass Scope Guard authorization before executing any security tool.
        </p>

        <form onSubmit={handleEvaluate} style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <input
            type="text"
            placeholder="e.g. app.lab.local, 192.168.1.50, critical.lab.local, evil.com"
            value={testTarget}
            onChange={(e) => setTestTarget(e.target.value)}
            style={{
              flex: 1,
              padding: '10px 14px',
              borderRadius: '6px',
              backgroundColor: 'var(--bg-canvas)',
              border: '1px solid var(--border-default)',
              color: 'var(--text-primary)',
              fontSize: '13px',
              fontFamily: 'var(--font-mono)',
              outline: 'none',
            }}
          />
          <button
            type="submit"
            disabled={evaluating || !testTarget.trim()}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '10px 20px',
              borderRadius: '6px',
              backgroundColor: 'var(--accent)',
              color: '#090d16',
              fontSize: '13px',
              fontWeight: 600,
              opacity: evaluating || !testTarget.trim() ? 0.6 : 1,
            }}
          >
            {evaluating ? <RefreshCw size={14} className="spin" /> : <ShieldCheck size={16} />}
            Evaluate Scope
          </button>
        </form>

        {evalResult && (
          <ScopeIndicator
            decision={evalResult.decision}
            target={evalResult.target}
            reason={evalResult.reason}
            matchedRuleId={evalResult.matchedScopeItemId}
          />
        )}
      </div>

      {/* Scope Rules Table */}
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
              Active Authorized Scope Rules ({scopeItems.length})
            </h2>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              Rules with <code>inScope=false</code> take absolute priority and strictly exclude matching targets.
            </p>
          </div>
          <button
            onClick={() => setShowAddForm(!showAddForm)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '6px 12px',
              borderRadius: '6px',
              backgroundColor: 'var(--bg-surface-elevated)',
              border: '1px solid var(--border-default)',
              color: 'var(--text-primary)',
              fontSize: '12px',
              fontWeight: 600,
            }}
          >
            <Plus size={14} /> Add Scope Rule
          </button>
        </div>

        {/* Add Rule Form Modal / Inline */}
        {showAddForm && (
          <form
            onSubmit={handleAddItem}
            style={{
              padding: '20px',
              backgroundColor: 'var(--bg-surface-elevated)',
              borderBottom: '1px solid var(--border-subtle)',
              display: 'flex',
              flexWrap: 'wrap',
              gap: '12px',
              alignItems: 'flex-end',
            }}
          >
            <div>
              <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>Type</label>
              <select
                value={newType}
                onChange={(e) => setNewType(e.target.value)}
                style={{
                  padding: '8px 12px',
                  borderRadius: '6px',
                  backgroundColor: 'var(--bg-surface)',
                  border: '1px solid var(--border-default)',
                  color: 'var(--text-primary)',
                  fontSize: '13px',
                }}
              >
                <option value="domain">domain</option>
                <option value="subdomain">subdomain</option>
                <option value="ip">ip</option>
                <option value="cidr">cidr</option>
                <option value="url">url</option>
                <option value="hostname">hostname</option>
              </select>
            </div>

            <div style={{ flex: 1, minWidth: '200px' }}>
              <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>Target Value / Pattern</label>
              <input
                type="text"
                placeholder="e.g. *.corp.local or 10.0.0.0/16"
                value={newValue}
                onChange={(e) => setNewValue(e.target.value)}
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  backgroundColor: 'var(--bg-surface)',
                  border: '1px solid var(--border-default)',
                  color: 'var(--text-primary)',
                  fontSize: '13px',
                  fontFamily: 'var(--font-mono)',
                  boxSizing: 'border-box',
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>Policy</label>
              <select
                value={newInScope ? 'true' : 'false'}
                onChange={(e) => setNewInScope(e.target.value === 'true')}
                style={{
                  padding: '8px 12px',
                  borderRadius: '6px',
                  backgroundColor: 'var(--bg-surface)',
                  border: '1px solid var(--border-default)',
                  color: newInScope ? 'var(--status-pass-text)' : 'var(--status-blocked-text)',
                  fontWeight: 600,
                  fontSize: '13px',
                }}
              >
                <option value="true">IN SCOPE (Allow)</option>
                <option value="false">EXCLUSION (Strict Block)</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>Environment</label>
              <select
                value={newEnvironment}
                onChange={(e) => setNewEnvironment(e.target.value)}
                style={{
                  padding: '8px 12px',
                  borderRadius: '6px',
                  backgroundColor: 'var(--bg-surface)',
                  border: '1px solid var(--border-default)',
                  color: 'var(--text-primary)',
                  fontSize: '13px',
                }}
              >
                <option value="lab">lab</option>
                <option value="development">development</option>
                <option value="staging">staging</option>
                <option value="production">production</option>
              </select>
            </div>

            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                type="submit"
                style={{
                  padding: '8px 16px',
                  borderRadius: '6px',
                  backgroundColor: 'var(--accent)',
                  color: '#090d16',
                  fontSize: '13px',
                  fontWeight: 600,
                }}
              >
                Save Rule
              </button>
              <button
                type="button"
                onClick={() => setShowAddForm(false)}
                style={{
                  padding: '8px 14px',
                  borderRadius: '6px',
                  backgroundColor: 'transparent',
                  border: '1px solid var(--border-default)',
                  color: 'var(--text-secondary)',
                  fontSize: '13px',
                }}
              >
                Cancel
              </button>
            </div>
          </form>
        )}

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
            <thead>
              <tr style={{ backgroundColor: 'var(--bg-surface-elevated)', color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-subtle)' }}>
                <th style={{ padding: '12px 20px', fontWeight: 600 }}>Rule ID</th>
                <th style={{ padding: '12px 20px', fontWeight: 600 }}>Type</th>
                <th style={{ padding: '12px 20px', fontWeight: 600 }}>Target Value</th>
                <th style={{ padding: '12px 20px', fontWeight: 600 }}>Policy</th>
                <th style={{ padding: '12px 20px', fontWeight: 600 }}>Environment</th>
                <th style={{ padding: '12px 20px', fontWeight: 600 }}>Notes</th>
              </tr>
            </thead>
            <tbody>
              {scopeItems.map((item) => (
                <tr key={item.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '12px 20px', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                    {item.id}
                  </td>
                  <td style={{ padding: '12px 20px', fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>
                    {item.type}
                  </td>
                  <td style={{ padding: '12px 20px', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', fontWeight: 600 }}>
                    {item.value}
                  </td>
                  <td style={{ padding: '12px 20px' }}>
                    <span
                      style={{
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: 700,
                        fontFamily: 'var(--font-mono)',
                        backgroundColor: item.inScope ? 'var(--status-pass-bg)' : 'var(--status-blocked-bg)',
                        color: item.inScope ? 'var(--status-pass-text)' : 'var(--status-blocked-text)',
                      }}
                    >
                      {item.inScope ? 'IN SCOPE' : 'EXCLUDED'}
                    </span>
                  </td>
                  <td style={{ padding: '12px 20px', color: 'var(--text-secondary)' }}>
                    {item.environment || 'unknown'}
                  </td>
                  <td style={{ padding: '12px 20px', color: 'var(--text-muted)' }}>
                    {item.notes || '—'}
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
