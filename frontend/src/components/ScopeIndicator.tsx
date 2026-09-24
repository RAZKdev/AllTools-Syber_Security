import React from 'react';
import { ShieldCheck, ShieldAlert } from 'lucide-react';

interface ScopeIndicatorProps {
  decision: 'ALLOW' | 'BLOCK';
  target: string;
  reason?: string;
  matchedRuleId?: string;
}

export const ScopeIndicator: React.FC<ScopeIndicatorProps> = ({
  decision,
  target,
  reason,
  matchedRuleId,
}) => {
  const isAllowed = decision === 'ALLOW';

  return (
    <div
      style={{
        padding: '16px',
        borderRadius: '8px',
        backgroundColor: isAllowed ? 'var(--status-pass-bg)' : 'var(--status-blocked-bg)',
        border: `1px solid ${isAllowed ? 'var(--status-pass-border)' : 'var(--status-blocked-border)'}`,
        marginTop: '12px',
        marginBottom: '12px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
        {isAllowed ? (
          <ShieldCheck size={20} color="var(--status-pass-text)" />
        ) : (
          <ShieldAlert size={20} color="var(--status-blocked-text)" />
        )}
        <span
          style={{
            fontSize: '13px',
            fontWeight: 700,
            letterSpacing: '0.05em',
            fontFamily: 'var(--font-mono)',
            color: isAllowed ? 'var(--status-pass-text)' : 'var(--status-blocked-text)',
          }}
        >
          {isAllowed ? 'AUTHORIZED — IN SCOPE' : 'BLOCKED — OUT OF SCOPE'}
        </span>
      </div>

      <div style={{ fontSize: '13px', marginTop: '6px' }}>
        <div style={{ color: 'var(--text-secondary)', marginBottom: '4px' }}>
          <strong>Target:</strong> <code style={{ color: 'var(--text-primary)', marginLeft: '4px' }}>{target}</code>
        </div>
        {reason && (
          <div style={{ color: 'var(--text-secondary)' }}>
            <strong>Reason:</strong> <span style={{ color: 'var(--text-primary)', marginLeft: '4px' }}>{reason}</span>
          </div>
        )}
        {matchedRuleId && (
          <div style={{ color: 'var(--text-muted)', fontSize: '11px', marginTop: '6px', fontFamily: 'var(--font-mono)' }}>
            Rule Reference: {matchedRuleId}
          </div>
        )}
      </div>
    </div>
  );
};
