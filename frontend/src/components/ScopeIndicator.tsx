import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, ShieldOff } from 'lucide-react';
import { ScopeGuardVerificationStatus } from '@/services/api';

interface ScopeIndicatorProps {
  decision?: 'ALLOW' | 'BLOCK';
  target?: string;
  reason?: string;
  matchedRuleId?: string;
  isProbeVerified?: boolean;
  probeStatus?: ScopeGuardVerificationStatus;
  probeReason?: string;
  isChecking?: boolean;
}

export const ScopeIndicator: React.FC<ScopeIndicatorProps> = ({
  decision,
  target,
  reason,
  matchedRuleId,
  isProbeVerified,
  probeStatus,
  probeReason,
  isChecking,
}) => {
  // If rendering a full evaluation result for a tested target
  if (decision) {
    const isAllow = decision === 'ALLOW';
    return (
      <div
        style={{
          marginTop: '12px',
          padding: '12px 14px',
          borderRadius: '4px',
          backgroundColor: isAllow ? 'var(--status-pass-bg)' : 'var(--status-blocked-bg)',
          border: `1px solid ${isAllow ? 'var(--status-pass-border)' : 'var(--status-blocked-border)'}`,
          display: 'flex',
          flexDirection: 'column',
          gap: '6px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {isAllow ? (
              <ShieldCheck size={16} color="var(--status-pass-text)" />
            ) : (
              <ShieldAlert size={16} color="var(--status-blocked-text)" />
            )}
            <span
              style={{
                fontFamily: 'var(--font-mono)',
                fontWeight: 700,
                fontSize: '12px',
                color: isAllow ? 'var(--status-pass-text)' : 'var(--status-blocked-text)',
              }}
            >
              SCOPE DECISION: {decision}
            </span>
          </div>
          {matchedRuleId && (
            <span
              style={{
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
                color: 'var(--text-secondary)',
              }}
            >
              Rule: <strong>{matchedRuleId}</strong>
            </span>
          )}
        </div>

        {target && (
          <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
            Target: <code style={{ color: 'var(--text-primary)' }}>{target}</code>
          </div>
        )}

        {reason && (
          <div
            style={{
              fontSize: '11px',
              color: 'var(--text-primary)',
              lineHeight: 1.4,
              marginTop: '2px',
            }}
          >
            {reason}
          </div>
        )}
      </div>
    );
  }

  // If rendering status badge (Probe verified)
  if (isChecking) {
    return (
      <div
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '2px 8px',
          borderRadius: '3px',
          background: 'var(--bg-surface-elevated)',
          border: '1px solid var(--border-default)',
          fontSize: '11px',
          color: 'var(--status-warn-text)',
        }}
      >
        <AlertTriangle size={12} />
        <span>Verifying Scope Guard Probe...</span>
      </div>
    );
  }

  const activeVerified = probeStatus ? probeStatus === 'VERIFIED_ACTIVE' : isProbeVerified;

  if (activeVerified) {
    return (
      <div
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '2px 8px',
          borderRadius: '3px',
          background: 'var(--status-pass-bg)',
          border: '1px solid var(--status-pass-border)',
          fontSize: '11px',
          color: 'var(--status-pass-text)',
          fontWeight: 700,
        }}
        title={probeReason || 'Backend Scope Guard dual-assertion confirmed: In-scope target allowed & default-deny boundary active'}
      >
        <ShieldCheck size={13} />
        <span>SCOPE GUARD: ACTIVE (Dual-Verified)</span>
      </div>
    );
  }

  if (probeStatus === 'NO_ACTIVE_ALLOW_RULE') {
    return (
      <div
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '2px 8px',
          borderRadius: '3px',
          background: 'rgba(255, 152, 0, 0.12)',
          border: '1px solid #ff9800',
          fontSize: '11px',
          color: '#ffb74d',
          fontWeight: 600,
        }}
        title={probeReason || 'Default-deny active, but no active in-scope rule found to verify ALLOW path'}
      >
        <AlertTriangle size={13} />
        <span>SCOPE GUARD: DEFAULT-DENY (No Allow Rules)</span>
      </div>
    );
  }

  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        padding: '2px 8px',
        borderRadius: '3px',
        background: 'var(--status-blocked-bg)',
        border: '1px solid var(--status-blocked-border)',
        fontSize: '11px',
        color: 'var(--status-blocked-text)',
        fontWeight: 600,
      }}
      title={probeReason || 'Scope Guard enforcement unverified: Backend offline or probe failed'}
    >
      <ShieldOff size={13} />
      <span>SCOPE GUARD: UNVERIFIED</span>
    </div>
  );
};
