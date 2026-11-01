import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, ShieldOff, CircleSlash } from 'lucide-react';
import { EnforcementStatus } from '@/services/api';

interface ScopeIndicatorProps {
  decision?: 'ALLOW' | 'BLOCK';
  target?: string;
  reason?: string;
  matchedRuleId?: string;
  evaluatedAt?: string;
  probeStatus?: EnforcementStatus;
  probeReason?: string;
  isChecking?: boolean;
}

export const ScopeIndicator: React.FC<ScopeIndicatorProps> = ({
  decision,
  target,
  reason,
  matchedRuleId,
  evaluatedAt,
  probeStatus,
  probeReason,
  isChecking,
}) => {
  if (decision) {
    const isAllow = decision === 'ALLOW';
    return (
      <div
        className="wb-scope-result"
        style={{
          backgroundColor: isAllow
            ? 'var(--status-pass-bg)'
            : 'var(--status-blocked-bg)',
          border: `1px solid ${
            isAllow ? 'var(--status-pass-border)' : 'var(--status-blocked-border)'
          }`,
        }}
        role="status"
      >
        <div className="wb-scope-result-head">
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
                color: isAllow
                  ? 'var(--status-pass-text)'
                  : 'var(--status-blocked-text)',
              }}
            >
              BACKEND DECISION: {decision}
            </span>
          </div>
          {matchedRuleId && (
            <span className="wb-scope-result-meta">
              Rule: <strong>{matchedRuleId}</strong>
            </span>
          )}
        </div>

        {target && (
          <div className="wb-scope-result-meta">
            Target: <code style={{ color: 'var(--text-primary)' }}>{target}</code>
          </div>
        )}

        {reason && (
          <div className="wb-scope-result-reason">{reason}</div>
        )}

        {evaluatedAt && (
          <div className="wb-scope-result-meta">
            Evaluated: {new Date(evaluatedAt).toLocaleString()} (backend timestamp)
          </div>
        )}
      </div>
    );
  }

  if (isChecking) {
    return (
      <span className="wb-enforcement-inline" style={{ color: 'var(--status-warn-text)' }}>
        <AlertTriangle size={12} />
        Checking enforcement…
      </span>
    );
  }

  switch (probeStatus) {
    case 'default_deny_verified':
      return (
        <span
          className="wb-enforcement-inline"
          style={{ color: 'var(--status-pass-text)' }}
          title={
            probeReason ||
            'Backend returned BLOCK for the out-of-scope sentinel target.'
          }
        >
          <ShieldCheck size={13} />
          Default-deny verified
        </span>
      );
    case 'probe_allowed':
      return (
        <span
          className="wb-enforcement-inline"
          style={{ color: 'var(--status-blocked-text)' }}
          title={
            probeReason ||
            'The sentinel target was allowed; enforcement cannot be claimed.'
          }
        >
          <ShieldAlert size={13} />
          Enforcement unverified
        </span>
      );
    case 'unavailable':
      return (
        <span
          className="wb-enforcement-inline"
          style={{ color: 'var(--status-blocked-text)' }}
          title={probeReason || 'Enforcement probe could not reach the backend.'}
        >
          <ShieldOff size={13} />
          Enforcement unavailable
        </span>
      );
    case 'demo':
      return (
        <span
          className="wb-enforcement-inline"
          style={{ color: 'var(--text-muted)' }}
          title="Demo Mode does not run enforcement probes."
        >
          <CircleSlash size={13} />
          Enforcement: n/a (demo)
        </span>
      );
    default:
      return (
        <span
          className="wb-enforcement-inline"
          style={{ color: 'var(--text-muted)' }}
          title={probeReason || 'No enforcement probe has run for this assessment.'}
        >
          <CircleSlash size={13} />
          Enforcement not checked
        </span>
      );
  }
};
