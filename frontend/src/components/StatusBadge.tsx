import React from 'react';
import { ExecutionStatus } from '@contracts/types';
import { CheckCircle2, XCircle, AlertTriangle, HelpCircle, ShieldAlert, ShieldX } from 'lucide-react';

interface StatusBadgeProps {
  status: ExecutionStatus | string;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'md' }) => {
  const normStatus = status.toUpperCase();

  const getStyleAndIcon = () => {
    switch (normStatus) {
      case 'PASS':
        return {
          color: 'var(--status-pass-text)',
          bg: 'var(--status-pass-bg)',
          border: 'var(--status-pass-border)',
          icon: <CheckCircle2 size={size === 'sm' ? 12 : 14} />,
          label: 'PASS',
        };
      case 'FAIL':
        return {
          color: 'var(--status-fail-text)',
          bg: 'var(--status-fail-bg)',
          border: 'var(--status-fail-border)',
          icon: <XCircle size={size === 'sm' ? 12 : 14} />,
          label: 'FAIL',
        };
      case 'WARN':
        return {
          color: 'var(--status-warn-text)',
          bg: 'var(--status-warn-bg)',
          border: 'var(--status-warn-border)',
          icon: <AlertTriangle size={size === 'sm' ? 12 : 14} />,
          label: 'WARN',
        };
      case 'BLOCKED_OUT_OF_SCOPE':
      case 'BLOCKED':
        return {
          color: 'var(--status-blocked-text)',
          bg: 'var(--status-blocked-bg)',
          border: 'var(--status-blocked-border)',
          icon: <ShieldX size={size === 'sm' ? 12 : 14} />,
          label: 'BLOCKED (OUT OF SCOPE)',
        };
      case 'ERROR':
        return {
          color: 'var(--status-error-text)',
          bg: 'var(--status-error-bg)',
          border: 'var(--status-error-border)',
          icon: <ShieldAlert size={size === 'sm' ? 12 : 14} />,
          label: 'ERROR',
        };
      case 'INSUFFICIENT_DATA':
        return {
          color: '#a78bfa',
          bg: 'rgba(167, 139, 250, 0.15)',
          border: 'rgba(167, 139, 250, 0.4)',
          icon: <HelpCircle size={size === 'sm' ? 12 : 14} />,
          label: 'INSUFFICIENT DATA',
        };
      default:
        return {
          color: 'var(--status-neutral-text)',
          bg: 'var(--status-neutral-bg)',
          border: 'var(--status-neutral-border)',
          icon: <HelpCircle size={size === 'sm' ? 12 : 14} />,
          label: normStatus || 'NOT TESTED',
        };
    }
  };

  const config = getStyleAndIcon();

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        padding: size === 'sm' ? '2px 8px' : '4px 10px',
        borderRadius: '6px',
        fontSize: size === 'sm' ? '11px' : '12px',
        fontWeight: 600,
        fontFamily: 'var(--font-mono)',
        color: config.color,
        backgroundColor: config.bg,
        border: `1px solid ${config.border}`,
        letterSpacing: '0.03em',
        whiteSpace: 'nowrap',
      }}
    >
      {config.icon}
      {config.label}
    </span>
  );
};
