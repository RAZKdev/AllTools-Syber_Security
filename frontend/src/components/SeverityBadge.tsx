import React from 'react';
import { Severity } from '@contracts/types';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const norm = (severity || 'informational').toLowerCase() as Severity;

  const styles: Record<Severity, { color: string; bg: string; border: string; label: string }> = {
    critical: {
      color: 'var(--sev-critical-text)',
      bg: 'var(--sev-critical-bg)',
      border: 'var(--sev-critical-border)',
      label: 'CRITICAL',
    },
    high: {
      color: 'var(--sev-high-text)',
      bg: 'var(--sev-high-bg)',
      border: 'var(--sev-high-border)',
      label: 'HIGH',
    },
    medium: {
      color: 'var(--sev-medium-text)',
      bg: 'var(--sev-medium-bg)',
      border: 'var(--sev-medium-border)',
      label: 'MEDIUM',
    },
    low: {
      color: 'var(--sev-low-text)',
      bg: 'var(--sev-low-bg)',
      border: 'var(--sev-low-border)',
      label: 'LOW',
    },
    informational: {
      color: 'var(--sev-info-text)',
      bg: 'var(--sev-info-bg)',
      border: 'var(--sev-info-border)',
      label: 'INFO',
    },
  };

  const current = styles[norm] || styles.informational;

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: size === 'sm' ? '2px 8px' : '4px 10px',
        borderRadius: '6px',
        fontSize: size === 'sm' ? '11px' : '12px',
        fontWeight: 700,
        fontFamily: 'var(--font-mono)',
        color: current.color,
        backgroundColor: current.bg,
        border: `1px solid ${current.border}`,
        letterSpacing: '0.04em',
      }}
    >
      {current.label}
    </span>
  );
};
