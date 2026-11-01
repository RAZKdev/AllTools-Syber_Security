import React from 'react';
import { RefreshCw } from 'lucide-react';

export type BackendConnectionState = 'connected' | 'checking' | 'offline' | 'error';

interface ConnectionStatusProps {
  status: BackendConnectionState;
  onRefresh?: () => void;
  latencyMs?: number;
}

export const ConnectionStatus: React.FC<ConnectionStatusProps> = ({
  status,
  onRefresh,
  latencyMs,
}) => {
  const getLabelAndDot = () => {
    switch (status) {
      case 'connected':
        return {
          dotClass: 'active',
          label: 'Connected',
          color: 'var(--status-pass-text)',
        };
      case 'checking':
        return {
          dotClass: 'warning',
          label: 'Checking...',
          color: 'var(--status-warn-text)',
        };
      case 'offline':
        return {
          dotClass: 'blocked',
          label: 'Offline',
          color: 'var(--status-blocked-text)',
        };
      case 'error':
      default:
        return {
          dotClass: 'blocked',
          label: 'API Error',
          color: 'var(--status-error-text)',
        };
    }
  };

  const current = getLabelAndDot();

  return (
    <div className="wb-statusbar-item" style={{ fontSize: '11px' }}>
      <span>Backend API:</span>
      <span className={`wb-status-dot ${current.dotClass}`} />
      <strong style={{ color: current.color }}>{current.label}</strong>
      {status === 'connected' && latencyMs !== undefined && (
        <span style={{ color: 'var(--text-muted)' }}>({latencyMs}ms)</span>
      )}
      {onRefresh && (
        <button
          onClick={onRefresh}
          className="wb-btn wb-btn-sm"
          style={{ padding: '1px 5px', marginLeft: '4px' }}
          title="Re-check backend API connectivity"
        >
          <RefreshCw size={10} className={status === 'checking' ? 'spin' : ''} />
        </button>
      )}
    </div>
  );
};
