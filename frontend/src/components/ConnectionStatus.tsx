import React from 'react';
import { RefreshCw } from 'lucide-react';

export type BackendConnectionState =
  | 'connected'
  | 'checking'
  | 'offline'
  | 'api_error';

interface ConnectionStatusProps {
  status: BackendConnectionState;
  onRefresh?: () => void;
  lastCheckedAt?: Date | null;
  compact?: boolean;
}

const LABELS: Record<BackendConnectionState, string> = {
  connected: 'Connected',
  checking: 'Checking…',
  offline: 'Offline',
  api_error: 'API error',
};

export const ConnectionStatus: React.FC<ConnectionStatusProps> = ({
  status,
  onRefresh,
  lastCheckedAt,
  compact = false,
}) => {
  const tone =
    status === 'connected'
      ? 'var(--status-pass-text)'
      : status === 'checking'
        ? 'var(--status-warn-text)'
        : 'var(--status-blocked-text)';
  const dotClass =
    status === 'connected'
      ? 'active'
      : status === 'checking'
        ? 'warning'
        : 'blocked';

  const timeLabel = lastCheckedAt
    ? `Last checked ${lastCheckedAt.toLocaleTimeString()}`
    : 'Not checked yet';

  return (
    <div
      className={`wb-connection ${compact ? 'wb-connection-compact' : ''}`}
      title={`${LABELS[status]} · ${timeLabel}`}
      aria-label={`Backend status: ${LABELS[status]}. ${timeLabel}.`}
      role="status"
    >
      <span className={`wb-status-dot ${dotClass}`} />
      <span style={{ color: tone, fontWeight: 600 }}>
        Backend: {LABELS[status]}
      </span>
      {!compact && <span className="wb-connection-time">{timeLabel}</span>}
      {onRefresh && (
        <button
          type="button"
          className="wb-icon-button"
          onClick={onRefresh}
          title="Re-check backend connection"
          aria-label="Re-check backend connection"
        >
          <RefreshCw size={11} className={status === 'checking' ? 'spin' : ''} />
        </button>
      )}
    </div>
  );
};
