import React from 'react';
import { RefreshCw, WifiOff, AlertTriangle, Inbox, LucideIcon } from 'lucide-react';

export type StateKind = 'loading' | 'empty' | 'offline' | 'error';

interface StatePanelProps {
  kind: StateKind;
  title?: string;
  description?: string;
  icon?: LucideIcon;
  errorMessage?: string;
  onRetry?: () => void;
  action?: React.ReactNode;
}

export const StatePanel: React.FC<StatePanelProps> = ({
  kind,
  title,
  description,
  icon: CustomIcon,
  errorMessage,
  onRetry,
  action,
}) => {
  if (kind === 'loading') {
    return (
      <div className="wb-state-panel">
        <RefreshCw size={24} className="wb-state-icon spin" color="var(--accent)" />
        <div className="wb-state-title">{title || 'Loading operational data...'}</div>
        <div className="wb-state-desc">
          {description || 'Connecting to backend API endpoints and retrieving verified records.'}
        </div>
      </div>
    );
  }

  if (kind === 'offline') {
    return (
      <div className="wb-state-panel">
        <WifiOff size={28} className="wb-state-icon" color="var(--status-blocked-text)" />
        <div className="wb-state-title" style={{ color: 'var(--status-blocked-text)' }}>
          {title || 'Backend API Offline'}
        </div>
        <div className="wb-state-desc">
          {description ||
            'Cannot reach the local FastAPI server at http://127.0.0.1:8000. Ensure the backend process is running.'}
        </div>
        {errorMessage && (
          <code
            style={{
              fontSize: '10px',
              color: 'var(--text-muted)',
              background: 'var(--bg-table-zebra)',
              padding: '4px 8px',
              borderRadius: '3px',
              maxWidth: '80%',
              wordBreak: 'break-all',
            }}
          >
            {errorMessage}
          </code>
        )}
        {onRetry && (
          <button onClick={onRetry} className="wb-btn wb-btn-primary">
            <RefreshCw size={12} /> Retry Connection
          </button>
        )}
      </div>
    );
  }

  if (kind === 'error') {
    return (
      <div className="wb-state-panel">
        <AlertTriangle size={28} className="wb-state-icon" color="var(--status-error-text)" />
        <div className="wb-state-title" style={{ color: 'var(--status-error-text)' }}>
          {title || 'API Request Failed'}
        </div>
        <div className="wb-state-desc">
          {description || 'An unexpected error occurred while communicating with the backend API.'}
        </div>
        {errorMessage && (
          <code
            style={{
              fontSize: '10px',
              color: 'var(--status-error-text)',
              background: 'var(--status-error-bg)',
              border: '1px solid var(--status-error-border)',
              padding: '4px 8px',
              borderRadius: '3px',
              maxWidth: '80%',
              wordBreak: 'break-all',
            }}
          >
            {errorMessage}
          </code>
        )}
        {onRetry && (
          <button onClick={onRetry} className="wb-btn wb-btn-warning">
            <RefreshCw size={12} /> Retry Request
          </button>
        )}
      </div>
    );
  }

  // kind === 'empty'
  const Icon = CustomIcon || Inbox;
  return (
    <div className="wb-state-panel">
      <Icon size={26} className="wb-state-icon" />
      <div className="wb-state-title">{title || 'No records found'}</div>
      <div className="wb-state-desc">
        {description || 'No operational data is currently recorded in this session.'}
      </div>
      {action && <div style={{ marginTop: '8px' }}>{action}</div>}
    </div>
  );
};
