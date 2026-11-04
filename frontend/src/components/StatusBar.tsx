import React from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Database,
  CircleSlash,
} from 'lucide-react';
import { ConnectionStatus, BackendConnectionState } from './ConnectionStatus';
import { EnforcementStatus } from '@/services/api';

interface StatusBarProps {
  connectionState: BackendConnectionState;
  lastCheckedAt: Date | null;
  enforcementStatus: EnforcementStatus;
  enforcementReason: string;
  isScopeGuardChecking: boolean;
  isDemoMode: boolean;
  assessmentId: string | null;
  assessmentName: string | null;
  engagementName: string | null;
  scopeRulesCount: number | null;
  onRefreshConnection: () => void;
}

const EnforcementIcon: React.FC<{
  status: EnforcementStatus;
}> = ({ status }) => {
  if (status === 'default_deny_verified') {
    return <ShieldCheck size={12} color="var(--status-pass-text)" />;
  }
  if (status === 'probe_allowed' || status === 'unavailable') {
    return <ShieldAlert size={12} color="var(--status-blocked-text)" />;
  }
  if (status === 'checking') {
    return <AlertTriangle size={12} color="var(--status-warn-text)" />;
  }
  return <CircleSlash size={12} color="var(--text-muted)" />;
};

function enforcementLabel(
  status: EnforcementStatus,
  isChecking: boolean,
): string {
  if (isChecking) return 'Checking…';
  switch (status) {
    case 'default_deny_verified':
      return 'Default-deny verified';
    case 'probe_allowed':
      return 'Not verified';
    case 'unavailable':
      return 'Unavailable';
    case 'demo':
      return 'n/a (demo)';
    case 'not_checked':
    default:
      return 'Not checked';
  }
}

export const StatusBar: React.FC<StatusBarProps> = ({
  connectionState,
  lastCheckedAt,
  enforcementStatus,
  enforcementReason,
  isScopeGuardChecking,
  isDemoMode,
  assessmentId,
  assessmentName,
  engagementName,
  scopeRulesCount,
  onRefreshConnection,
}) => {
  const enforcementText = enforcementLabel(
    enforcementStatus,
    isScopeGuardChecking,
  );
  const enforcementTone =
    enforcementStatus === 'default_deny_verified'
      ? 'var(--status-pass-text)'
      : enforcementStatus === 'probe_allowed' ||
          enforcementStatus === 'unavailable'
        ? 'var(--status-blocked-text)'
        : 'var(--text-secondary)';

  return (
    <footer className="wb-statusbar" aria-label="Workbench status">
      <div className="wb-statusbar-group">
        <div className="wb-statusbar-item">
          <span className={`wb-mode-chip ${isDemoMode ? 'demo' : 'live'}`}>
            {isDemoMode ? 'DEMO' : 'LIVE'}
          </span>
        </div>

        <ConnectionStatus
          status={connectionState}
          lastCheckedAt={lastCheckedAt}
          onRefresh={onRefreshConnection}
        />

        <div className="wb-statusbar-item wb-statusbar-assessment">
          <span>Assessment:</span>
          <strong title={assessmentName || undefined}>
            {assessmentId ||
              (connectionState === 'offline' || connectionState === 'api_error'
                ? 'Unavailable'
                : 'No assessment')}
          </strong>
          {assessmentName && (
            <span className="wb-statusbar-muted">({assessmentName})</span>
          )}
        </div>
      </div>

      <div className="wb-statusbar-group">
        <div
          className="wb-statusbar-item"
          style={{ color: enforcementTone }}
          title={
            enforcementReason ||
            'Enforcement status is separate from backend connectivity.'
          }
        >
          <EnforcementIcon status={enforcementStatus} />
          <span>Scope Guard: {enforcementText}</span>
        </div>

        <div className="wb-statusbar-item">
          <span>Scope rules:</span>
          <strong>{scopeRulesCount === null ? '—' : scopeRulesCount}</strong>
        </div>

        <div
          className="wb-statusbar-item"
          style={{ color: 'var(--text-muted)' }}
          title={
            isDemoMode
              ? 'Demo data comes from static fixtures and is never stored by the backend.'
              : engagementName
                ? `Engagement: ${engagementName}. Operational data is provided by backend-managed storage.`
                : 'Operational data is provided by backend-managed storage.'
          }
        >
          <Database size={11} />
          <span>
            {isDemoMode ? 'Storage: demo fixtures' : 'Storage: backend-managed'}
          </span>
        </div>

        <div className="wb-statusbar-item wb-statusbar-muted">
          <span>
            {lastCheckedAt
              ? `Checked ${lastCheckedAt.toLocaleTimeString()}`
              : 'Not checked yet'}
          </span>
        </div>
      </div>
    </footer>
  );
};
