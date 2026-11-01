import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Database } from 'lucide-react';
import { ConnectionStatus, BackendConnectionState } from './ConnectionStatus';
import { ScopeGuardVerificationStatus } from '@/services/api';

interface StatusBarProps {
  connectionState: BackendConnectionState;
  isScopeGuardVerified: boolean;
  isScopeGuardChecking: boolean;
  scopeGuardStatus?: ScopeGuardVerificationStatus;
  scopeRulesCount: number;
  isDemoMode: boolean;
  onRefreshConnection: () => void;
}

export const StatusBar: React.FC<StatusBarProps> = ({
  connectionState,
  isScopeGuardVerified,
  isScopeGuardChecking,
  scopeGuardStatus,
  scopeRulesCount,
  isDemoMode,
  onRefreshConnection,
}) => {
  return (
    <footer className="wb-statusbar">
      <div className="wb-statusbar-group">
        {/* Scope Guard Status */}
        <div className="wb-statusbar-item">
          {isScopeGuardChecking ? (
            <>
              <span className="wb-status-dot warning" />
              <span style={{ color: 'var(--status-warn-text)' }}>Scope Guard: Probing...</span>
            </>
          ) : scopeGuardStatus === 'VERIFIED_ACTIVE' || isScopeGuardVerified ? (
            <>
              <ShieldCheck size={12} color="var(--status-pass-text)" />
              <span style={{ color: 'var(--status-pass-text)', fontWeight: 600 }}>
                Scope Guard: Enforcement Active (Dual-Verified)
              </span>
            </>
          ) : scopeGuardStatus === 'NO_ACTIVE_ALLOW_RULE' ? (
            <>
              <AlertTriangle size={12} color="#ffb74d" />
              <span style={{ color: '#ffb74d', fontWeight: 600 }}>
                Scope Guard: Default-Deny (No Allow Rules)
              </span>
            </>
          ) : (
            <>
              <ShieldAlert size={12} color="var(--status-blocked-text)" />
              <span style={{ color: 'var(--status-blocked-text)', fontWeight: 600 }}>
                Scope Guard: Unverified (Probe Pending/Offline)
              </span>
            </>
          )}
        </div>

        {/* Scope Rules Count */}
        <div className="wb-statusbar-item">
          <span>Target Rules:</span>
          <strong style={{ color: 'var(--text-primary)' }}>{scopeRulesCount}</strong>
        </div>

        {/* Mode Indicator */}
        <div className="wb-statusbar-item">
          {isDemoMode ? (
            <span style={{ color: '#ffb74d', fontWeight: 700 }}>[MODE: DEMO FIXTURE]</span>
          ) : (
            <span style={{ color: 'var(--status-pass-text)' }}>[MODE: LIVE API]</span>
          )}
        </div>
      </div>

      <div className="wb-statusbar-group">
        {/* Session In-Memory Advisory */}
        <div className="wb-statusbar-item" style={{ color: 'var(--text-muted)' }}>
          <Database size={11} />
          <span>Local In-Memory Repository</span>
        </div>

        {/* Connection Status */}
        <ConnectionStatus
          status={connectionState}
          onRefresh={onRefreshConnection}
        />
      </div>
    </footer>
  );
};
