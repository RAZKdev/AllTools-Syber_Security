import React from 'react';
import {
  Shield,
  LayoutDashboard,
  Target,
  PlayCircle,
  AlertTriangle,
  FileText,
  Sparkles,
  LogOut,
} from 'lucide-react';
import { DemoBanner } from './DemoBanner';
import { StatusBar } from './StatusBar';
import { BackendConnectionState } from './ConnectionStatus';
import { ScopeGuardVerificationStatus } from '@/services/api';

export type ActiveTab = 'dashboard' | 'scope' | 'executions' | 'findings' | 'reports';

interface AppShellProps {
  currentTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  activeEngagementName: string;
  isDemoMode: boolean;
  onToggleDemo: () => void;
  connectionState: BackendConnectionState;
  isScopeGuardVerified: boolean;
  isScopeGuardChecking: boolean;
  scopeGuardStatus?: ScopeGuardVerificationStatus;
  scopeRulesCount: number;
  onRefreshConnection: () => void;
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({
  currentTab,
  onTabChange,
  activeEngagementName,
  isDemoMode,
  onToggleDemo,
  connectionState,
  isScopeGuardVerified,
  isScopeGuardChecking,
  scopeGuardStatus,
  scopeRulesCount,
  onRefreshConnection,
  children,
}) => {
  const tabs = [
    { id: 'dashboard' as const, label: 'Dashboard', icon: LayoutDashboard },
    { id: 'scope' as const, label: 'Target Scope', icon: Target },
    { id: 'executions' as const, label: 'Check Executions', icon: PlayCircle },
    { id: 'findings' as const, label: 'Issue Activity', icon: AlertTriangle },
    { id: 'reports' as const, label: 'Reports & Audit', icon: FileText },
  ];

  return (
    <div className="wb-shell">
      {/* Permanent high-contrast banner when Demo Mode is active */}
      {isDemoMode && <DemoBanner onExitDemo={onToggleDemo} />}

      {/* Top Application / Brand Bar */}
      <header className="wb-topbar">
        <div className="wb-brand">
          <Shield size={18} color="var(--accent)" />
          <span>AllTools-CyberSec</span>
          <span className="wb-brand-badge">Defensive Workbench v0.1.0</span>
        </div>

        <div className="wb-topbar-center">
          <span>Active Engagement:</span>
          <span className="wb-engagement-pill">{activeEngagementName}</span>
        </div>

        <div className="wb-topbar-actions">
          {/* Explicit Demo Mode Button */}
          {isDemoMode ? (
            <button
              onClick={onToggleDemo}
              className="wb-btn wb-btn-sm"
              style={{
                background: 'rgba(255, 152, 0, 0.16)',
                borderColor: '#ff9800',
                color: '#ffb74d',
              }}
              title="Exit Demo Mode and return to Live backend mode"
            >
              <LogOut size={12} />
              Exit Demo
            </button>
          ) : (
            <button
              onClick={onToggleDemo}
              className="wb-btn wb-btn-sm"
              title="Load isolated offline demonstration fixtures"
            >
              <Sparkles size={12} color="#ffb74d" />
              Load Demo
            </button>
          )}
        </div>
      </header>

      {/* Top Navigation Tabs (Burp Suite Professional Style) */}
      <nav className="wb-tabbar">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = currentTab === tab.id;
          return (
            <button
              key={tab.id}
              className={`wb-tab ${isActive ? 'active' : ''}`}
              onClick={() => onTabChange(tab.id)}
            >
              <Icon size={14} color={isActive ? 'var(--accent)' : 'var(--text-secondary)'} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Main Workspace Window */}
      <main className="wb-workspace">
        <div className="wb-page-container">{children}</div>
      </main>

      {/* Bottom Status Bar */}
      <StatusBar
        connectionState={connectionState}
        isScopeGuardVerified={isScopeGuardVerified}
        isScopeGuardChecking={isScopeGuardChecking}
        scopeGuardStatus={scopeGuardStatus}
        scopeRulesCount={scopeRulesCount}
        isDemoMode={isDemoMode}
        onRefreshConnection={onRefreshConnection}
      />
    </div>
  );
};
