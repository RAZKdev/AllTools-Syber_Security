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
import {
  BackendConnectionState,
  ConnectionStatus,
} from './ConnectionStatus';
import { EnforcementStatus, Assessment, Engagement } from '@/services/api';

export type ActiveTab = 'dashboard' | 'scope' | 'executions' | 'findings' | 'reports';

interface AppShellProps {
  currentTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  isDemoMode: boolean;
  onToggleDemo: () => void;
  connectionState: BackendConnectionState;
  lastCheckedAt: Date | null;
  enforcementStatus: EnforcementStatus;
  enforcementReason: string;
  isScopeGuardChecking: boolean;
  onRefreshConnection: () => void;
  scopeRulesCount: number | null;
  engagements: Engagement[];
  assessments: Assessment[];
  selectedEngagementId: string | null;
  selectedAssessmentId: string | null;
  onSelectEngagement: (engagementId: string) => void;
  onSelectAssessment: (assessmentId: string) => void;
  contextLoading: boolean;
  contextError: string | null;
  selectedEngagementName: string | null;
  selectedAssessmentName: string | null;
  children: React.ReactNode;
}

const ENFORCEMENT_LABELS: Record<EnforcementStatus, string> = {
  not_checked: 'Enforcement not checked',
  checking: 'Checking enforcement…',
  default_deny_verified: 'Default-deny verified',
  probe_allowed: 'Enforcement unverified',
  unavailable: 'Enforcement unavailable',
  demo: 'n/a (demo)',
};

export const AppShell: React.FC<AppShellProps> = ({
  currentTab,
  onTabChange,
  isDemoMode,
  onToggleDemo,
  connectionState,
  lastCheckedAt,
  enforcementStatus,
  enforcementReason,
  isScopeGuardChecking,
  onRefreshConnection,
  scopeRulesCount,
  engagements,
  assessments,
  selectedEngagementId,
  selectedAssessmentId,
  onSelectEngagement,
  onSelectAssessment,
  contextLoading,
  contextError,
  selectedEngagementName,
  selectedAssessmentName,
  children,
}) => {
  const tabs = [
    { id: 'dashboard' as const, label: 'Dashboard', icon: LayoutDashboard },
    { id: 'scope' as const, label: 'Scope Guard', icon: Target },
    { id: 'executions' as const, label: 'Check Executions', icon: PlayCircle },
    { id: 'findings' as const, label: 'Findings & Risks', icon: AlertTriangle },
    { id: 'reports' as const, label: 'Reports & Audit', icon: FileText },
  ];

  const enforcementTone =
    enforcementStatus === 'default_deny_verified'
      ? 'var(--status-pass-text)'
      : enforcementStatus === 'probe_allowed' ||
          enforcementStatus === 'unavailable'
        ? 'var(--status-blocked-text)'
        : 'var(--text-muted)';

  const handleTabKeyDown = (
    event: React.KeyboardEvent<HTMLButtonElement>,
    index: number,
  ) => {
    let nextIndex: number | null = null;
    if (event.key === 'ArrowRight') nextIndex = (index + 1) % tabs.length;
    if (event.key === 'ArrowLeft')
      nextIndex = (index - 1 + tabs.length) % tabs.length;
    if (event.key === 'Home') nextIndex = 0;
    if (event.key === 'End') nextIndex = tabs.length - 1;
    if (nextIndex === null) return;
    event.preventDefault();
    const nextTab = tabs[nextIndex];
    onTabChange(nextTab.id);
    document.getElementById(`wb-tab-${nextTab.id}`)?.focus();
  };

  return (
    <div className="wb-shell">
      <header className="wb-topbar">
        <div className="wb-brand">
          <Shield size={18} color="var(--accent)" />
          <span>AllTools-CyberSec</span>
          <span className="wb-brand-badge">Defensive Workbench v0.1.0</span>
        </div>

        <div className="wb-topbar-context">
          <label className="wb-topbar-field">
            <span className="wb-topbar-label">Engagement</span>
            <select
              className="wb-select wb-topbar-select"
              aria-label="Active engagement"
              value={selectedEngagementId || ''}
              onChange={(event) => onSelectEngagement(event.target.value)}
              disabled={isDemoMode || contextLoading || engagements.length === 0}
            >
              {engagements.length === 0 && (
                <option value="">
                  {contextError
                    ? 'Context unavailable'
                    : contextLoading
                      ? 'Loading engagements…'
                      : 'No engagement available'}
                </option>
              )}
              {engagements.map((engagement) => (
                <option key={engagement.id} value={engagement.id}>
                  {engagement.id} · {engagement.name}
                </option>
              ))}
            </select>
          </label>

          <label className="wb-topbar-field">
            <span className="wb-topbar-label">Assessment</span>
            <select
              className="wb-select wb-topbar-select"
              aria-label="Active assessment"
              value={selectedAssessmentId || ''}
              onChange={(event) => onSelectAssessment(event.target.value)}
              disabled={isDemoMode || contextLoading || assessments.length === 0}
            >
              {assessments.length === 0 && (
                <option value="">
                  {contextError
                    ? 'Context unavailable'
                    : contextLoading
                      ? 'Loading assessments…'
                      : 'No assessment available'}
                </option>
              )}
              {assessments.map((assessment) => (
                <option key={assessment.id} value={assessment.id}>
                  {assessment.id} · {assessment.name}
                </option>
              ))}
            </select>
          </label>
          {contextError && !isDemoMode && (
            <span
              className="wb-topbar-context-error"
              title={contextError}
              role="status"
            >
              Context error
            </span>
          )}
        </div>

        <div className="wb-topbar-status">
          <ConnectionStatus
            status={connectionState}
            lastCheckedAt={lastCheckedAt}
            compact
            onRefresh={onRefreshConnection}
          />
          <span
            className="wb-enforcement-chip"
            style={{ color: enforcementTone }}
            title={enforcementReason || ENFORCEMENT_LABELS[enforcementStatus]}
          >
            <Shield size={11} />
            {ENFORCEMENT_LABELS[enforcementStatus]}
          </span>
        </div>

        <div className="wb-topbar-actions">
          {isDemoMode ? (
            <button
              onClick={onToggleDemo}
              className="wb-btn wb-btn-sm wb-btn-demo"
              title="Exit Demo Mode and return to live backend mode"
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

      <nav className="wb-tabbar" role="tablist" aria-label="Workbench sections">
        {tabs.map((tab, index) => {
          const Icon = tab.icon;
          const isActive = currentTab === tab.id;
          return (
            <button
              key={tab.id}
              id={`wb-tab-${tab.id}`}
              role="tab"
              aria-selected={isActive}
              aria-controls={`wb-panel-${tab.id}`}
              aria-current={isActive ? 'page' : undefined}
              tabIndex={isActive ? 0 : -1}
              className={`wb-tab ${isActive ? 'active' : ''}`}
              onClick={() => onTabChange(tab.id)}
              onKeyDown={(event) => handleTabKeyDown(event, index)}
            >
              <Icon
                size={14}
                color={isActive ? 'var(--accent)' : 'var(--text-secondary)'}
              />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Permanent banner, below the top navigation, whenever Demo Mode is active */}
      {isDemoMode && <DemoBanner onExitDemo={onToggleDemo} />}

      <main className="wb-workspace">
        <div
          className="wb-page-container"
          id={`wb-panel-${currentTab}`}
          role="tabpanel"
          aria-labelledby={`wb-tab-${currentTab}`}
        >
          {children}
        </div>
      </main>

      <StatusBar
        connectionState={connectionState}
        lastCheckedAt={lastCheckedAt}
        enforcementStatus={enforcementStatus}
        enforcementReason={enforcementReason}
        isScopeGuardChecking={isScopeGuardChecking}
        isDemoMode={isDemoMode}
        assessmentId={selectedAssessmentId}
        assessmentName={selectedAssessmentName}
        engagementName={selectedEngagementName}
        scopeRulesCount={scopeRulesCount}
        onRefreshConnection={onRefreshConnection}
      />
    </div>
  );
};
