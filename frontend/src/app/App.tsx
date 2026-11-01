import React, { useCallback, useEffect, useRef, useState } from 'react';
import { AppShell, ActiveTab } from '@/components/AppShell';
import { BackendConnectionState } from '@/components/ConnectionStatus';
import {
  api,
  ApiError,
  Assessment,
  EnforcementStatus,
  Engagement,
} from '@/services/api';
import {
  DEMO_ASSESSMENT,
  DEMO_ENGAGEMENT,
  DEMO_SCOPE_ITEMS,
} from '@/demo/fixtures';
import { DashboardPage } from '@/pages/DashboardPage';
import { ScopePage } from '@/pages/ScopePage';
import { ExecutionsPage } from '@/pages/ExecutionsPage';
import { FindingsPage } from '@/pages/FindingsPage';
import { ReportsPage } from '@/pages/ReportsPage';

const VALID_TABS: ActiveTab[] = [
  'dashboard',
  'scope',
  'executions',
  'findings',
  'reports',
];

function isExpired(expiresAt?: string): boolean {
  if (!expiresAt) return false;
  const timestamp = Date.parse(expiresAt);
  return Number.isFinite(timestamp) && timestamp <= Date.now();
}

function pickAssessment(
  list: Assessment[],
  preferredId?: string | null,
): Assessment | null {
  if (preferredId) {
    const preferred = list.find((item) => item.id === preferredId);
    if (preferred) return preferred;
  }
  const running = list
    .filter((item) => item.status === 'RUNNING')
    .sort((a, b) => {
      const aTime = Date.parse(a.startedAt || a.createdAt || '');
      const bTime = Date.parse(b.startedAt || b.createdAt || '');
      return (Number.isFinite(bTime) ? bTime : 0) - (Number.isFinite(aTime) ? aTime : 0);
    });
  return running[0] || list[0] || null;
}

export const App: React.FC = () => {
  // Demo Mode is never activated by a URL parameter or a failed request.
  // It only turns on after an explicit user action in this session.
  const [isDemoMode, setIsDemoMode] = useState<boolean>(false);

  const [currentTab, setCurrentTab] = useState<ActiveTab>(() => {
    const tabParam = new URLSearchParams(window.location.search).get('tab');
    if (tabParam && VALID_TABS.includes(tabParam as ActiveTab)) {
      return tabParam as ActiveTab;
    }
    return 'dashboard';
  });

  // Backend connectivity
  const [connectionState, setConnectionState] =
    useState<BackendConnectionState>('checking');
  const [lastCheckedAt, setLastCheckedAt] = useState<Date | null>(null);

  // Scope Guard enforcement verification (separate from connectivity)
  const [enforcementStatus, setEnforcementStatus] =
    useState<EnforcementStatus>('not_checked');
  const [enforcementReason, setEnforcementReason] = useState<string>('');
  const isScopeGuardChecking = enforcementStatus === 'checking';

  // Workspace context
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [selectedEngagementId, setSelectedEngagementId] = useState<string | null>(
    null,
  );
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string | null>(
    null,
  );
  const [contextLoading, setContextLoading] = useState<boolean>(true);
  const [contextError, setContextError] = useState<string | null>(null);
  const [scopeRulesCount, setScopeRulesCount] = useState<number | null>(null);

  const [refreshNonce, setRefreshNonce] = useState<number>(0);
  const contextRequestId = useRef(0);
  const selectedEngagementIdRef = useRef<string | null>(null);
  const selectedAssessmentIdRef = useRef<string | null>(null);

  useEffect(() => {
    selectedEngagementIdRef.current = selectedEngagementId;
    selectedAssessmentIdRef.current = selectedAssessmentId;
  }, [selectedEngagementId, selectedAssessmentId]);

  const loadScopeSummary = useCallback(
    async (engagementId: string | null, demo: boolean) => {
      if (demo) {
        setScopeRulesCount(
          DEMO_SCOPE_ITEMS.filter(
            (item) => item.inScope && !isExpired(item.expiresAt),
          ).length,
        );
        return;
      }
      if (!engagementId) {
        setScopeRulesCount(null);
        return;
      }
      try {
        const items = await api.getScopeItems(engagementId);
        setScopeRulesCount(
          items.filter((item) => item.inScope && !isExpired(item.expiresAt)).length,
        );
      } catch {
        // An error is not zero rules. Keep the value unknown.
        setScopeRulesCount(null);
      }
    },
    [],
  );

  const loadWorkspaceContext = useCallback(
    async (options?: {
      engagementId?: string | null;
      assessmentId?: string | null;
      demo?: boolean;
    }) => {
      const demo = options?.demo ?? false;
      if (demo) {
        contextRequestId.current += 1;
        setEngagements([DEMO_ENGAGEMENT]);
        setAssessments([DEMO_ASSESSMENT]);
        setSelectedEngagementId(DEMO_ENGAGEMENT.id);
        setSelectedAssessmentId(DEMO_ASSESSMENT.id);
        setContextLoading(false);
        setContextError(null);
        await loadScopeSummary(DEMO_ENGAGEMENT.id, true);
        return;
      }

      const requestId = contextRequestId.current + 1;
      contextRequestId.current = requestId;
      setContextLoading(true);
      setContextError(null);

      try {
        const engagementList = await api.getEngagements();
        if (contextRequestId.current !== requestId) return;

        const preferredEngagement =
          engagementList.find(
            (item) =>
              item.id ===
              (options?.engagementId ||
                selectedEngagementIdRef.current ||
                undefined),
          ) ||
          engagementList.find((item) => item.status === 'ACTIVE') ||
          engagementList[0] ||
          null;

        if (!preferredEngagement) {
          setEngagements([]);
          setAssessments([]);
          setSelectedEngagementId(null);
          setSelectedAssessmentId(null);
          setScopeRulesCount(null);
          setContextLoading(false);
          return;
        }

        const assessmentList = await api.getAssessments(preferredEngagement.id);
        if (contextRequestId.current !== requestId) return;

        const preferredAssessment = pickAssessment(
          assessmentList,
          options?.assessmentId || selectedAssessmentIdRef.current,
        );

        setEngagements(engagementList);
        setAssessments(assessmentList);
        setSelectedEngagementId(preferredEngagement.id);
        setSelectedAssessmentId(preferredAssessment?.id || null);
        setContextLoading(false);
        await loadScopeSummary(preferredEngagement.id, false);
      } catch (err: any) {
        if (contextRequestId.current !== requestId) return;
        // Do not keep a stale context visible as if it were current.
        setEngagements([]);
        setAssessments([]);
        setSelectedEngagementId(null);
        setSelectedAssessmentId(null);
        setScopeRulesCount(null);
        setContextError(
          err?.message || 'Unable to load engagement and assessment context.',
        );
        setContextLoading(false);
      }
    },
    [loadScopeSummary],
  );

  const checkBackendHealth = useCallback(async () => {
    try {
      await api.getHealth();
      setConnectionState('connected');
      setLastCheckedAt(new Date());
    } catch (err) {
      setConnectionState(err instanceof ApiError ? 'api_error' : 'offline');
      setLastCheckedAt(new Date());
    }
  }, []);

  // Initial context + demo/live transition
  useEffect(() => {
    if (isDemoMode) {
      setConnectionState((current) => current);
      setEnforcementStatus('demo');
      setEnforcementReason('Demo Mode does not run enforcement probes.');
      loadWorkspaceContext({ demo: true });
      return;
    }
    setEnforcementStatus((current) =>
      current === 'demo' ? 'not_checked' : current,
    );
    loadWorkspaceContext({ demo: false });
  }, [isDemoMode, loadWorkspaceContext]);

  // Health polling: 15s while visible, plus an immediate check on focus.
  useEffect(() => {
    checkBackendHealth();
    const intervalId = window.setInterval(() => {
      if (!document.hidden) checkBackendHealth();
    }, 15000);
    const onVisibilityChange = () => {
      if (!document.hidden) checkBackendHealth();
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => {
      window.clearInterval(intervalId);
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [checkBackendHealth]);

  // Enforcement probe: live only, one active assessment, after connectivity is proven.
  useEffect(() => {
    if (isDemoMode) {
      setEnforcementStatus('demo');
      setEnforcementReason('Demo Mode does not run enforcement probes.');
      return;
    }
    if (connectionState !== 'connected') {
      setEnforcementStatus(
        connectionState === 'offline' || connectionState === 'api_error'
          ? 'unavailable'
          : 'not_checked',
      );
      setEnforcementReason(
        connectionState === 'offline' || connectionState === 'api_error'
          ? 'Enforcement cannot be verified while the backend is unreachable.'
          : '',
      );
      return;
    }
    if (!selectedAssessmentId) {
      setEnforcementStatus('not_checked');
      setEnforcementReason('No active assessment is available for the probe.');
      return;
    }

    let cancelled = false;
    setEnforcementStatus('checking');
    setEnforcementReason('');
    api.probeScopeGuard(selectedAssessmentId).then((result) => {
      if (cancelled) return;
      setEnforcementStatus(result.status);
      setEnforcementReason(result.reason);
    });
    return () => {
      cancelled = true;
    };
  }, [isDemoMode, connectionState, selectedAssessmentId, refreshNonce]);

  // Refresh the scope summary when the engagement context changes.
  useEffect(() => {
    if (isDemoMode) return;
    loadScopeSummary(selectedEngagementId, false);
  }, [isDemoMode, selectedEngagementId, refreshNonce, loadScopeSummary]);

  // Desktop launcher heartbeat & beforeunload shutdown preservation
  useEffect(() => {
    const sendHeartbeat = () => {
      fetch('/api/heartbeat', { method: 'POST' }).catch(() => {});
    };

    sendHeartbeat();
    const intervalId = window.setInterval(sendHeartbeat, 2500);

    const handleBeforeUnload = () => {
      if (navigator.sendBeacon) {
        navigator.sendBeacon('/api/shutdown');
      } else {
        fetch('/api/shutdown', { method: 'POST', keepalive: true }).catch(() => {});
      }
    };

    window.addEventListener('beforeunload', handleBeforeUnload);

    return () => {
      window.clearInterval(intervalId);
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, []);

  const handleTabChange = (tab: ActiveTab) => {
    setCurrentTab(tab);
    const url = new URL(window.location.href);
    url.searchParams.set('tab', tab);
    window.history.replaceState({}, '', url.toString());
  };

  const handleToggleDemo = () => {
    setIsDemoMode((previous) => !previous);
  };

  const handleSelectEngagement = (engagementId: string) => {
    setSelectedEngagementId(engagementId);
    setSelectedAssessmentId(null);
    loadWorkspaceContext({ engagementId, assessmentId: null });
  };

  const handleSelectAssessment = (assessmentId: string) => {
    setSelectedAssessmentId(assessmentId);
    setRefreshNonce((value) => value + 1);
  };

  const handleRefreshAll = () => {
    setRefreshNonce((value) => value + 1);
    checkBackendHealth();
    if (!isDemoMode) loadWorkspaceContext();
  };

  const selectedEngagement = isDemoMode
    ? DEMO_ENGAGEMENT
    : engagements.find((item) => item.id === selectedEngagementId) || null;
  const selectedAssessment = isDemoMode
    ? DEMO_ASSESSMENT
    : assessments.find((item) => item.id === selectedAssessmentId) || null;

  return (
    <AppShell
      currentTab={currentTab}
      onTabChange={handleTabChange}
      isDemoMode={isDemoMode}
      onToggleDemo={handleToggleDemo}
      connectionState={connectionState}
      lastCheckedAt={lastCheckedAt}
      enforcementStatus={enforcementStatus}
      enforcementReason={enforcementReason}
      isScopeGuardChecking={isScopeGuardChecking}
      onRefreshConnection={handleRefreshAll}
      scopeRulesCount={scopeRulesCount}
      engagements={isDemoMode ? [DEMO_ENGAGEMENT] : engagements}
      assessments={isDemoMode ? [DEMO_ASSESSMENT] : assessments}
      selectedEngagementId={selectedEngagementId}
      selectedAssessmentId={selectedAssessmentId}
      onSelectEngagement={handleSelectEngagement}
      onSelectAssessment={handleSelectAssessment}
      contextLoading={contextLoading}
      contextError={contextError}
      selectedEngagementName={selectedEngagement?.name || null}
      selectedAssessmentName={selectedAssessment?.name || null}
    >
      {currentTab === 'dashboard' && (
        <DashboardPage
          isDemoMode={isDemoMode}
          assessmentId={selectedAssessmentId}
          engagementId={selectedEngagementId}
          engagement={selectedEngagement}
          assessment={selectedAssessment}
          connectionState={connectionState}
          contextLoading={contextLoading}
          refreshToken={refreshNonce}
          onNavigateTab={handleTabChange}
        />
      )}

      {currentTab === 'scope' && (
        <ScopePage
          isDemoMode={isDemoMode}
          assessmentId={selectedAssessmentId}
          engagementId={selectedEngagementId}
          connectionState={connectionState}
          contextLoading={contextLoading}
          refreshToken={refreshNonce}
          onScopeUpdated={() => loadScopeSummary(selectedEngagementId, false)}
        />
      )}

      {currentTab === 'executions' && (
        <ExecutionsPage
          isDemoMode={isDemoMode}
          assessmentId={selectedAssessmentId}
          connectionState={connectionState}
          refreshToken={refreshNonce}
          onExecutionsChanged={() =>
            loadScopeSummary(selectedEngagementId, false)
          }
        />
      )}

      {currentTab === 'findings' && (
        <FindingsPage
          isDemoMode={isDemoMode}
          assessmentId={selectedAssessmentId}
          connectionState={connectionState}
          refreshToken={refreshNonce}
        />
      )}

      {currentTab === 'reports' && (
        <ReportsPage
          isDemoMode={isDemoMode}
          assessmentId={selectedAssessmentId}
          connectionState={connectionState}
          refreshToken={refreshNonce}
        />
      )}
    </AppShell>
  );
};

export default App;
