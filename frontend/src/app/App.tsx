import React, { useState, useEffect, useCallback } from 'react';
import { AppShell, ActiveTab } from '@/components/AppShell';
import { BackendConnectionState } from '@/components/ConnectionStatus';
import { api, ScopeGuardVerificationStatus } from '@/services/api';
import { DEMO_SCOPE_ITEMS, DEMO_ENGAGEMENT } from '@/demo/fixtures';
import { DashboardPage } from '@/pages/DashboardPage';
import { ScopePage } from '@/pages/ScopePage';
import { ExecutionsPage } from '@/pages/ExecutionsPage';
import { FindingsPage } from '@/pages/FindingsPage';
import { ReportsPage } from '@/pages/ReportsPage';

export const App: React.FC = () => {
  // Mandate: Aplikasi selalu memulai dalam Live Mode (unless explicitly requested via URL param)
  const [isDemoMode, setIsDemoMode] = useState<boolean>(() => {
    return new URLSearchParams(window.location.search).get('demo') === 'true';
  });

  const [currentTab, setCurrentTab] = useState<ActiveTab>(() => {
    const tabParam = new URLSearchParams(window.location.search).get('tab');
    if (tabParam && ['dashboard', 'scope', 'executions', 'findings', 'reports'].includes(tabParam)) {
      return tabParam as ActiveTab;
    }
    return 'dashboard';
  });

  // Backend Connectivity & Scope Guard Probe State
  const [connectionState, setConnectionState] = useState<BackendConnectionState>('checking');
  const [isScopeGuardVerified, setIsScopeGuardVerified] = useState<boolean>(false);
  const [scopeGuardStatus, setScopeGuardStatus] = useState<ScopeGuardVerificationStatus>('CHECKING');
  const [isScopeGuardChecking, setIsScopeGuardChecking] = useState<boolean>(false);
  const [scopeRulesCount, setScopeRulesCount] = useState<number>(0);
  const [activeEngagementName, setActiveEngagementName] = useState<string>('Laboratory Defensive Security Assessment');

  // Verification & Health Check Logic
  const checkBackendHealth = useCallback(async () => {
    setConnectionState((prev) => (prev === 'connected' ? 'connected' : 'checking'));
    try {
      const health = await api.getHealth();
      if (health.status === 'healthy') {
        setConnectionState('connected');
      } else {
        setConnectionState('error');
      }
    } catch {
      setConnectionState('offline');
      setIsScopeGuardVerified(false);
      setScopeGuardStatus('UNVERIFIED');
    }
  }, []);

  const verifyScopeGuardProbe = useCallback(async () => {
    if (isDemoMode) {
      setIsScopeGuardVerified(true);
      setScopeGuardStatus('VERIFIED_ACTIVE');
      return;
    }

    setIsScopeGuardChecking(true);
    try {
      const probeResult = await api.probeScopeGuard('ASM-001');
      setIsScopeGuardVerified(probeResult.isVerified);
      setScopeGuardStatus(probeResult.status);
    } catch {
      setIsScopeGuardVerified(false);
      setScopeGuardStatus('UNVERIFIED');
    } finally {
      setIsScopeGuardChecking(false);
    }
  }, [isDemoMode]);

  const refreshScopeCount = useCallback(async () => {
    if (isDemoMode) {
      setScopeRulesCount(DEMO_SCOPE_ITEMS.length);
      setActiveEngagementName(DEMO_ENGAGEMENT.name);
      return;
    }

    try {
      const items = await api.getScopeItems();
      setScopeRulesCount(items.length);
      const engagements = await api.getEngagements();
      if (engagements.length > 0) {
        setActiveEngagementName(engagements[0].name);
      }
    } catch {
      setScopeRulesCount(0);
    }
  }, [isDemoMode]);

  // Initial mount verification
  useEffect(() => {
    checkBackendHealth();
    verifyScopeGuardProbe();
    refreshScopeCount();

    // Periodic connectivity & health check every 6s
    const healthInterval = setInterval(() => {
      checkBackendHealth();
    }, 6000);

    return () => clearInterval(healthInterval);
  }, [checkBackendHealth, verifyScopeGuardProbe, refreshScopeCount]);

  // Desktop launcher heartbeat & beforeunload shutdown preservation
  useEffect(() => {
    const sendHeartbeat = () => {
      fetch('/api/heartbeat', { method: 'POST' }).catch(() => {});
    };

    sendHeartbeat();
    const intervalId = setInterval(sendHeartbeat, 2500);

    const handleBeforeUnload = () => {
      if (navigator.sendBeacon) {
        navigator.sendBeacon('/api/shutdown');
      } else {
        fetch('/api/shutdown', { method: 'POST', keepalive: true }).catch(() => {});
      }
    };

    window.addEventListener('beforeunload', handleBeforeUnload);

    return () => {
      clearInterval(intervalId);
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, []);

  // Handle synchronized tab change
  const handleTabChange = (tab: ActiveTab) => {
    setCurrentTab(tab);
    const url = new URL(window.location.href);
    url.searchParams.set('tab', tab);
    window.history.replaceState({}, '', url.toString());
  };

  // Handle explicit demo toggle with synchronized URL parameter
  const handleToggleDemo = () => {
    setIsDemoMode((prev) => {
      const next = !prev;
      const url = new URL(window.location.href);
      if (next) {
        url.searchParams.set('demo', 'true');
      } else {
        url.searchParams.delete('demo');
      }
      window.history.replaceState({}, '', url.toString());
      return next;
    });
  };

  const handleRefreshAll = () => {
    checkBackendHealth();
    verifyScopeGuardProbe();
    refreshScopeCount();
  };

  return (
    <AppShell
      currentTab={currentTab}
      onTabChange={handleTabChange}
      activeEngagementName={activeEngagementName}
      isDemoMode={isDemoMode}
      onToggleDemo={handleToggleDemo}
      connectionState={connectionState}
      isScopeGuardVerified={isScopeGuardVerified}
      isScopeGuardChecking={isScopeGuardChecking}
      scopeGuardStatus={scopeGuardStatus}
      scopeRulesCount={scopeRulesCount}
      onRefreshConnection={handleRefreshAll}
    >
      {currentTab === 'dashboard' && (
        <DashboardPage
          isDemoMode={isDemoMode}
          onNavigateTab={handleTabChange}
        />
      )}

      {currentTab === 'scope' && (
        <ScopePage
          isDemoMode={isDemoMode}
          onScopeUpdated={refreshScopeCount}
        />
      )}

      {currentTab === 'executions' && (
        <ExecutionsPage isDemoMode={isDemoMode} />
      )}

      {currentTab === 'findings' && (
        <FindingsPage isDemoMode={isDemoMode} />
      )}

      {currentTab === 'reports' && (
        <ReportsPage isDemoMode={isDemoMode} />
      )}
    </AppShell>
  );
};

export default App;
