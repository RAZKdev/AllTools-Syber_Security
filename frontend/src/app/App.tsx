import React, { useState, useEffect } from 'react';
import { Layout, ActiveTab } from '@/components/Layout';
import { DashboardPage } from '@/pages/DashboardPage';
import { ScopePage } from '@/pages/ScopePage';
import { ExecutionsPage } from '@/pages/ExecutionsPage';
import { FindingsPage } from '@/pages/FindingsPage';
import { ReportsPage } from '@/pages/ReportsPage';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<ActiveTab>('dashboard');

  useEffect(() => {
    // Heartbeat mechanism: periodically informs backend that the browser is open.
    // If the browser tab/window is closed, backend auto-terminates after a 3s window.
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

  return (
    <Layout
      currentTab={currentTab}
      onTabChange={setCurrentTab}
      activeEngagementName="Lab Engagement Alpha"
    >
      {currentTab === 'dashboard' && (
        <DashboardPage
          onNavigateToScope={() => setCurrentTab('scope')}
          onNavigateToExecutions={() => setCurrentTab('executions')}
        />
      )}

      {currentTab === 'scope' && <ScopePage />}

      {currentTab === 'executions' && <ExecutionsPage />}

      {currentTab === 'findings' && <FindingsPage />}

      {currentTab === 'reports' && <ReportsPage />}
    </Layout>
  );
};

export default App;
