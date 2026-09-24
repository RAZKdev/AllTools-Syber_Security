import React, { useState } from 'react';
import { Layout, ActiveTab } from '@/components/Layout';
import { DashboardPage } from '@/pages/DashboardPage';
import { ScopePage } from '@/pages/ScopePage';
import { ExecutionsPage } from '@/pages/ExecutionsPage';
import { FindingsPage } from '@/pages/FindingsPage';
import { ReportsPage } from '@/pages/ReportsPage';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<ActiveTab>('dashboard');

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
