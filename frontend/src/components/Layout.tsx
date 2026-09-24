import React from 'react';
import { Shield, LayoutDashboard, Target, PlayCircle, Settings, FileText, AlertTriangle } from 'lucide-react';

export type ActiveTab = 'dashboard' | 'scope' | 'executions' | 'findings' | 'reports';

interface LayoutProps {
  currentTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  activeEngagementName?: string;
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({
  currentTab,
  onTabChange,
  activeEngagementName = 'Lab Engagement Alpha',
  children,
}) => {
  const navItems = [
    { id: 'dashboard' as const, label: 'Dashboard', icon: LayoutDashboard },
    { id: 'scope' as const, label: 'Scope Guard', icon: Target },
    { id: 'executions' as const, label: 'Check Executions', icon: PlayCircle },
    { id: 'findings' as const, label: 'Findings & Risks', icon: AlertTriangle },
    { id: 'reports' as const, label: 'Reports & Audit', icon: FileText },
  ];

  return (
    <div style={{ display: 'flex', minHeight: '100vh', backgroundColor: 'var(--bg-canvas)' }}>
      {/* Sidebar */}
      <aside
        style={{
          width: '260px',
          backgroundColor: 'var(--bg-surface)',
          borderRight: '1px solid var(--border-subtle)',
          display: 'flex',
          flexDirection: 'column',
          flexShrink: 0,
        }}
      >
        {/* Brand Header */}
        <div
          style={{
            padding: '20px 24px',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
          }}
        >
          <div
            style={{
              width: '34px',
              height: '34px',
              borderRadius: '8px',
              backgroundColor: 'rgba(56, 189, 248, 0.1)',
              border: '1px solid rgba(56, 189, 248, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent)',
            }}
          >
            <Shield size={20} />
          </div>
          <div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '0.02em' }}>
              AllTools-CyberSec
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Defensive Workbench</div>
          </div>
        </div>

        {/* Scope Guard Status Pill */}
        <div style={{ padding: '16px 20px 12px 20px' }}>
          <div
            style={{
              padding: '10px 14px',
              borderRadius: '6px',
              backgroundColor: 'rgba(16, 185, 129, 0.08)',
              border: '1px solid rgba(16, 185, 129, 0.25)',
              display: 'flex',
              flexDirection: 'column',
              gap: '4px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span
                style={{
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--status-pass-text)',
                  boxShadow: '0 0 8px rgba(52, 211, 153, 0.6)',
                }}
              />
              <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--status-pass-text)', letterSpacing: '0.05em' }}>
                SCOPE GUARD ACTIVE
              </span>
            </div>
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
              Fail-Closed / Default Deny
            </span>
          </div>
        </div>

        {/* Navigation Menu */}
        <nav style={{ padding: '8px 12px', flex: 1 }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', padding: '8px 12px 4px 12px', letterSpacing: '0.05em' }}>
            OPERATIONS
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                style={{
                  width: '100%',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  padding: '10px 14px',
                  borderRadius: '6px',
                  fontSize: '13px',
                  fontWeight: isActive ? 600 : 500,
                  color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                  backgroundColor: isActive ? 'var(--bg-surface-elevated)' : 'transparent',
                  marginBottom: '2px',
                  borderLeft: isActive ? '3px solid var(--accent)' : '3px solid transparent',
                  transition: 'all 0.15s ease',
                  textAlign: 'left',
                }}
              >
                <Icon size={18} color={isActive ? 'var(--accent)' : 'var(--text-secondary)'} />
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Bottom Profile / Settings */}
        <div style={{ padding: '16px 20px', borderTop: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Settings size={16} color="var(--text-muted)" />
          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Defensive Mode: Authorized</span>
        </div>
      </aside>

      {/* Main Content Area */}
      <main style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, overflowY: 'auto' }}>
        {/* Top Navbar */}
        <header
          style={{
            height: '60px',
            backgroundColor: 'var(--bg-surface)',
            borderBottom: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0 32px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Active Engagement:</span>
            <span
              style={{
                fontSize: '13px',
                fontWeight: 600,
                color: 'var(--text-primary)',
                backgroundColor: 'var(--bg-surface-elevated)',
                padding: '4px 10px',
                borderRadius: '6px',
                border: '1px solid var(--border-default)',
              }}
            >
              {activeEngagementName}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontSize: '12px', color: 'var(--text-muted)' }}>
            <span>Backend API: <strong style={{ color: 'var(--status-pass-text)' }}>Connected</strong></span>
          </div>
        </header>

        {/* View Container */}
        <div style={{ padding: '32px', maxWidth: '1300px', width: '100%', margin: '0 auto', boxSizing: 'border-box' }}>
          {children}
        </div>
      </main>
    </div>
  );
};
