import React, { useId, useState } from 'react';
import { PanelLeftClose, PanelLeftOpen } from 'lucide-react';

interface ContextSidebarProps {
  title: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
}

export const ContextSidebar: React.FC<ContextSidebarProps> = ({
  title,
  children,
  footer,
}) => {
  const [collapsed, setCollapsed] = useState(false);
  const panelId = useId();

  return (
    <aside
      className={`wb-context-sidebar ${collapsed ? 'collapsed' : ''}`}
      aria-label={`${title} context`}
    >
      <div className="wb-context-header">
        {!collapsed && <span className="wb-context-title">{title}</span>}
        <button
          type="button"
          className="wb-icon-button wb-context-toggle"
          onClick={() => setCollapsed((value) => !value)}
          aria-expanded={!collapsed}
          aria-controls={panelId}
          title={collapsed ? 'Expand context sidebar' : 'Collapse context sidebar'}
          aria-label={collapsed ? 'Expand context sidebar' : 'Collapse context sidebar'}
        >
          {collapsed ? <PanelLeftOpen size={14} /> : <PanelLeftClose size={14} />}
        </button>
      </div>

      <div className="wb-context-body" id={panelId} hidden={collapsed}>
        {children}
      </div>

      {!collapsed && footer && <div className="wb-context-footer">{footer}</div>}
    </aside>
  );
};
