import React, { useState } from 'react';

export interface DetailTab {
  id: string;
  label: string;
  content: React.ReactNode;
}

interface DetailPanelProps {
  title: string;
  tabs: DetailTab[];
  actions?: React.ReactNode;
  defaultTabId?: string;
}

export const DetailPanel: React.FC<DetailPanelProps> = ({
  title,
  tabs,
  actions,
  defaultTabId,
}) => {
  const [activeTabId, setActiveTabId] = useState<string>(defaultTabId || tabs[0]?.id || '');

  const currentTab = tabs.find((t) => t.id === activeTabId) || tabs[0];

  return (
    <div className="wb-panel" style={{ height: '100%' }}>
      <div className="wb-panel-header">
        <div className="wb-panel-title">{title}</div>
        {actions && <div>{actions}</div>}
      </div>

      {tabs.length > 1 && (
        <div className="wb-subtabs">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              className={`wb-subtab ${activeTabId === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTabId(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>
      )}

      <div className="wb-panel-body" style={{ padding: '14px' }}>
        {currentTab ? currentTab.content : null}
      </div>
    </div>
  );
};
