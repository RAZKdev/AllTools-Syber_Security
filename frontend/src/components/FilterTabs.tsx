import React from 'react';

export interface FilterOption {
  id: string;
  label: string;
  count?: number;
}

interface FilterTabsProps {
  options: FilterOption[];
  activeId: string;
  onChange: (id: string) => void;
  size?: 'sm' | 'md';
}

export const FilterTabs: React.FC<FilterTabsProps> = ({
  options,
  activeId,
  onChange,
  size = 'sm',
}) => {
  return (
    <div
      style={{
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        gap: '3px',
        maxWidth: '100%',
      }}
    >
      {options.map((opt) => {
        const isActive = activeId === opt.id;
        return (
          <button
            key={opt.id}
            onClick={() => onChange(opt.id)}
            className={`wb-btn ${size === 'sm' ? 'wb-btn-sm' : ''}`}
            style={{
              background: isActive ? 'var(--bg-surface-active)' : 'transparent',
              borderColor: isActive ? 'var(--border-strong)' : 'transparent',
              color: isActive ? 'var(--accent)' : 'var(--text-muted)',
              fontWeight: isActive ? 700 : 500,
            }}
          >
            <span>{opt.label}</span>
            {opt.count !== undefined && (
              <span
                style={{
                  fontSize: '9px',
                  fontFamily: 'var(--font-mono)',
                  padding: '0 4px',
                  borderRadius: '2px',
                  backgroundColor: isActive ? 'var(--accent-muted)' : 'var(--bg-surface-elevated)',
                  color: isActive ? 'var(--accent)' : 'var(--text-secondary)',
                }}
              >
                {opt.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
};
