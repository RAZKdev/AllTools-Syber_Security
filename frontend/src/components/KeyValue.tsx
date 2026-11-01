import React from 'react';

export interface KeyValueItem {
  key: string;
  value: React.ReactNode;
}

interface KeyValueProps {
  items: KeyValueItem[];
  keyWidth?: string;
}

export const KeyValue: React.FC<KeyValueProps> = ({ items, keyWidth = '140px' }) => {
  return (
    <div className="wb-kv-grid" style={{ gridTemplateColumns: `${keyWidth} 1fr` }}>
      {items.map((item, idx) => (
        <React.Fragment key={idx}>
          <div className="wb-kv-key">{item.key}</div>
          <div className="wb-kv-val">{item.value ?? '—'}</div>
        </React.Fragment>
      ))}
    </div>
  );
};
