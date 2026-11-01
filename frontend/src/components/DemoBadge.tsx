import React from 'react';

export const DemoBadge: React.FC = () => {
  return (
    <span
      className="wb-chip"
      style={{
        background: 'rgba(255, 152, 0, 0.16)',
        color: '#ffb74d',
        border: '1px solid rgba(255, 152, 0, 0.4)',
      }}
      title="This record is loaded from demo fixture data"
    >
      DEMO
    </span>
  );
};
