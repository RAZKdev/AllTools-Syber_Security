import React from 'react';
import { AlertCircle, LogOut } from 'lucide-react';

interface DemoBannerProps {
  onExitDemo: () => void;
}

export const DemoBanner: React.FC<DemoBannerProps> = ({ onExitDemo }) => {
  return (
    <div className="wb-demo-banner">
      <div className="wb-demo-banner-left">
        <span className="wb-demo-badge">DEMO MODE</span>
        <AlertCircle size={14} />
        <span>
          <strong>DEMO DATA — NOT LIVE:</strong> Operating with isolated offline fixtures. Live targets and backend execution are disabled.
        </span>
      </div>
      <button
        onClick={onExitDemo}
        className="wb-btn wb-btn-sm"
        style={{ background: '#3d2500', borderColor: '#b36b00', color: '#ffe0b2' }}
        title="Exit Demo Mode and return to live backend data"
      >
        <LogOut size={12} />
        Exit Demo
      </button>
    </div>
  );
};
