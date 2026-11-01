import React from 'react';

interface ToolbarProps {
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}

export const Toolbar: React.FC<ToolbarProps> = ({ children, className = '', style }) => {
  return (
    <div className={`wb-toolbar ${className}`} style={style}>
      {children}
    </div>
  );
};
