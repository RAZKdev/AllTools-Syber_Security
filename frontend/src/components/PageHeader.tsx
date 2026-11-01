import React from 'react';
import { DemoBadge } from './DemoBadge';

interface PageHeaderProps {
  title: string;
  description?: string;
  actions?: React.ReactNode;
  meta?: React.ReactNode;
  isDemoMode?: boolean;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  title,
  description,
  actions,
  meta,
  isDemoMode = false,
}) => {
  return (
    <div className="wb-page-header">
      <div className="wb-page-header-main">
        <div className="wb-page-title-row">
          <h1 className="wb-page-title">{title}</h1>
          {isDemoMode && <DemoBadge />}
        </div>
        {description && <p className="wb-page-description">{description}</p>}
        {meta && <div className="wb-page-meta">{meta}</div>}
      </div>
      {actions && <div className="wb-page-header-actions">{actions}</div>}
    </div>
  );
};
