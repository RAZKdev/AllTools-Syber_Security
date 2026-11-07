import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { Severity } from '@contracts/types';
import { SeverityBadge } from './SeverityBadge';

describe('SeverityBadge', () => {
  it.each([
    ['critical', 'CRITICAL'],
    ['high', 'HIGH'],
    ['medium', 'MEDIUM'],
    ['low', 'LOW'],
    ['informational', 'INFO'],
  ] as const)('renders %s as %s', (severity, label) => {
    render(<SeverityBadge severity={severity} />);

    expect(screen.getByText(label)).toBeInTheDocument();
  });

  it('falls back to INFO for an unknown severity', () => {
    render(<SeverityBadge severity={'unknown' as Severity} />);

    expect(screen.getByText('INFO')).toBeInTheDocument();
  });
});
