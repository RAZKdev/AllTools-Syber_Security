import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { StatusBadge } from './StatusBadge';

describe('StatusBadge', () => {
  it.each([
    ['PASS', 'PASS'],
    ['fail', 'FAIL'],
    ['WARN', 'WARN'],
  ])('normalizes %s to %s', (status, label) => {
    render(<StatusBadge status={status} />);

    expect(screen.getByText(label)).toBeInTheDocument();
  });

  it('labels an out-of-scope block and explains why', () => {
    render(<StatusBadge status="BLOCKED_OUT_OF_SCOPE" />);

    expect(screen.getByText('BLOCKED')).toBeInTheDocument();
    expect(
      screen.getByLabelText('Blocked — target is outside the authorized scope'),
    ).toBeInTheDocument();
  });

  it('renders an unknown status in uppercase', () => {
    render(<StatusBadge status="custom_state" />);

    expect(screen.getByText('CUSTOM_STATE')).toBeInTheDocument();
  });

  it('renders NOT TESTED when the status is empty', () => {
    render(<StatusBadge status="" />);

    expect(screen.getByText('NOT TESTED')).toBeInTheDocument();
  });
});
