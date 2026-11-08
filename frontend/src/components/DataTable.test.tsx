import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { DataTable, type DataTableColumn } from './DataTable';

interface Row {
  id: string;
  name: string;
  status?: string | null;
}

const columns: DataTableColumn<Row>[] = [
  { key: 'name', label: 'Name' },
  { key: 'status', label: 'Status' },
];

const rows: Row[] = [
  { id: 'row-1', name: 'Alpha', status: 'PASS' },
  { id: 'row-2', name: 'Beta', status: null },
];

describe('DataTable', () => {
  it('renders the default empty message when there are no rows', () => {
    render(
      <DataTable
        columns={columns}
        data={[]}
        keyExtractor={(row) => row.id}
      />,
    );

    expect(screen.getByText('No records recorded.')).toBeInTheDocument();
  });

  it('renders a custom empty message', () => {
    render(
      <DataTable
        columns={columns}
        data={[]}
        keyExtractor={(row) => row.id}
        emptyMessage="Nothing here yet."
      />,
    );

    expect(screen.getByText('Nothing here yet.')).toBeInTheDocument();
  });

  it('renders headers, cell values, and an em dash for missing values', () => {
    render(
      <DataTable
        columns={columns}
        data={rows}
        keyExtractor={(row) => row.id}
      />,
    );

    expect(screen.getByRole('columnheader', { name: 'Name' })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: 'Status' })).toBeInTheDocument();
    expect(screen.getByText('Alpha')).toBeInTheDocument();
    expect(screen.getByText('PASS')).toBeInTheDocument();
    expect(screen.getByText('—')).toBeInTheDocument();
  });

  it('selects a row on click when selection is enabled', async () => {
    const user = userEvent.setup();
    const onSelectRow = vi.fn();

    render(
      <DataTable
        columns={columns}
        data={rows}
        keyExtractor={(row) => row.id}
        onSelectRow={onSelectRow}
      />,
    );

    await user.click(screen.getByRole('button', { name: /Alpha/ }));

    expect(onSelectRow).toHaveBeenCalledTimes(1);
    expect(onSelectRow).toHaveBeenCalledWith(rows[0]);
  });

  it('selects a row with Enter and Space', async () => {
    const user = userEvent.setup();
    const onSelectRow = vi.fn();

    render(
      <DataTable
        columns={columns}
        data={rows}
        keyExtractor={(row) => row.id}
        onSelectRow={onSelectRow}
      />,
    );

    const row = screen.getByRole('button', { name: /Alpha/ });
    row.focus();

    await user.keyboard('{Enter}');
    await user.keyboard(' ');

    expect(onSelectRow).toHaveBeenCalledTimes(2);
    expect(onSelectRow).toHaveBeenNthCalledWith(1, rows[0]);
    expect(onSelectRow).toHaveBeenNthCalledWith(2, rows[0]);
  });

  it('does not make rows interactive without a selection handler', () => {
    render(
      <DataTable
        columns={columns}
        data={rows}
        keyExtractor={(row) => row.id}
      />,
    );

    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('marks the selected row with aria-selected', () => {
    render(
      <DataTable
        columns={columns}
        data={rows}
        keyExtractor={(row) => row.id}
        selectedId="row-1"
        onSelectRow={vi.fn()}
      />,
    );

    expect(screen.getByRole('button', { name: /Alpha/ })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    expect(screen.getByRole('button', { name: /Beta/ })).toHaveAttribute(
      'aria-selected',
      'false',
    );
  });
});
