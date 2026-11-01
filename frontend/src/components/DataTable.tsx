import React from 'react';

export interface DataTableColumn<T> {
  key: string;
  label: string;
  width?: string;
  align?: 'left' | 'center' | 'right';
  render?: (row: T, index: number) => React.ReactNode;
}

interface DataTableProps<T> {
  columns: DataTableColumn<T>[];
  data: T[];
  keyExtractor: (row: T, index: number) => string;
  selectedId?: string | null;
  onSelectRow?: (row: T) => void;
  emptyMessage?: string;
}

export function DataTable<T extends Record<string, any>>({
  columns,
  data,
  keyExtractor,
  selectedId,
  onSelectRow,
  emptyMessage = 'No records recorded.',
}: DataTableProps<T>) {
  if (data.length === 0) {
    return (
      <div
        style={{
          padding: '28px',
          textAlign: 'center',
          color: 'var(--text-muted)',
          fontSize: '11px',
        }}
      >
        {emptyMessage}
      </div>
    );
  }

  return (
    <div className="wb-table-container">
      <table className="wb-table">
        <thead>
          <tr>
            {columns.map((col) => (
              <th
                key={col.key}
                style={{
                  width: col.width,
                  textAlign: col.align || 'left',
                }}
              >
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, idx) => {
            const rowKey = keyExtractor(row, idx);
            const isSelected = selectedId === rowKey;

            const isInteractive = Boolean(onSelectRow);

            return (
              <tr
                key={rowKey}
                className={`${isSelected ? 'selected' : ''} ${isInteractive ? 'interactive' : ''}`}
                tabIndex={isInteractive ? 0 : undefined}
                role={isInteractive ? 'button' : undefined}
                aria-selected={isInteractive ? isSelected : undefined}
                onClick={() => onSelectRow && onSelectRow(row)}
                onKeyDown={(e) => {
                  if (isInteractive && (e.key === 'Enter' || e.key === ' ')) {
                    e.preventDefault();
                    onSelectRow!(row);
                  }
                }}
              >
                {columns.map((col) => {
                  const val = row[col.key];
                  return (
                    <td
                      key={col.key}
                      style={{
                        textAlign: col.align || 'left',
                      }}
                    >
                      {col.render ? col.render(row, idx) : String(val ?? '—')}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
