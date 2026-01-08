import { useState, useMemo, useRef } from 'react';
import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  SortingState,
} from '@tanstack/react-table';
import { useVirtualizer } from '@tanstack/react-virtual';
import { ChevronUp, ChevronDown, RotateCcw } from 'lucide-react';
import clsx from 'clsx';
import type { ProcessData } from '../../types';
import { ProcessDetails } from '../ProcessDetails';
import { useColumnWidths } from '../../hooks/useColumnWidths';
import { getColumnConfig } from '../../config/tableColumns';
import { ColumnResizer } from './ColumnResizer';
import { createColumns } from './columns';

interface ProcessTableProps {
  processes: ProcessData[];
}

const ROW_HEIGHT = 50;

export function ProcessTable({ processes }: ProcessTableProps) {
  const [sorting, setSorting] = useState<SortingState>([
    { id: 'level', desc: false },
    { id: 'cpu', desc: true },
  ]);
  const [selectedProcess, setSelectedProcess] = useState<ProcessData | null>(null);

  const tableContainerRef = useRef<HTMLDivElement>(null);

  const { widths, setColumnWidth, resetWidths, gridTemplate } = useColumnWidths();

  const columns = useMemo(() => createColumns(), []);

  const table = useReactTable({
    data: processes,
    columns,
    state: {
      sorting,
    },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  const rows = table.getRowModel().rows;

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => tableContainerRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 10,
  });

  const virtualItems = virtualizer.getVirtualItems();

  return (
    <>
      <div className="bg-white dark:bg-gray-900 rounded-lg shadow-sm border border-gray-200 dark:border-gray-800 overflow-hidden">
        {/* Reset button */}
        <div className="flex justify-end px-4 py-2 border-b border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-800/50">
          <button
            onClick={resetWidths}
            className="flex items-center gap-1 text-xs text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 transition-colors"
            title="Reset column widths"
          >
            <RotateCcw className="w-3 h-3" />
            Reset columns
          </button>
        </div>

        {processes.length === 0 ? (
          <div className="p-8 text-center text-gray-500 dark:text-gray-400">
            No processes found
          </div>
        ) : (
          <div className="overflow-x-auto">
            <div
              ref={tableContainerRef}
              className="overflow-auto"
              style={{ height: '600px' }}
            >
              {/* Header */}
              <div
                className="process-table-grid bg-gray-50 dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 sticky top-0 z-10"
                style={{ gridTemplateColumns: gridTemplate }}
              >
                {table.getHeaderGroups().map((headerGroup) =>
                  headerGroup.headers.map((header) => {
                    const config = getColumnConfig(header.id);
                    return (
                      <div
                        key={header.id}
                        className="relative px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-750 select-none"
                        onClick={header.column.getToggleSortingHandler()}
                      >
                        <div className="flex items-center gap-1">
                          {flexRender(
                            header.column.columnDef.header,
                            header.getContext()
                          )}
                          {{
                            asc: <ChevronUp className="w-3 h-3" />,
                            desc: <ChevronDown className="w-3 h-3" />,
                          }[header.column.getIsSorted() as string] ?? null}
                        </div>
                        {config?.canResize && (
                          <ColumnResizer
                            columnId={header.id}
                            currentWidth={widths[header.id] || config.defaultWidth}
                            onResize={setColumnWidth}
                            minWidth={config.minWidth}
                            maxWidth={config.maxWidth}
                          />
                        )}
                      </div>
                    );
                  })
                )}
              </div>

              {/* Body */}
              <div
                style={{
                  height: `${virtualizer.getTotalSize()}px`,
                  position: 'relative',
                }}
              >
                {virtualItems.map((virtualRow) => {
                  const row = rows[virtualRow.index];
                  return (
                    <div
                      key={row.id}
                      className="process-table-grid hover:bg-gray-50 dark:hover:bg-gray-800/50 cursor-pointer transition-colors border-b border-gray-200 dark:border-gray-800"
                      style={{
                        gridTemplateColumns: gridTemplate,
                        position: 'absolute',
                        top: 0,
                        left: 0,
                        width: '100%',
                        height: `${virtualRow.size}px`,
                        transform: `translateY(${virtualRow.start}px)`,
                      }}
                      onClick={() => setSelectedProcess(row.original)}
                    >
                      {row.getVisibleCells().map((cell) => {
                        const config = getColumnConfig(cell.column.id);
                        return (
                          <div
                            key={cell.id}
                            className={clsx(
                              'px-4 py-3 text-sm flex items-center',
                              config?.truncate && 'overflow-hidden min-w-0'
                            )}
                          >
                            {flexRender(
                              cell.column.columnDef.cell,
                              cell.getContext()
                            )}
                          </div>
                        );
                      })}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </div>

      {selectedProcess && (
        <ProcessDetails
          process={selectedProcess}
          onClose={() => setSelectedProcess(null)}
        />
      )}
    </>
  );
}
