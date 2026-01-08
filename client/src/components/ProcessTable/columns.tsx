import { createColumnHelper, ColumnDef } from '@tanstack/react-table';
import { Network } from 'lucide-react';
import clsx from 'clsx';
import type { ProcessData } from '../../types';
import {
  getLevelStyle,
  getNetworkStyle,
  getIndicatorStyle,
  levelDescriptions,
  reasonDescriptions,
  levelOrder,
} from './constants';

const columnHelper = createColumnHelper<ProcessData>();

export function createColumns(): ColumnDef<ProcessData, any>[] {
  return [
    columnHelper.accessor('level', {
      header: 'Risk',
      cell: (info) => {
        const level = info.getValue();
        return (
          <span
            className={clsx(
              'px-2 py-1 text-xs font-medium rounded cursor-help transition-all duration-150 hover:shadow-md inline-block',
              getLevelStyle(level)
            )}
            title={levelDescriptions[level as keyof typeof levelDescriptions]}
          >
            {level}
          </span>
        );
      },
      sortingFn: (rowA, rowB) => {
        const levelA = rowA.getValue('level') as string;
        const levelB = rowB.getValue('level') as string;
        const orderA = levelOrder[levelA] ?? 999;
        const orderB = levelOrder[levelB] ?? 999;
        return orderA - orderB;
      },
    }),
    columnHelper.accessor('pid', {
      header: 'PID',
      cell: (info) => <span className="font-mono text-sm">{info.getValue()}</span>,
    }),
    columnHelper.accessor('name', {
      header: 'Process',
      cell: (info) => (
        <div className="overflow-hidden min-w-0">
          <div className="font-medium truncate" title={info.getValue()}>
            {info.getValue()}
          </div>
          {info.row.original.parent && (
            <div className="text-xs text-gray-500 dark:text-gray-400 truncate">
              Parent: {info.row.original.parent}
            </div>
          )}
        </div>
      ),
    }),
    columnHelper.accessor('user', {
      header: 'User',
      cell: (info) => (
        <span className="text-sm truncate block" title={info.getValue()}>
          {info.getValue()}
        </span>
      ),
    }),
    columnHelper.accessor('cpu', {
      header: 'CPU %',
      cell: (info) => (
        <span className="font-mono text-sm">{info.getValue().toFixed(1)}</span>
      ),
    }),
    columnHelper.accessor('mem', {
      header: 'Mem %',
      cell: (info) => (
        <span className="font-mono text-sm">{info.getValue().toFixed(1)}</span>
      ),
    }),
    columnHelper.accessor('connections', {
      header: 'Network',
      cell: (info) => {
        const conn = info.getValue();
        if (conn.outbound === 0 && conn.listen === 0) return '-';

        const networkTooltip = `${conn.outbound} outbound connections, ${conn.listen} listening ports${
          conn.remotes.length > 0
            ? `\nRemote IPs: ${conn.remotes.slice(0, 3).join(', ')}${conn.remotes.length > 3 ? '...' : ''}`
            : ''
        }`;

        return (
          <div
            className={clsx(
              'flex items-center gap-2 text-sm cursor-help transition-all duration-150',
              getNetworkStyle(conn.outbound, conn.listen)
            )}
            title={networkTooltip}
          >
            <Network className="w-4 h-4 flex-shrink-0" />
            <span className="font-medium whitespace-nowrap">
              {conn.outbound} out, {conn.listen} listen
            </span>
          </div>
        );
      },
    }),
    columnHelper.accessor('reasons', {
      header: 'Indicators',
      cell: (info) => {
        const reasons = info.getValue();
        if (reasons.length === 0) return '-';

        return (
          <div className="flex flex-wrap gap-1">
            {reasons.slice(0, 3).map((r: string, i: number) => (
              <span
                key={i}
                className={clsx(
                  'text-xs px-2 py-1 rounded cursor-help relative group font-medium transition-all duration-150 hover:shadow-md whitespace-nowrap',
                  getIndicatorStyle(r)
                )}
                title={reasonDescriptions[r] || r.replace(/-/g, ' ')}
              >
                {r.replace(/-/g, ' ')}
              </span>
            ))}
            {reasons.length > 3 && (
              <span
                className="text-xs px-2 py-1 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 rounded cursor-help font-medium border-l-4 border-gray-400 whitespace-nowrap"
                title={`${reasons.length - 3} additional security indicators detected`}
              >
                +{reasons.length - 3} more
              </span>
            )}
          </div>
        );
      },
    }),
  ];
}
