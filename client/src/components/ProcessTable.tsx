import { useState, useMemo } from 'react';
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  SortingState,
  ColumnDef,
} from '@tanstack/react-table';
import { ChevronUp, ChevronDown, AlertTriangle, Shield, Network, Terminal } from 'lucide-react';
import clsx from 'clsx';
import type { ProcessData } from '../types';
import { ProcessDetails } from './ProcessDetails';

// Helper functions extracted outside component to prevent recreation
const getLevelStyle = (level: string) => {
  switch (level) {
    case 'CRITICAL':
      return 'bg-red-500 text-white shadow-sm border-l-4 border-red-600';
    case 'HIGH':
      return 'bg-orange-500 text-white shadow-sm border-l-4 border-orange-600';
    case 'MED':
      return 'bg-yellow-500 text-white shadow-sm border-l-4 border-yellow-600';
    case 'LOW':
      return 'bg-green-500 text-white shadow-sm border-l-4 border-green-600';
    default:
      return 'bg-gray-500 text-white shadow-sm border-l-4 border-gray-600';
  }
};

const getNetworkStyle = (outbound: number, listen: number) => {
  const total = outbound + listen;
  if (total >= 20) {
    return 'text-red-700 dark:text-red-300';
  } else if (total >= 10) {
    return 'text-orange-700 dark:text-orange-300';
  } else if (total >= 5) {
    return 'text-yellow-700 dark:text-yellow-300';
  }
  return 'text-blue-700 dark:text-blue-300';
};

const getIndicatorStyle = (reason: string) => {
  const keyloggerThreats = ['keylogger-with-network-activity', 'input-monitoring-with-network', 'unsigned-input-monitor', 'accessibility-with-network'];
  const highThreats = ['keylogger-pattern', 'browser-spawned-input-monitor', 'suspicious-data-upload-pattern'];
  const mediumThreats = ['screen-recorder', 'remote-access', 'cryptominer'];
  const lowThreats = ['unsigned-binary', 'different-user', 'agent-ish', 'launchd-managed'];

  if (keyloggerThreats.includes(reason)) {
    return 'bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-300 border-l-4 border-red-500 shadow-sm';
  } else if (highThreats.includes(reason)) {
    return 'bg-orange-50 dark:bg-orange-950/30 text-orange-700 dark:text-orange-300 border-l-4 border-orange-500 shadow-sm';
  } else if (mediumThreats.includes(reason)) {
    return 'bg-yellow-50 dark:bg-yellow-950/30 text-yellow-700 dark:text-yellow-300 border-l-4 border-yellow-500 shadow-sm';
  } else if (lowThreats.includes(reason)) {
    return 'bg-blue-50 dark:bg-blue-950/30 text-blue-700 dark:text-blue-300 border-l-4 border-blue-500 shadow-sm';
  }
  return 'bg-gray-50 dark:bg-gray-800 text-gray-700 dark:text-gray-300 border-l-4 border-gray-400 shadow-sm';
};

// Static lookup objects moved outside component
const levelDescriptions = {
  'CRITICAL': '🚨 Immediate threat - likely malware or data theft',
  'HIGH': '⚠️ High risk - investigate immediately',
  'MED': '⚡ Medium risk - monitor closely',
  'LOW': '✅ Low risk - normal system activity'
};

const reasonIcons: Record<string, React.ReactNode> = {
  'keylogger-pattern': <AlertTriangle className="w-3 h-3 text-red-500" />,
  'keylogger-with-network-activity': <AlertTriangle className="w-3 h-3 text-red-600 animate-pulse" />,
  'input-monitoring-with-network': <AlertTriangle className="w-3 h-3 text-red-600 animate-pulse" />,
  'unsigned-input-monitor': <Shield className="w-3 h-3 text-red-500" />,
  'browser-spawned-input-monitor': <Terminal className="w-3 h-3 text-orange-500" />,
  'accessibility-with-network': <AlertTriangle className="w-3 h-3 text-red-600" />,
  'suspicious-data-upload-pattern': <Network className="w-3 h-3 text-orange-500" />,
  'screen-recorder': <Terminal className="w-3 h-3 text-orange-500" />,
  'unsigned-binary': <Shield className="w-3 h-3 text-yellow-500" />,
};

const reasonDescriptions: Record<string, string> = {
  'keylogger-pattern': 'Matches known keylogger signatures',
  'keylogger-with-network-activity': '🚨 CRITICAL: Keylogger sending data over network!',
  'input-monitoring-with-network': '🚨 CRITICAL: Input monitoring + network activity',
  'unsigned-input-monitor': '🚨 CRITICAL: Unsigned binary with input access',
  'browser-spawned-input-monitor': 'Input monitoring process spawned from browser',
  'accessibility-with-network': '🚨 CRITICAL: Accessibility permissions + network use',
  'suspicious-data-upload-pattern': 'Unusual data upload patterns to suspicious domains',
  'screen-recorder': 'Screen capture or recording capabilities',
  'unsigned-binary': 'Binary is not code signed',
  'different-user': 'Process running under different user account',
  'agent-ish': 'Background agent or daemon process',
  'launchd-managed': 'Managed by macOS launch daemon system',
  'remote-access': 'Remote access or control capabilities',
  'cryptominer': 'Cryptocurrency mining software detected',
  'data-exfiltration': 'Data transfer or synchronization tool',
};

const columnHelper = createColumnHelper<ProcessData>();

// Create column definitions function that will be called once inside the component
const createColumns = (): ColumnDef<ProcessData, any>[] => [
  columnHelper.accessor('level', {
    header: 'Risk',
    cell: (info) => {
      const level = info.getValue();
      return (
        <span
          className={clsx(
            'px-2 py-1 text-xs font-medium rounded cursor-help transition-all duration-150 hover:shadow-md',
            getLevelStyle(level)
          )}
          title={levelDescriptions[level as keyof typeof levelDescriptions]}
        >
          {level}
        </span>
      );
    },
  }),
  columnHelper.accessor('pid', {
    header: 'PID',
    cell: (info) => <span className="font-mono text-sm">{info.getValue()}</span>,
  }),
  columnHelper.accessor('name', {
    header: 'Process',
    cell: (info) => (
      <div>
        <div className="font-medium">{info.getValue()}</div>
        {info.row.original.parent && (
          <div className="text-xs text-gray-500 dark:text-gray-400">
            Parent: {info.row.original.parent}
          </div>
        )}
      </div>
    ),
  }),
  columnHelper.accessor('user', {
    header: 'User',
    cell: (info) => <span className="text-sm">{info.getValue()}</span>,
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
        conn.remotes.length > 0 ? `\nRemote IPs: ${conn.remotes.slice(0, 3).join(', ')}${conn.remotes.length > 3 ? '...' : ''}` : ''
      }`;

      return (
        <div
          className={clsx(
            "flex items-center gap-2 text-sm cursor-help transition-all duration-150",
            getNetworkStyle(conn.outbound, conn.listen)
          )}
          title={networkTooltip}
        >
          <Network className="w-4 h-4" />
          <span className="font-medium">{conn.outbound} out, {conn.listen} listen</span>
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
          {reasons.slice(0, 3).map((r, i) => (
            <span
              key={i}
              className={clsx(
                "text-xs px-2 py-1 rounded cursor-help relative group font-medium transition-all duration-150 hover:shadow-md",
                getIndicatorStyle(r)
              )}
              title={reasonDescriptions[r] || r.replace(/-/g, ' ')}
            >
              {r.replace(/-/g, ' ')}
              <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 px-3 py-2 bg-gray-900 text-white text-xs rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none whitespace-nowrap z-50 max-w-xs shadow-xl">
                {reasonDescriptions[r] || r.replace(/-/g, ' ')}
                <div className="absolute top-full left-1/2 transform -translate-x-1/2 w-0 h-0 border-l-4 border-r-4 border-t-4 border-transparent border-t-gray-900"></div>
              </div>
            </span>
          ))}
          {reasons.length > 3 && (
            <span
              className="text-xs px-2 py-1 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 rounded cursor-help font-medium border-l-4 border-gray-400"
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

interface ProcessTableProps {
  processes: ProcessData[];
}

export function ProcessTable({ processes }: ProcessTableProps) {
  const [sorting, setSorting] = useState<SortingState>([
    { id: 'level', desc: false },
    { id: 'cpu', desc: true },
  ]);
  const [selectedProcess, setSelectedProcess] = useState<ProcessData | null>(null);

  // Memoize columns to prevent recreation on every render
  const columns = useMemo(() => createColumns(), []);

  // useReactTable handles its own memoization internally
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
  
  return (
    <>
      <div className="bg-white dark:bg-gray-900 rounded-lg shadow-sm border border-gray-200 dark:border-gray-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
              {table.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id}>
                  {headerGroup.headers.map((header) => (
                    <th
                      key={header.id}
                      className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-750"
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
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
              {table.getRowModel().rows.map((row) => (
                <tr
                  key={row.id}
                  className="hover:bg-gray-50 dark:hover:bg-gray-800/50 cursor-pointer transition-colors"
                  onClick={() => setSelectedProcess(row.original)}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td
                      key={cell.id}
                      className="px-4 py-3 text-sm whitespace-nowrap"
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        {processes.length === 0 && (
          <div className="p-8 text-center text-gray-500 dark:text-gray-400">
            No processes found
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