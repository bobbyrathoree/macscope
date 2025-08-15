import { AlertTriangle, AlertCircle, Activity, Cpu } from 'lucide-react';
import clsx from 'clsx';
import type { ProcessData, SystemStats } from '../types';

interface StatsBarProps {
  processes: ProcessData[];
  systemStats?: SystemStats;
}

export function StatsBar({ processes, systemStats }: StatsBarProps) {
  const critical = processes.filter(p => p.level === 'CRITICAL').length;
  const high = processes.filter(p => p.level === 'HIGH').length;
  const medium = processes.filter(p => p.level === 'MED').length;
  
  const memUsage = systemStats ? 
    ((systemStats.system.totalMem - systemStats.system.freeMem) / systemStats.system.totalMem * 100).toFixed(1) : 0;
  
  return (
    <div className="bg-gray-100 dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800">
      <div className="container mx-auto px-4 py-3">
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
          <StatCard
            icon={<AlertTriangle className="w-4 h-4" />}
            label="Critical"
            value={critical}
            className={clsx(critical > 0 && 'text-red-600 dark:text-red-400')}
            pulse={critical > 0}
          />
          <StatCard
            icon={<AlertCircle className="w-4 h-4" />}
            label="High"
            value={high}
            className={clsx(high > 0 && 'text-orange-600 dark:text-orange-400')}
          />
          <StatCard
            icon={<Activity className="w-4 h-4" />}
            label="Medium"
            value={medium}
            className={clsx(medium > 0 && 'text-yellow-600 dark:text-yellow-400')}
          />
          <StatCard
            icon={<Activity className="w-4 h-4" />}
            label="Total"
            value={processes.length}
          />
          <StatCard
            icon={<Cpu className="w-4 h-4" />}
            label="CPU Cores"
            value={systemStats?.system.cpuCount || '-'}
          />
          <StatCard
            icon={<Activity className="w-4 h-4" />}
            label="Memory"
            value={`${memUsage}%`}
          />
        </div>
        
        {critical > 0 && (
          <div className="mt-3 p-2 bg-red-100 dark:bg-red-950/50 border border-red-200 dark:border-red-800 rounded-lg animate-pulse">
            <p className="text-sm text-red-700 dark:text-red-300 font-medium">
              🚨 {critical} critical threat{critical !== 1 ? 's' : ''} detected - immediate action recommended
            </p>
            {(() => {
              const keyloggers = processes.filter(p => 
                p.level === 'CRITICAL' && 
                p.reasons.some(r => r.includes('keylogger') || r.includes('input-monitoring'))
              );
              return keyloggers.length > 0 && (
                <p className="text-xs text-red-600 dark:text-red-400 mt-1">
                  ⌨️ {keyloggers.length} process{keyloggers.length !== 1 ? 'es' : ''} detected with input monitoring + network activity
                </p>
              );
            })()}
          </div>
        )}
        
        {!systemStats?.system.isRoot && (
          <div className="mt-3 p-2 bg-yellow-100 dark:bg-yellow-950/50 border border-yellow-200 dark:border-yellow-800 rounded-lg">
            <p className="text-sm text-yellow-700 dark:text-yellow-300">
              💡 Running without elevated privileges - some processes may not be visible
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ 
  icon, 
  label, 
  value, 
  className, 
  pulse 
}: { 
  icon: React.ReactNode;
  label: string;
  value: string | number;
  className?: string;
  pulse?: boolean;
}) {
  return (
    <div className={clsx(
      "flex items-center gap-2 text-sm",
      pulse && "animate-pulse-slow",
      className
    )}>
      {icon}
      <span className="text-gray-600 dark:text-gray-400">{label}:</span>
      <span className="font-semibold">{value}</span>
    </div>
  );
}