import { useEffect, useState, useMemo } from 'react';
import { ProcessTable } from './components/ProcessTable';
import { StatsBar } from './components/StatsBar';
import { Header } from './components/Header';
import { useWebSocket } from './hooks/useWebSocket';
import { useSystemStats } from './hooks/useSystemStats';
import type { ProcessData } from './types';

function App() {
  const [processes, setProcesses] = useState<ProcessData[]>([]);
  const [filter, setFilter] = useState('');
  const [processLimit, setProcessLimit] = useState(200);
  const [darkMode, setDarkMode] = useState(() => 
    window.matchMedia('(prefers-color-scheme: dark)').matches
  );
  
  const { stats } = useSystemStats();
  
  useWebSocket((data) => {
    if (data.type === 'initial' || data.type === 'update') {
      setProcesses(data.data as ProcessData[]);
    } else if (data.type === 'delta') {
      const delta = data.data as {
        added: ProcessData[];
        updated: ProcessData[];
        removed: number[];
      };

      setProcesses((prevProcesses) => {
        // Create a map for efficient lookup
        const processMap = new Map(prevProcesses.map(p => [p.pid, p]));

        // Remove processes
        delta.removed.forEach(pid => {
          processMap.delete(pid);
        });

        // Update existing processes
        delta.updated.forEach(proc => {
          processMap.set(proc.pid, proc);
        });

        // Add new processes
        delta.added.forEach(proc => {
          processMap.set(proc.pid, proc);
        });

        // Convert map back to array
        return Array.from(processMap.values());
      });
    }
  });
  
  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [darkMode]);

  // Memoize filtered processes with proper order: filter THEN slice
  const filteredProcesses = useMemo(() => {
    // Pre-compute lowercase filter once
    const lowerFilter = filter.toLowerCase();

    // Filter first (if filter exists), then slice
    return processes
      .filter(p =>
        !filter ||
        (p.name || '').toLowerCase().includes(lowerFilter) ||
        (p.cmd || '').toLowerCase().includes(lowerFilter) ||
        (p.user || '').toLowerCase().includes(lowerFilter)
      )
      .slice(0, processLimit);
  }, [processes, filter, processLimit]);
  
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950">
      <Header 
        darkMode={darkMode}
        onToggleDark={() => setDarkMode(!darkMode)}
        filter={filter}
        onFilterChange={setFilter}
        processLimit={processLimit}
        onProcessLimitChange={setProcessLimit}
      />
      
      <StatsBar 
        processes={processes}
        systemStats={stats}
      />
      
      <main className="container mx-auto px-4 py-6">
        <ProcessTable processes={filteredProcesses} />
      </main>
    </div>
  );
}

export default App;