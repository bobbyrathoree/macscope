import { useEffect, useState } from 'react';
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
      setProcesses(data.data);
    }
  });
  
  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [darkMode]);
  
  const filteredProcesses = processes
    .slice(0, processLimit)
    .filter(p => 
      !filter || 
      (p.name || '').toLowerCase().includes(filter.toLowerCase()) ||
      (p.cmd || '').toLowerCase().includes(filter.toLowerCase()) ||
      (p.user || '').toLowerCase().includes(filter.toLowerCase())
    );
  
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