import { Shield, Moon, Sun, Search } from 'lucide-react';

interface HeaderProps {
  darkMode: boolean;
  onToggleDark: () => void;
  filter: string;
  onFilterChange: (value: string) => void;
  processLimit: number;
  onProcessLimitChange: (value: number) => void;
}

export function Header({ darkMode, onToggleDark, filter, onFilterChange, processLimit, onProcessLimitChange }: HeaderProps) {
  return (
    <header className="bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800">
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-blue-600 dark:text-blue-400" />
            <div>
              <h1 className="text-2xl font-bold">Procscope</h1>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                macOS Security Monitor
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            <select
              value={processLimit}
              onChange={(e) => onProcessLimitChange(Number(e.target.value))}
              className="px-3 py-2 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
            >
              <option value={100}>100 processes</option>
              <option value={200}>200 processes</option>
              <option value={500}>500 processes</option>
              <option value={1000}>1000 processes</option>
            </select>
            
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Filter processes..."
                value={filter}
                onChange={(e) => onFilterChange(e.target.value)}
                className="pl-9 pr-4 py-2 w-64 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                aria-label="Filter processes by name, command, or user"
              />
            </div>
            
            <button
              onClick={onToggleDark}
              className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
              aria-label="Toggle dark mode"
            >
              {darkMode ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>
    </header>
  );
}