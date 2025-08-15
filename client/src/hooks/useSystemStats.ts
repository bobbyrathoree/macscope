import { useQuery } from '@tanstack/react-query';
import type { SystemStats } from '../types';

export function useSystemStats() {
  const { data: stats, error, isLoading } = useQuery({
    queryKey: ['system-stats'],
    queryFn: async () => {
      const response = await fetch('/api/stats');
      if (!response.ok) throw new Error('Failed to fetch stats');
      return response.json() as Promise<SystemStats>;
    },
    refetchInterval: 5000,
  });
  
  return { stats, error, isLoading };
}