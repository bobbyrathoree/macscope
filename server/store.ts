import type { ProcessRow } from '../src/types.js';

type Subscriber = (processes: ProcessRow[]) => void;

class ProcessStore {
  private processes: ProcessRow[] = [];
  private subscribers: Set<Subscriber> = new Set();
  private lastUpdate = Date.now();
  
  getProcesses(): ProcessRow[] {
    return this.processes;
  }
  
  getProcess(pid: number): ProcessRow | undefined {
    return this.processes.find(p => p.pid === pid);
  }
  
  updateProcesses(newProcesses: ProcessRow[]) {
    // Only update if there are actual changes (simple comparison)
    const hasChanges = 
      this.processes.length !== newProcesses.length ||
      JSON.stringify(this.processes.slice(0, 5)) !== JSON.stringify(newProcesses.slice(0, 5));
    
    if (hasChanges) {
      this.processes = newProcesses;
      this.lastUpdate = Date.now();
      this.notifySubscribers();
    }
  }
  
  subscribe(callback: Subscriber): () => void {
    this.subscribers.add(callback);
    return () => this.subscribers.delete(callback);
  }
  
  private notifySubscribers() {
    this.subscribers.forEach(callback => callback(this.processes));
  }
  
  getStats() {
    const critical = this.processes.filter(p => p.level === 'CRITICAL').length;
    const high = this.processes.filter(p => p.level === 'HIGH').length;
    const medium = this.processes.filter(p => p.level === 'MED').length;
    const total = this.processes.length;
    
    return {
      total,
      critical,
      high,
      medium,
      lastUpdate: this.lastUpdate
    };
  }
}

export const processStore = new ProcessStore();