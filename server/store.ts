import type { ProcessWireFormat } from '../shared/types.js';
import type { FastifyBaseLogger } from 'fastify';

type Subscriber = (processes: ProcessWireFormat[]) => void;

// Logger will be injected from index.ts
let logger: FastifyBaseLogger | undefined;

export function setLogger(log: FastifyBaseLogger) {
  logger = log;
}

interface CachedStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  lastUpdate: number;
}

class ProcessStore {
  private processes: ProcessWireFormat[] = [];
  private subscribers: Set<Subscriber> = new Set();
  private lastUpdate = Date.now();
  private lastHash = '';
  private cachedStats: CachedStats = {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    lastUpdate: this.lastUpdate
  };

  getProcesses(): ProcessWireFormat[] {
    return this.processes;
  }

  getProcess(pid: number): ProcessWireFormat | undefined {
    return this.processes.find(p => p.pid === pid);
  }

  /**
   * Computes a lightweight hash of the process list for change detection.
   * Includes: pid, cpu (rounded), suspicion level, and connection count.
   */
  private computeHash(processes: ProcessWireFormat[]): string {
    let hash = processes.length.toString();

    for (const proc of processes) {
      // Include key fields that indicate meaningful changes
      hash += `|${proc.pid}`;
      hash += `:${Math.round(proc.cpu * 10)}`; // Round to 1 decimal place
      hash += `:${proc.level}`;
      hash += `:${proc.connections.outbound + proc.connections.listen}`;
    }

    return hash;
  }

  /**
   * Computes stats for the current process list.
   */
  private computeStats(processes: ProcessWireFormat[]): CachedStats {
    const critical = processes.filter(p => p.level === 'CRITICAL').length;
    const high = processes.filter(p => p.level === 'HIGH').length;
    const medium = processes.filter(p => p.level === 'MED').length;

    return {
      total: processes.length,
      critical,
      high,
      medium,
      lastUpdate: this.lastUpdate
    };
  }

  updateProcesses(newProcesses: ProcessWireFormat[]) {
    // Use hash-based change detection
    const newHash = this.computeHash(newProcesses);

    if (newHash !== this.lastHash) {
      this.processes = newProcesses;
      this.lastUpdate = Date.now();
      this.lastHash = newHash;

      // Update cached stats during the update
      this.cachedStats = this.computeStats(newProcesses);

      if (logger) {
        logger.debug({
          processCount: newProcesses.length,
          critical: this.cachedStats.critical,
          high: this.cachedStats.high,
          medium: this.cachedStats.medium,
          subscribers: this.subscribers.size
        }, 'Process store updated');
      }

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

  getStats(): CachedStats {
    return this.cachedStats;
  }
}

export const processStore = new ProcessStore();