import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { listProcesses } from '../src/proc.js';
import { getConnectionSummary } from '../src/conns.js';
import { collectLaunchDaemons } from '../src/launchctl.js';
import { getCodeSignInfo } from '../src/codesign.js';
import { analyzeSecurity } from '../src/security.js';
import { logSuspiciousProcess, initLogger } from '../src/logger.js';
import { processStore } from './store.js';
import type { ProcessWireFormat, CodesignInfo } from '../shared/types.js';
import type { ProcInfo, ConnSummary } from '../src/types.js';
import type { FastifyBaseLogger } from 'fastify';

// Logger will be injected from index.ts
let logger: FastifyBaseLogger;

export function setLogger(log: FastifyBaseLogger) {
  logger = log;
}

// ============================================
// Worker Pool for Codesign Operations
// ============================================

interface WorkerPoolTask {
  id: string;
  path: string;
  resolve: (result: CodesignInfo | null) => void;
  reject: (error: Error) => void;
}

class CodesignWorkerPool {
  private workers: Worker[] = [];
  private taskQueue: WorkerPoolTask[] = [];
  private pendingTasks = new Map<string, WorkerPoolTask>();
  private availableWorkers: Worker[] = [];
  private isShuttingDown = false;
  private initialized = false;

  constructor(private poolSize: number = 2) {}

  async initialize(): Promise<boolean> {
    if (this.initialized) {
      return true;
    }

    try {
      const __filename = fileURLToPath(import.meta.url);
      const __dirname = dirname(__filename);
      // Use .ts extension for development with tsx
      const workerPath = join(__dirname, 'workers', 'codesign-worker.ts');

      // Create worker pool
      for (let i = 0; i < this.poolSize; i++) {
        // Use tsx to run TypeScript workers in development mode
        const worker = new Worker(workerPath, {
          execArgv: ['--import', 'tsx']
        });

        worker.on('message', (message: any) => {
          if (message.type === 'ready') {
            this.availableWorkers.push(worker);
            this.processQueue();
            return;
          }

          const { id, result, error } = message;
          const task = this.pendingTasks.get(id);

          if (task) {
            this.pendingTasks.delete(id);

            if (error) {
              task.reject(new Error(error));
            } else {
              task.resolve(result);
            }

            // Worker is now available again
            this.availableWorkers.push(worker);
            this.processQueue();
          }
        });

        worker.on('error', (error) => {
          logger.error({ err: error }, `[Worker Pool] Worker ${i} error`);
          // Remove failed worker from available pool
          const idx = this.availableWorkers.indexOf(worker);
          if (idx !== -1) {
            this.availableWorkers.splice(idx, 1);
          }
        });

        worker.on('exit', (code) => {
          if (code !== 0 && !this.isShuttingDown) {
            logger.warn({ code }, `[Worker Pool] Worker ${i} exited unexpectedly`);
          }
        });

        this.workers.push(worker);
      }

      // Wait for workers to be ready (with timeout)
      const readyPromise = new Promise<boolean>((resolve) => {
        const checkReady = setInterval(() => {
          if (this.availableWorkers.length === this.poolSize) {
            clearInterval(checkReady);
            resolve(true);
          }
        }, 50);

        // Timeout after 2 seconds
        setTimeout(() => {
          clearInterval(checkReady);
          resolve(this.availableWorkers.length > 0);
        }, 2000);
      });

      const ready = await readyPromise;

      if (ready) {
        this.initialized = true;
        logger.info({ poolSize: this.poolSize }, '[Worker Pool] Codesign worker pool initialized');
      } else {
        logger.warn('[Worker Pool] Failed to initialize all workers, falling back to main thread');
        this.shutdown();
      }

      return ready;
    } catch (error) {
      logger.error({ err: error }, '[Worker Pool] Failed to initialize worker pool');
      this.shutdown();
      return false;
    }
  }

  async getCodeSignInfo(path: string): Promise<CodesignInfo | null> {
    if (!this.initialized || this.isShuttingDown) {
      throw new Error('Worker pool not initialized or shutting down');
    }

    return new Promise((resolve, reject) => {
      const id = `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
      const task: WorkerPoolTask = { id, path, resolve, reject };

      this.taskQueue.push(task);
      this.processQueue();

      // Timeout after 5 seconds
      setTimeout(() => {
        const queueIdx = this.taskQueue.indexOf(task);
        if (queueIdx !== -1) {
          this.taskQueue.splice(queueIdx, 1);
          reject(new Error('Codesign worker timeout'));
        }

        if (this.pendingTasks.has(id)) {
          this.pendingTasks.delete(id);
          reject(new Error('Codesign worker timeout'));
        }
      }, 5000);
    });
  }

  private processQueue(): void {
    while (this.taskQueue.length > 0 && this.availableWorkers.length > 0) {
      const task = this.taskQueue.shift();
      const worker = this.availableWorkers.shift();

      if (task && worker) {
        this.pendingTasks.set(task.id, task);
        worker.postMessage({ id: task.id, path: task.path });
      }
    }
  }

  shutdown(): void {
    if (this.isShuttingDown) {
      return;
    }

    this.isShuttingDown = true;
    this.initialized = false;

    // Reject all pending tasks
    for (const task of this.pendingTasks.values()) {
      task.reject(new Error('Worker pool shutting down'));
    }
    this.pendingTasks.clear();

    // Clear queue
    for (const task of this.taskQueue) {
      task.reject(new Error('Worker pool shutting down'));
    }
    this.taskQueue = [];

    // Terminate all workers
    for (const worker of this.workers) {
      worker.terminate().catch((err) => {
        logger.error({ err }, '[Worker Pool] Error terminating worker');
      });
    }

    this.workers = [];
    this.availableWorkers = [];

    logger.info('[Worker Pool] Worker pool shut down');
  }

  isReady(): boolean {
    return this.initialized && !this.isShuttingDown;
  }
}

// Global worker pool instance
let workerPool: CodesignWorkerPool | null = null;
let useWorkerPool = true; // Feature flag

let monitorInterval: NodeJS.Timeout | null = null;
let currentScanInterval: number = 10000; // Track current interval in ms

// Process fingerprinting for caching
interface ProcessFingerprint {
  pid: number;
  execPath: string;
  cmd: string;
  connectionCount: number;
}

interface CachedAnalysis {
  level: 'LOW' | 'MED' | 'HIGH' | 'CRITICAL';
  reasons: string[];
}

const processFingerprints = new Map<number, string>();
const previousResults = new Map<number, CachedAnalysis>();

// Scan frequency constants (in milliseconds)
const SCAN_INTERVAL = {
  CRITICAL: 5000,  // 5 seconds - critical threats detected
  HIGH: 7000,      // 7 seconds - high threats detected
  NORMAL: 10000,   // 10 seconds - only medium/low threats
  IDLE: 15000,     // 15 seconds - idle system (<100 procs, no threats)
  MIN: 5000,       // Minimum scan interval (safety bound)
  MAX: 15000       // Maximum scan interval (safety bound)
};

/**
 * Generate a fingerprint for a process based on key identifying characteristics
 */
function getProcessFingerprint(proc: ProcInfo, conn: ConnSummary | undefined): string {
  const connectionCount = (conn?.outbound || 0) + (conn?.listen || 0);
  const fingerprint: ProcessFingerprint = {
    pid: proc.pid,
    execPath: proc.execPath || '',
    cmd: proc.cmd || '',
    connectionCount
  };
  return JSON.stringify(fingerprint);
}

export async function startProcessMonitor() {
  if (monitorInterval) return;

  // Initialize logger directory
  await initLogger();

  // Initialize worker pool for codesign operations
  if (useWorkerPool) {
    workerPool = new CodesignWorkerPool(2); // Start with 2 workers
    const initialized = await workerPool.initialize();

    if (!initialized) {
      logger.warn('[Worker Pool] Falling back to main thread execution');
      workerPool = null;
      useWorkerPool = false;
    }
  }

  logger.info({ adaptive: true, interval: currentScanInterval, workerPool: useWorkerPool }, 'Process monitor started');

  // Start initial scan (will self-schedule subsequent scans)
  scheduleScan();
}

/**
 * Schedule the next scan based on adaptive timing
 */
function scheduleScan() {
  if (monitorInterval) {
    clearTimeout(monitorInterval);
  }

  monitorInterval = setTimeout(async () => {
    await scanProcesses();
    // After scan completes, schedule next one
    scheduleScan();
  }, currentScanInterval);
}

export function stopProcessMonitor() {
  if (monitorInterval) {
    clearTimeout(monitorInterval);
    monitorInterval = null;
  }

  // Shutdown worker pool gracefully
  if (workerPool) {
    workerPool.shutdown();
    workerPool = null;
  }

  logger.info('Process monitor stopped');
}

async function scanProcesses() {
  try {
    // Add timeout and error handling to prevent system overload
    const timeoutPromise = new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Scan timeout')), 15000)
    );
    
    const scanPromise = Promise.all([
      listProcesses(),
      getConnectionSummary(),
      collectLaunchDaemons()
    ]);
    
    const [procs, conns, launchInfo] = await Promise.race([scanPromise, timeoutPromise]) as [
      ProcInfo[],
      Map<number, ConnSummary>,
      Map<number, string>
    ];

    // Build parent map for process injection detection
    const parentMap = new Map<number, ProcInfo | undefined>();
    for (const proc of procs) {
      if (proc.ppid) {
        parentMap.set(proc.pid, procs.find((p: ProcInfo) => p.pid === proc.ppid));
      }
    }

    // Limit process analysis to prevent system overload
    const limitedProcs = procs.slice(0, 200); // Limit to 200 processes max

    // Track current PIDs for cleanup
    const currentPids = new Set(limitedProcs.map((p: ProcInfo) => p.pid));

    // Analyze each process with concurrency control
    const rows: ProcessWireFormat[] = [];
    const batchSize = 10; // Process in small batches
    let cachedCount = 0;
    let analyzedCount = 0;

    for (let i = 0; i < limitedProcs.length; i += batchSize) {
      const batch = limitedProcs.slice(i, i + batchSize);
      const batchResults = await Promise.all(
        batch.map(async (proc: ProcInfo) => {
          const conn = conns.get(proc.pid);
          const launchd = launchInfo.get(proc.pid);
          const parent = parentMap.get(proc.pid);

          // Generate fingerprint for this process
          const currentFingerprint = getProcessFingerprint(proc, conn);
          const previousFingerprint = processFingerprints.get(proc.pid);

          let suspicion: { level: 'LOW' | 'MED' | 'HIGH' | 'CRITICAL'; reasons: string[] };
          let csig: CodesignInfo | null = null;

          // Check if process fingerprint changed
          if (previousFingerprint === currentFingerprint && previousResults.has(proc.pid)) {
            // Reuse cached analysis result
            suspicion = previousResults.get(proc.pid)!;
            cachedCount++;
          } else {
            // Fingerprint changed or new process - run full analysis
            analyzedCount++;

            // Only get code signature for highly suspicious processes to prevent overload
            if (conn && conn.outbound > 50) { // Much higher threshold
              try {
                const path = proc.execPath || proc.cmd || '';

                // Use worker pool if available, otherwise fall back to main thread
                if (workerPool && workerPool.isReady()) {
                  csig = await Promise.race([
                    workerPool.getCodeSignInfo(path),
                    new Promise<CodesignInfo>((_, reject) => setTimeout(() => reject(new Error('Codesign timeout')), 2000))
                  ]) as CodesignInfo;
                } else {
                  // Fallback to main thread execution
                  csig = await Promise.race([
                    getCodeSignInfo(path),
                    new Promise<CodesignInfo>((_, reject) => setTimeout(() => reject(new Error('Codesign timeout')), 2000))
                  ]) as CodesignInfo;
                }
              } catch (err) {
                // Skip codesign on timeout/error
                csig = null;
              }
            }

            suspicion = await analyzeSecurity(proc, conn, launchd, csig, parent);

            // Update cache with new fingerprint and result
            processFingerprints.set(proc.pid, currentFingerprint);
            previousResults.set(proc.pid, {
              level: suspicion.level,
              reasons: suspicion.reasons
            });
          }
          
          // Log HIGH and CRITICAL processes (but don't await to prevent blocking)
          if (suspicion.level === 'HIGH' || suspicion.level === 'CRITICAL') {
            logSuspiciousProcess({
              ...proc,
              name: proc.name || 'unknown',
              level: suspicion.level,
              reasons: suspicion.reasons,
              connections: conn || { outbound: 0, listen: 0, sampleRemotes: new Set() },
              codesign: csig || { signed: false, valid: false },
              parent: parent?.name || null
            }).catch(err => logger.error({ err }, 'Failed to log suspicious process'));
          }
          
          return {
            pid: proc.pid,
            ppid: proc.ppid,
            name: proc.name || 'unknown',
            cmd: proc.cmd || '',
            user: proc.user || '',
            cpu: proc.cpu || 0,
            mem: proc.mem || 0,
            execPath: proc.execPath,
            connections: {
              outbound: conn?.outbound || 0,
              listen: conn?.listen || 0,
              remotes: Array.from(conn?.sampleRemotes || [])
            },
            level: suspicion.level,
            reasons: suspicion.reasons,
            launchd: launchd || undefined,
            codesign: csig ? {
              signed: csig.signed,
              valid: csig.valid || false,
              teamId: csig.teamIdentifier,
              notarized: csig.notarized,
              appStore: csig.isAppStore
            } : undefined,
            parent: parent?.name
          };
        })
      );
      rows.push(...batchResults);
    }

    // Clean up fingerprints and results for processes that no longer exist
    for (const pid of Array.from(processFingerprints.keys())) {
      if (!currentPids.has(pid)) {
        processFingerprints.delete(pid);
        previousResults.delete(pid);
      }
    }

    // Log cache statistics
    const cacheHitRate = cachedCount + analyzedCount > 0
      ? ((cachedCount / (cachedCount + analyzedCount)) * 100).toFixed(1)
      : '0.0';
    logger.debug({
      analyzed: analyzedCount,
      cached: cachedCount,
      cacheHitRate: `${cacheHitRate}%`,
      totalProcesses: rows.length
    }, 'Process analysis complete');

    // Sort by suspicion level and CPU usage
    rows.sort((a, b) => {
      const levelOrder = { CRITICAL: 0, HIGH: 1, MED: 2, LOW: 3 };
      const levelDiff = levelOrder[a.level] - levelOrder[b.level];
      if (levelDiff !== 0) return levelDiff;
      return b.cpu - a.cpu;
    });

    processStore.updateProcesses(rows);

    // Calculate next scan interval based on threat level
    const nextInterval = calculateNextScanInterval(rows, procs.length);
    updateScanInterval(nextInterval);
  } catch (err) {
    logger.error({ err }, 'Process scan error');
  }
}

/**
 * Calculate the next scan interval based on current threat levels
 */
function calculateNextScanInterval(processes: ProcessWireFormat[], totalProcessCount: number): number {
  // Count threats by level
  const threatCounts = {
    critical: 0,
    high: 0,
    med: 0,
    low: 0
  };

  for (const proc of processes) {
    switch (proc.level) {
      case 'CRITICAL':
        threatCounts.critical++;
        break;
      case 'HIGH':
        threatCounts.high++;
        break;
      case 'MED':
        threatCounts.med++;
        break;
      case 'LOW':
        threatCounts.low++;
        break;
    }
  }

  // Determine interval based on threat priority
  let interval: number;

  if (threatCounts.critical > 0) {
    // CRITICAL threats detected - scan frequently
    interval = SCAN_INTERVAL.CRITICAL;
  } else if (threatCounts.high > 0) {
    // HIGH threats detected - scan more frequently
    interval = SCAN_INTERVAL.HIGH;
  } else if (totalProcessCount < 100 && threatCounts.med === 0) {
    // Idle system - few processes and no medium/high threats
    interval = SCAN_INTERVAL.IDLE;
  } else {
    // Normal operation - only medium/low threats
    interval = SCAN_INTERVAL.NORMAL;
  }

  // Apply safety bounds
  interval = Math.max(SCAN_INTERVAL.MIN, Math.min(SCAN_INTERVAL.MAX, interval));

  return interval;
}

/**
 * Update the scan interval and log changes
 */
function updateScanInterval(newInterval: number) {
  if (newInterval !== currentScanInterval) {
    const oldSeconds = (currentScanInterval / 1000).toFixed(1);
    const newSeconds = (newInterval / 1000).toFixed(1);

    let reason = '';
    if (newInterval === SCAN_INTERVAL.CRITICAL) {
      reason = 'CRITICAL threats detected';
    } else if (newInterval === SCAN_INTERVAL.HIGH) {
      reason = 'HIGH threats detected';
    } else if (newInterval === SCAN_INTERVAL.IDLE) {
      reason = 'Idle system';
    } else {
      reason = 'Normal operation';
    }

    logger.info({
      oldInterval: `${oldSeconds}s`,
      newInterval: `${newSeconds}s`,
      reason
    }, 'Scan frequency changed');
    currentScanInterval = newInterval;
  }
}