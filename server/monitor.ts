import { listProcesses } from '../src/proc.js';
import { getConnectionSummary } from '../src/conns.js';
import { collectLaunchDaemons } from '../src/launchctl.js';
import { getCodeSignInfo } from '../src/codesign.js';
import { analyzeSecurity } from '../src/security.js';
import { logSuspiciousProcess, initLogger } from '../src/logger.js';
import { processStore } from './store.js';
import type { ProcessWireFormat, CodesignInfo } from '../shared/types.js';
import type { ProcInfo, ConnSummary } from '../src/types.js';

let monitorInterval: NodeJS.Timeout | null = null;

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
  
  // Initial scan
  scanProcesses();
  
  // Update every 10 seconds to reduce system load
  monitorInterval = setInterval(scanProcesses, 10000);
  
  console.log('📊 Process monitor started');
}

export function stopProcessMonitor() {
  if (monitorInterval) {
    clearInterval(monitorInterval);
    monitorInterval = null;
    console.log('📊 Process monitor stopped');
  }
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
                csig = await Promise.race([
                  getCodeSignInfo(proc.execPath || proc.cmd || ''),
                  new Promise<CodesignInfo>((_, reject) => setTimeout(() => reject(new Error('Codesign timeout')), 2000))
                ]) as CodesignInfo;
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
            }).catch(err => console.error('Logging error:', err));
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
    console.log(`Process analysis: ${analyzedCount} analyzed, ${cachedCount} cached (${cacheHitRate}% cache hit rate)`);

    // Sort by suspicion level and CPU usage
    rows.sort((a, b) => {
      const levelOrder = { CRITICAL: 0, HIGH: 1, MED: 2, LOW: 3 };
      const levelDiff = levelOrder[a.level] - levelOrder[b.level];
      if (levelDiff !== 0) return levelDiff;
      return b.cpu - a.cpu;
    });

    processStore.updateProcesses(rows);
  } catch (err) {
    console.error('Process scan error:', err);
  }
}