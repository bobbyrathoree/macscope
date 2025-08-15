import { listProcesses } from '../src/proc.js';
import { getConnectionSummary } from '../src/conns.js';
import { collectLaunchDaemons } from '../src/launchctl.js';
import { getCodeSignInfo } from '../src/codesign.js';
import { analyzeSecurity } from '../src/security.js';
import { logSuspiciousProcess, initLogger } from '../src/logger.js';
import { processStore } from './store.js';
import type { ProcessRow } from '../src/types.js';

let monitorInterval: NodeJS.Timeout | null = null;

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
    
    const [procs, conns, launchInfo] = await Promise.race([scanPromise, timeoutPromise]);
    
    // Build parent map for process injection detection
    const parentMap = new Map<number, typeof procs[0]>();
    for (const proc of procs) {
      if (proc.ppid) {
        parentMap.set(proc.pid, procs.find(p => p.pid === proc.ppid));
      }
    }
    
    // Limit process analysis to prevent system overload
    const limitedProcs = procs.slice(0, 200); // Limit to 200 processes max
    
    // Analyze each process with concurrency control
    const rows: ProcessRow[] = [];
    const batchSize = 10; // Process in small batches
    
    for (let i = 0; i < limitedProcs.length; i += batchSize) {
      const batch = limitedProcs.slice(i, i + batchSize);
      const batchResults = await Promise.all(
        batch.map(async (proc) => {
          const conn = conns.get(proc.pid);
          const launchd = launchInfo.get(proc.pid);
          const parent = parentMap.get(proc.pid);
          
          // Only get code signature for highly suspicious processes to prevent overload
          let csig = null;
          if (conn && conn.outbound > 50) { // Much higher threshold
            try {
              csig = await Promise.race([
                getCodeSignInfo(proc.execPath || proc.cmd || ''),
                new Promise((_, reject) => setTimeout(() => reject(new Error('Codesign timeout')), 2000))
              ]);
            } catch (err) {
              // Skip codesign on timeout/error
              csig = null;
            }
          }
        
          const suspicion = await analyzeSecurity(proc, conn, launchd, csig, parent);
          
          // Log HIGH and CRITICAL processes (but don't await to prevent blocking)
          if (suspicion.level === 'HIGH' || suspicion.level === 'CRITICAL') {
            logSuspiciousProcess({
              ...proc,
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
              valid: csig.valid,
              teamId: csig.teamIdentifier,
              notarized: csig.notarized,
              appStore: csig.appStore
            } : undefined,
            parent: parent?.name
          };
        })
      );
      rows.push(...batchResults);
    }
    
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