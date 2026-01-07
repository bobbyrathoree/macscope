import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { NetworkStats } from './types';
import { logError } from './error-logger';

const execFileP = promisify(execFile);

export async function getNetworkStats(): Promise<Map<number, NetworkStats>> {
  const stats = new Map<number, NetworkStats>();
  
  try {
    // Use nettop to get network statistics per process
    // nettop provides real-time network usage data
    const { stdout } = await execFileP('nettop', ['-P', '-L', '1', '-J', 'bytes_in,bytes_out'], {
      timeout: 2000
    });
    
    const lines = stdout.split('\n');
    const timestamp = new Date();
    
    for (const line of lines) {
      // Parse nettop output format
      // Format: <process>.<pid> <bytes_in> <bytes_out>
      const match = line.match(/^(.+)\.(\d+)\s+(\d+)\s+(\d+)/);
      if (match && match[2] && match[3] && match[4]) {
        const pid = parseInt(match[2], 10);
        const bytesIn = parseInt(match[3], 10);
        const bytesOut = parseInt(match[4], 10);
        
        stats.set(pid, {
          pid,
          bytesIn,
          bytesOut,
          packetsIn: 0, // nettop doesn't provide packet counts in this mode
          packetsOut: 0,
          timestamp
        });
      }
    }
  } catch (error) {
    await logError('network:getNetworkStats:nettop', error);
    // Fallback to netstat if nettop fails
    try {
      await execFileP('netstat', ['-n', '-b']);
      // Basic parsing - this is less detailed than nettop
      // netstat doesn't provide per-process byte counts on macOS
      // Network stats via nettop failed, using basic netstat
    } catch (netstatError) {
      await logError('network:getNetworkStats:netstat-fallback', netstatError);
      // Network monitoring not available
    }
  }
  
  return stats;
}

export async function getNetworkConnections(pid: number): Promise<{
  connections: Array<{
    protocol: string;
    localAddr: string;
    remoteAddr: string;
    state: string;
  }>;
  summary: {
    tcpCount: number;
    udpCount: number;
    listeningPorts: string[];
    establishedCount: number;
  };
}> {
  const connections: Array<{
    protocol: string;
    localAddr: string;
    remoteAddr: string;
    state: string;
  }> = [];
  
  let tcpCount = 0;
  let udpCount = 0;
  const listeningPorts: string[] = [];
  let establishedCount = 0;
  
  try {
    // Use lsof to get detailed connection info for a specific PID
    const { stdout } = await execFileP('lsof', ['-nPi', '-p', String(pid)]);
    const lines = stdout.split('\n').slice(1); // Skip header
    
    for (const line of lines) {
      if (!line.trim()) continue;
      
      const parts = line.split(/\s+/);
      if (parts.length < 9) continue;
      
      const protocol = parts[7]?.toLowerCase() || '';
      const addresses = parts[8] || '';
      
      if (protocol.includes('tcp')) {
        tcpCount++;
        const [localAddr, remoteAddr] = addresses.split('->');
        const state = parts[9] || 'UNKNOWN';
        
        connections.push({
          protocol: 'TCP',
          localAddr: localAddr || '',
          remoteAddr: remoteAddr || '',
          state
        });
        
        if (state === 'ESTABLISHED') {
          establishedCount++;
        } else if (state === 'LISTEN' && localAddr) {
          const port = localAddr.split(':').pop();
          if (port) listeningPorts.push(port);
        }
      } else if (protocol.includes('udp')) {
        udpCount++;
        connections.push({
          protocol: 'UDP',
          localAddr: addresses,
          remoteAddr: '',
          state: 'N/A'
        });
      }
    }
  } catch (error) {
    await logError('network:getNetworkConnections', error);
    // Process might have ended or no permissions
  }
  
  return {
    connections,
    summary: {
      tcpCount,
      udpCount,
      listeningPorts,
      establishedCount
    }
  };
}

export function analyzeNetworkBehavior(
  current: NetworkStats,
  previous?: NetworkStats
): {
  bytesPerSecond: { in: number; out: number };
  isSuspicious: boolean;
  reasons: string[];
} {
  const reasons: string[] = [];
  let bytesInPerSec = 0;
  let bytesOutPerSec = 0;
  
  if (previous) {
    const timeDiff = (current.timestamp.getTime() - previous.timestamp.getTime()) / 1000;
    if (timeDiff > 0) {
      bytesInPerSec = (current.bytesIn - previous.bytesIn) / timeDiff;
      bytesOutPerSec = (current.bytesOut - previous.bytesOut) / timeDiff;
      
      // Suspicious patterns
      // High upload rate (possible data exfiltration)
      if (bytesOutPerSec > 10_000_000) { // 10 MB/s
        reasons.push('high-upload-rate');
      }
      
      // Asymmetric traffic (much more upload than download)
      if (bytesOutPerSec > bytesInPerSec * 10 && bytesOutPerSec > 1_000_000) {
        reasons.push('asymmetric-upload');
      }
      
      // Continuous low-rate transfer (possible covert channel)
      if (bytesOutPerSec > 1000 && bytesOutPerSec < 10000) {
        reasons.push('steady-low-rate-transfer');
      }
    }
  }
  
  // Check absolute values
  if (current.bytesOut > 100_000_000) { // 100 MB total
    reasons.push('large-data-transfer');
  }
  
  return {
    bytesPerSecond: {
      in: bytesInPerSec,
      out: bytesOutPerSec
    },
    isSuspicious: reasons.length > 0,
    reasons
  };
}