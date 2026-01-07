import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const execFileP = promisify(execFile);

export type ConnSummary = {
  outbound: number;
  listen: number;
  sampleRemotes: Set<string>;
};

export async function getConnectionSummary(): Promise<Map<number, ConnSummary>> {
  const map = new Map<number, ConnSummary>();
  
  try {
    const { stdout } = await execFileP('lsof', ['-iTCP', '-iUDP', '-n', '-P'], {
      maxBuffer: 1024 * 1024 * 10,
      timeout: 8000 // 8 second timeout to prevent hanging
    });
    
    const lines = stdout.split('\n').slice(1);
    
    for (const line of lines) {
      const parts = line.split(/\s+/);
      if (parts.length < 9) continue; // Reduced from 10

      const pid = parseInt(parts[1] || '0');
      if (isNaN(pid)) continue;
      
      // lsof output format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
      // So NAME is at index 8, not necessarily parts[8] due to variable spacing
      const name = parts[parts.length - 1]; // Use last part as NAME
      if (!name) continue;
      
      if (!map.has(pid)) {
        map.set(pid, { outbound: 0, listen: 0, sampleRemotes: new Set() });
      }
      
      const summary = map.get(pid)!;
      
      if (name.includes('LISTEN')) {
        summary.listen++;
      } else if (name.includes('->')) {
        summary.outbound++;
        const remote = name.split('->')[1] || '';
        if (remote && summary.sampleRemotes.size < 10) {
          summary.sampleRemotes.add(remote);
        }
      } else if (name.includes(':') && !name.includes('LISTEN')) {
        // Count other network connections (UDP, established TCP, etc.)
        summary.outbound++;
      }
    }
  } catch (err) {
    console.error('🚨 lsof error:', err);
  }
  
  return map;
}