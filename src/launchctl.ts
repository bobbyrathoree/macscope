import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const execFileP = promisify(execFile);

export async function collectLaunchDaemons(): Promise<Map<number, string>> {
  const map = new Map<number, string>();
  
  try {
    const { stdout } = await execFileP('launchctl', ['list'], {
      timeout: 5000 // 5 second timeout to prevent hanging
    });
    const lines = stdout.split('\n').slice(1);
    
    for (const line of lines) {
      const parts = line.split(/\t/);
      if (parts.length < 3) continue;
      
      const pid = parseInt(parts[0]);
      if (isNaN(pid) || pid === -1) continue;
      
      const label = parts[2];
      if (label) {
        map.set(pid, label);
      }
    }
  } catch (err) {
    // launchctl might fail
  }
  
  return map;
}