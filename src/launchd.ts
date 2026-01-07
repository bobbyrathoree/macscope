
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {logError} from './error-logger.js';
const execFileP = promisify(execFile);
export async function getLaunchdMap(): Promise<Record<string,string>> {
  try {
    const {stdout} = await execFileP('launchctl', ['list']);
    const lines = stdout.split('\n').slice(1);
    const map: Record<string,string> = {};
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3) {
        const pid = parts[0]; const label = parts.slice(2).join(' ');
        if (pid && pid !== '-' && /^\d+$/.test(pid)) {
          map[pid] = label;
        }
      }
    }
    return map;
  } catch (error) {
    await logError('launchd:getLaunchdMap', error);
    return {};
  }
}
