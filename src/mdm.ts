
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const execFileP = promisify(execFile);
export async function getMdmSummary(): Promise<string> {
  try {
    const {stdout} = await execFileP('profiles', ['status', '-type', 'enrollment']);
    return stdout.trim();
  } catch {
    try {
      const {stdout} = await execFileP('system_profiler', ['SPConfigurationProfileDataType']);
      return stdout.split('\n').slice(0, 30).join('\n');
    } catch {
      return 'MDM status unavailable (requires macOS and appropriate permissions).';
    }
  }
}
