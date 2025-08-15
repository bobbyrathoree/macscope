import psList from 'ps-list';
import os from 'node:os';

export type ProcInfo = { pid: number; ppid?: number; name?: string; cmd?: string; user?: string; cpu?: number; mem?: number; execPath?: string; };

export async function listProcesses(): Promise<ProcInfo[]> {
  const all = await psList();
  const totalMem = os.totalmem();
  return all.map((p:any)=>{
    const memPct = p.memory ? (p.memory / totalMem * 100) : 0;
    const execPath = extractExecPath(p.cmd || '');
    const result: ProcInfo = { pid:p.pid, ppid:p.ppid, name:p.name, cmd:p.cmd, user:p.username||p.uid||'', cpu:p.cpu||0, mem:memPct };
    if (execPath) result.execPath = execPath;
    return result;
  });
}
function extractExecPath(cmd: string): string|undefined {
  if (!cmd) return undefined;
  const token = cmd.trim().split(' ')[0];
  if (!token) return undefined;
  const cleanToken = token.replace(/^"|"$/g, '');
  if (cleanToken.startsWith('/')) return cleanToken;
  if (cleanToken.endsWith('.app')) return cleanToken;
  return undefined;
}
