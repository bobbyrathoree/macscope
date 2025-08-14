
import psList from 'ps-list';
import os from 'node:os';

export type ProcInfo = { pid: number; ppid?: number; name?: string; cmd?: string; user?: string; cpu?: number; mem?: number; execPath?: string; };

export async function listProcesses(): Promise<ProcInfo[]> {
  const all = await psList();
  const totalMem = os.totalmem();
  return all.map((p:any)=>{
    const memPct = p.memory ? (p.memory / totalMem * 100) : 0;
    const execPath = extractExecPath(p.cmd || '');
    return { pid:p.pid, ppid:p.ppid, name:p.name, cmd:p.cmd, user:p.username||p.uid||'', cpu:p.cpu||0, mem:memPct, execPath };
  });
}
function extractExecPath(cmd: string): string|undefined {
  if (!cmd) return undefined;
  const token = cmd.trim().split(' ')[0].replace(/^"|"$/g, '');
  if (token.startsWith('/')) return token;
  if (token.endsWith('.app')) return token;
  return undefined;
}
