import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {logError} from './error-logger.js';
const execFileP = promisify(execFile);
export type ConnSummary = { listen: number; outbound: number; sampleRemotes: Set<string>; };
export async function getConnectionsByPid(): Promise<Record<number, ConnSummary>> {
  try {
    const {stdout} = await execFileP('lsof', ['-nPi', '-F', 'pcPnT']);
    const lines = stdout.split('\n');
    const map: Record<number, ConnSummary> = {};
    let pid = -1;
    for (const line of lines) {
      if (!line) continue;
      const tag = line[0], val = line.slice(1);
      if (tag==='p'){ pid = parseInt(val,10); if (!map[pid]) map[pid]={listen:0,outbound:0,sampleRemotes:new Set()}; }
      else if (tag==='n' && pid>0){
        if (val.includes('->')){ 
          const remote = val.split('->')[1]; 
          if (remote) {
            map[pid]!.outbound++; 
            const host = remote.split(':')[0];
            if (host) {
              map[pid]!.sampleRemotes.add(host); 
            }
          }
        }
        else { map[pid]!.listen++; }
      }
    }
    return map;
  } catch (error) {
    await logError('lsof:getConnectionsByPid', error);
    return {};
  }
}