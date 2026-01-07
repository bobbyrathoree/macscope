#!/usr/bin/env tsx
import React, {useEffect, useMemo, useState, useCallback, useRef} from 'react';
import {render, Box, Text, useInput, useApp} from 'ink';
import TextInput from 'ink-text-input';
import isRoot from 'is-root';
import {listProcesses} from './proc';
import {getLaunchdMap} from './launchd';
import {getConnectionsByPid} from './lsof';
import {getCodesignInfo} from './codesign';
import {getMdmSummary} from './mdm';
import {analyzeSecurity} from './security';
import {ProcessRow, SuspicionLevel, CodesignInfo} from './types';
import {initLogger, logSuspiciousProcess, cleanupOldLogs} from './logger';

const header = () => (
  <Box flexDirection="column">
    <Text><Text color="cyanBright">procscope</Text> <Text dimColor>(Ink + React)</Text></Text>
    <Text dimColor>Type to filter • ↑/↓ select • Enter details • r refresh • m MDM • q quit</Text>
    {!isRoot() ? <Text color="yellow">Tip: run with sudo for fuller visibility.</Text> : <Text color="green">Running as root.</Text>}
  </Box>
);

function pct(n?: number){ return typeof n==='number' ? n.toFixed(1) : '' }

function getSuspicionColor(level: SuspicionLevel): string {
  switch (level) {
    case 'CRITICAL': return 'red';
    case 'HIGH': return 'yellow';
    case 'MED': return 'cyan';
    default: return 'gray';
  }
}

const VISIBLE_ROWS = 25; // Number of rows to display at once
const REFRESH_INTERVAL = 3000; // Slower refresh to reduce flicker (3 seconds)

const App: React.FC = () => {
  const {exit} = useApp();
  const [filter,setFilter]=useState('');
  const [rows,setRows]=useState<ProcessRow[]>([]);
  const [sel,setSel]=useState(0);
  const [scrollOffset, setScrollOffset] = useState(0);
  const [mdm,setMdm]=useState<string|null>(null);
  const [logStatus, setLogStatus] = useState<string>('');
  const lastRowsRef = useRef<ProcessRow[]>([]);

  const refresh = useCallback(async ()=>{
    const [plist,lmap,conns] = await Promise.all([
      listProcesses(),
      getLaunchdMap().catch(()=>({})),
      getConnectionsByPid().catch(()=>({}))
    ]);
    const procMap = new Map(plist.map(p => [p.pid, p]));
    
    const rs = await Promise.all(plist.map(async p => {
      const launchd = (lmap as any)[String(p.pid)];
      const conn = (conns as any)[p.pid];
      const parentProc = p.ppid ? procMap.get(p.ppid) : undefined;
      const suspicion = await analyzeSecurity(p, conn, launchd, undefined, parentProc);
      
      return {...p, launchd, conn, suspicion, parentName: parentProc?.name} as ProcessRow;
    }));
    
    // Sort by suspicion level first, then CPU
    rs.sort((a, b) => {
      const levelOrder = {'CRITICAL': 0, 'HIGH': 1, 'MED': 2, 'LOW': 3};
      const levelDiff = levelOrder[a.suspicion.level] - levelOrder[b.suspicion.level];
      if (levelDiff !== 0) return levelDiff;
      return (b.cpu || 0) - (a.cpu || 0);
    });
    
    // Log suspicious processes
    const suspiciousCount = rs.filter(r => 
      r.suspicion.level === 'HIGH' || r.suspicion.level === 'CRITICAL'
    ).length;
    
    for (const row of rs) {
      await logSuspiciousProcess(row);
    }
    
    // Only update if processes have changed significantly
    const hasChanged = rs.length !== lastRowsRef.current.length || 
      rs.some((r, i) => {
        const prev = lastRowsRef.current[i];
        return !prev || r.pid !== prev.pid || r.suspicion.level !== prev.suspicion.level;
      });
    
    if (hasChanged) {
      lastRowsRef.current = rs;
      setRows(rs);
      if (suspiciousCount > 0) {
        setLogStatus(`⚠️ Logged ${suspiciousCount} suspicious processes`);
        setTimeout(() => setLogStatus(''), 3000);
      }
    }
  },[]);

  useEffect(()=>{ 
    initLogger(); // Initialize logging
    cleanupOldLogs(); // Clean up old logs on startup
    refresh(); 
    const t=setInterval(refresh, REFRESH_INTERVAL); 
    return ()=>clearInterval(t);
  },[refresh]);

  useInput(async (input,key)=>{
    if (input==='q'||key.escape) exit();
    if (input==='r') refresh();
    if (input==='m'){ const s = await getMdmSummary().catch(()=>null); setMdm(s); setTimeout(()=>setMdm(null),8000); }
    
    if (key.downArrow) {
      setSel(s => {
        const newSel = Math.min(s + 1, view.length - 1);
        // Auto-scroll when reaching bottom of visible area
        if (newSel >= scrollOffset + VISIBLE_ROWS - 5) {
          setScrollOffset(Math.min(newSel - VISIBLE_ROWS + 5, Math.max(0, view.length - VISIBLE_ROWS)));
        }
        return newSel;
      });
    }
    
    if (key.upArrow) {
      setSel(s => {
        const newSel = Math.max(s - 1, 0);
        // Auto-scroll when reaching top of visible area
        if (newSel < scrollOffset + 5) {
          setScrollOffset(Math.max(newSel - 5, 0));
        }
        return newSel;
      });
    }
    
    // Page Down
    if (key.pageDown) {
      const jump = Math.min(VISIBLE_ROWS - 5, view.length - sel - 1);
      setSel(s => s + jump);
      setScrollOffset(o => Math.min(o + jump, Math.max(0, view.length - VISIBLE_ROWS)));
    }
    
    // Page Up
    if (key.pageUp) {
      const jump = Math.min(VISIBLE_ROWS - 5, sel);
      setSel(s => s - jump);
      setScrollOffset(o => Math.max(o - jump, 0));
    }
    
    if (key.return){
      const id = view[sel]?.pid; if (!id) return;
      setRows(r=>r.map((row)=>row.pid===id?{...row, expanded:!row.expanded}:row));
      const row = rows.find((r)=>r.pid===id);
      if (row && row.expanded && row.csig===undefined && row.execPath){
        const info = await getCodesignInfo(row.execPath).catch(()=>null);
        setRows(r=>r.map((rr)=>rr.pid===id?{...rr, csig:info as CodesignInfo}:rr));
      }
    }
  });

  const view = useMemo(()=>{
    const f = filter.trim().toLowerCase();
    const arr = !f? rows : rows.filter((r)=>
      String(r.name||'').toLowerCase().includes(f) ||
      String(r.cmd||'').toLowerCase().includes(f) ||
      String(r.pid).includes(f) ||
      String(r.launchd||'').toLowerCase().includes(f) ||
      r.suspicion.reasons.some(reason => reason.toLowerCase().includes(f))
    );
    return arr; // Don't slice here, we'll handle windowing in display
  },[rows,filter]);
  
  // Get the visible window of processes
  const visibleRows = useMemo(() => {
    return view.slice(scrollOffset, scrollOffset + VISIBLE_ROWS);
  }, [view, scrollOffset]);

  return (
    <Box flexDirection="column">
      {header()}
      <Box marginTop={1}>
        <Text>Filter: </Text>
        <TextInput value={filter} onChange={setFilter}/>
        <Text dimColor> [{sel + 1}/{view.length}] {view.length > VISIBLE_ROWS && `(↑↓ PgUp/PgDn to scroll)`}</Text>
      </Box>
      <Box flexDirection="column" borderStyle="round" marginTop={1}>
        <Text bold>{'  PID'.padEnd(8)}{'USER'.padEnd(12)}{'CPU%'.padEnd(7)}{'MEM%'.padEnd(7)}{'CONN'.padEnd(7)}{'LVL'.padEnd(5)}{'NAME'.padEnd(20)}{'LABEL/PARENT'.padEnd(28)}</Text>
        {visibleRows.map((r,visIdx:number)=>{
          const actualIdx = scrollOffset + visIdx;
          const isSelected = actualIdx === sel;
          return (
          <Box key={r.pid} flexDirection="column">
            <Text inverse={isSelected}>
              {' '}{String(r.pid).padEnd(7)}{String(r.user||'').slice(0,10).padEnd(12)}{pct(r.cpu).padEnd(7)}{pct(r.mem).padEnd(7)}{String((r.conn?.outbound||0)+(r.conn?.listen||0)).padEnd(7)}
              <Text color={getSuspicionColor(r.suspicion.level)}>{r.suspicion.level.padEnd(5)}</Text>
              {String(r.name||'').slice(0,18).padEnd(20)}{String(r.launchd || r.parentName || '').slice(0,26).padEnd(28)}
            </Text>
            {r.expanded && (
              <Box flexDirection="column" paddingLeft={2} marginBottom={1}>
                <Text>cmd: {r.cmd||''}</Text>
                {r.execPath ? <Text>exec: {r.execPath}</Text> : null}
                {r.conn ? <Text>net: listens={r.conn.listen} outbound={r.conn.outbound} sampleRemotes={[...r.conn.sampleRemotes].slice(0,5).join(', ')}</Text> : null}
                {r.parentName ? <Text>parent: {r.parentName} (ppid: {r.ppid})</Text> : null}
                {r.csig ? (
                  <Text>
                    codesign: team={r.csig.teamIdentifier||'-'} 
                    {r.csig.signed === false && <Text color="yellow"> UNSIGNED</Text>}
                    {r.csig.valid === false && <Text color="red"> INVALID</Text>}
                    {r.csig.notarized && <Text color="green"> NOTARIZED</Text>}
                  </Text>
                ) : <Text dimColor>codesign: checking...</Text>}
                <Text color={getSuspicionColor(r.suspicion.level)}>
                  suspicion: {r.suspicion.level} - {r.suspicion.reasons.join(', ')||'none'}
                </Text>
              </Box>
            )}
          </Box>
        )})}
      </Box>
      {logStatus && <Box marginTop={1}><Text color="yellow">{logStatus}</Text></Box>}
      {mdm && <Box marginTop={1} borderStyle="round"><Text>{mdm}</Text></Box>}
      <Box marginTop={1}>
        <Text dimColor>
          Logs: ~/.procscope/suspicious-processes.log • 
          {' '}Processes marked HIGH/CRITICAL are logged automatically
        </Text>
      </Box>
    </Box>
  );
};

render(<App />);
