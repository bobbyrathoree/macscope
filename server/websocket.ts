import type { FastifyRequest } from 'fastify';
import type { WebSocket } from 'ws';
import { processStore } from './store.js';

interface ProcessRow {
  pid: number;
  ppid?: number;
  name: string;
  cmd: string;
  user: string;
  cpu: number;
  mem: number;
  execPath?: string;
  connections: {
    outbound: number;
    listen: number;
    remotes: string[];
  };
  level: string;
  reasons: string[];
  launchd?: string;
  codesign?: {
    signed: boolean;
    valid: boolean;
    teamId?: string;
    notarized?: boolean;
    appStore?: boolean;
  };
  parent?: string;
}

interface Delta {
  added: ProcessRow[];
  updated: ProcessRow[];
  removed: number[];
}

function computeDelta(oldProcesses: ProcessRow[], newProcesses: ProcessRow[]): Delta {
  const oldMap = new Map(oldProcesses.map(p => [p.pid, p]));
  const newMap = new Map(newProcesses.map(p => [p.pid, p]));

  const added: ProcessRow[] = [];
  const updated: ProcessRow[] = [];
  const removed: number[] = [];

  // Find added and updated processes
  for (const newProc of newProcesses) {
    const oldProc = oldMap.get(newProc.pid);
    if (!oldProc) {
      // New process
      added.push(newProc);
    } else if (JSON.stringify(oldProc) !== JSON.stringify(newProc)) {
      // Process changed
      updated.push(newProc);
    }
  }

  // Find removed processes
  for (const oldProc of oldProcesses) {
    if (!newMap.has(oldProc.pid)) {
      removed.push(oldProc.pid);
    }
  }

  return { added, updated, removed };
}

export async function websocketHandler(socket: WebSocket, request: FastifyRequest) {
  let lastSentProcesses: ProcessRow[] = [];

  // Send initial data immediately
  try {
    const initialData = processStore.getProcesses();
    lastSentProcesses = initialData;
    socket.send(JSON.stringify({
      type: 'initial',
      data: initialData
    }));
  } catch (err) {
    // Socket might be closed already
    return;
  }

  // Subscribe to updates
  const unsubscribe = processStore.subscribe((processes) => {
    if (socket.readyState === socket.OPEN) {
      try {
        // Compute delta from last sent state
        const delta = computeDelta(lastSentProcesses, processes);

        // Only send if there are changes
        if (delta.added.length > 0 || delta.updated.length > 0 || delta.removed.length > 0) {
          socket.send(JSON.stringify({
            type: 'delta',
            data: delta
          }));

          // Update last sent state
          lastSentProcesses = processes;
        }
      } catch (err) {
        // Socket closed, will be cleaned up
      }
    }
  });

  // Handle client messages
  socket.on('message', (message) => {
    try {
      const data = JSON.parse(message.toString());

      switch (data.type) {
        case 'ping':
          if (socket.readyState === socket.OPEN) {
            socket.send(JSON.stringify({ type: 'pong' }));
          }
          break;
      }
    } catch (err) {
      // Ignore message parsing errors
    }
  });

  socket.on('close', () => {
    unsubscribe();
  });

  socket.on('error', (err) => {
    unsubscribe();
  });
}