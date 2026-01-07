import type { FastifyRequest } from 'fastify';
import type { WebSocket } from 'ws';
import type { ProcessWireFormat, Delta } from '../shared/types.js';
import { processStore } from './store.js';

// Connection limiting to prevent DoS attacks
const MAX_CONNECTIONS = 100;
const activeConnections = new Set<WebSocket>();

/**
 * Get the current number of active WebSocket connections
 */
export function getConnectionCount(): number {
  return activeConnections.size;
}

function computeDelta(oldProcesses: ProcessWireFormat[], newProcesses: ProcessWireFormat[]): Delta {
  const oldMap = new Map(oldProcesses.map(p => [p.pid, p]));
  const newMap = new Map(newProcesses.map(p => [p.pid, p]));

  const added: ProcessWireFormat[] = [];
  const updated: ProcessWireFormat[] = [];
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
  // Check connection limit
  if (activeConnections.size >= MAX_CONNECTIONS) {
    console.warn(
      `[WebSocket] Connection rejected: limit reached (${activeConnections.size}/${MAX_CONNECTIONS}) from ${request.ip}`
    );
    socket.close(1008, 'Connection limit reached');
    return;
  }

  // Add connection to tracking set
  activeConnections.add(socket);
  console.log(`[WebSocket] Connection established (${activeConnections.size}/${MAX_CONNECTIONS}) from ${request.ip}`);

  let lastSentProcesses: ProcessWireFormat[] = [];
  let lastResponseTime = Date.now();
  let heartbeatInterval: NodeJS.Timeout | null = null;
  let checkAliveInterval: NodeJS.Timeout | null = null;

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

  // Heartbeat mechanism: Send ping every 30 seconds
  heartbeatInterval = setInterval(() => {
    if (socket.readyState === socket.OPEN) {
      try {
        socket.send(JSON.stringify({ type: 'heartbeat' }));
      } catch (err) {
        // Socket closed, will be cleaned up
      }
    }
  }, 30000);

  // Check if client is still alive: Close if no response in 35 seconds
  checkAliveInterval = setInterval(() => {
    const timeSinceLastResponse = Date.now() - lastResponseTime;
    if (timeSinceLastResponse > 35000) {
      console.log('[WebSocket] Client has not responded in 35 seconds, closing connection');
      socket.close();
    }
  }, 5000); // Check every 5 seconds

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
        case 'pong':
          // Update last response time when client responds to heartbeat
          lastResponseTime = Date.now();
          break;
      }
    } catch (err) {
      // Ignore message parsing errors
    }
  });

  // Cleanup function
  const cleanup = () => {
    activeConnections.delete(socket);
    unsubscribe();
    if (heartbeatInterval) {
      clearInterval(heartbeatInterval);
      heartbeatInterval = null;
    }
    if (checkAliveInterval) {
      clearInterval(checkAliveInterval);
      checkAliveInterval = null;
    }
  };

  socket.on('close', () => {
    console.log(`[WebSocket] Connection closed (${activeConnections.size}/${MAX_CONNECTIONS})`);
    cleanup();
  });

  socket.on('error', (err) => {
    console.log(`[WebSocket] Connection error (${activeConnections.size}/${MAX_CONNECTIONS}):`, err.message);
    cleanup();
  });
}