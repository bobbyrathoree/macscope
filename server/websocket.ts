import type { FastifyRequest } from 'fastify';
import type { WebSocket } from 'ws';
import { processStore } from './store.js';

export async function websocketHandler(socket: WebSocket, request: FastifyRequest) {
  // Send initial data immediately
  try {
    socket.send(JSON.stringify({
      type: 'initial',
      data: processStore.getProcesses()
    }));
  } catch (err) {
    // Socket might be closed already
    return;
  }
  
  // Subscribe to updates
  const unsubscribe = processStore.subscribe((processes) => {
    if (socket.readyState === socket.OPEN) {
      try {
        socket.send(JSON.stringify({
          type: 'update',
          data: processes
        }));
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