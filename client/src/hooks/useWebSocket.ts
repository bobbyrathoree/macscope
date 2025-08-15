import { useEffect, useRef } from 'react';
import type { ProcessData } from '../types';

interface WebSocketMessage {
  type: 'initial' | 'update' | 'pong';
  data?: ProcessData[];
}

// Singleton WebSocket connection
let globalWs: WebSocket | null = null;
let globalSubscribers: Set<(data: WebSocketMessage) => void> = new Set();
let connectAttempts = 0;

export function useWebSocket(onMessage: (data: WebSocketMessage) => void) {
  const callbackRef = useRef(onMessage);
  callbackRef.current = onMessage;
  
  useEffect(() => {
    // Add this component's callback to global subscribers
    globalSubscribers.add(callbackRef.current);
    
    // If no global WebSocket exists, create one
    if (!globalWs) {
      createGlobalWebSocket();
    }
    
    return () => {
      // Remove this component's callback
      globalSubscribers.delete(callbackRef.current);
      
      // If no more subscribers, close the WebSocket
      if (globalSubscribers.size === 0 && globalWs) {
        globalWs.close(1000, 'No more subscribers');
        globalWs = null;
      }
    };
  }, []);
  
  return globalWs;
}

function createGlobalWebSocket() {
  if (globalWs || connectAttempts >= 5) return;
  
  connectAttempts++;
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//localhost:3000/ws`;
  globalWs = new WebSocket(wsUrl);
  
  globalWs.onopen = () => {
    connectAttempts = 0;
  };
  
  globalWs.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      // Notify all subscribers
      globalSubscribers.forEach(callback => callback(data));
    } catch (err) {
      console.error('Failed to parse WebSocket message:', err);
    }
  };
  
  globalWs.onclose = (event) => {
    globalWs = null;
    
    if (event.wasClean || event.code === 1000) {
      return; // Clean close, don't reconnect
    }
    
    // Only reconnect if we still have subscribers
    if (globalSubscribers.size > 0) {
      const delay = Math.min(2000 * connectAttempts, 10000);
      setTimeout(createGlobalWebSocket, delay);
    }
  };
  
  globalWs.onerror = () => {
    // Error handling is done in onclose
  };
}