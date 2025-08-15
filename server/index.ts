import Fastify from 'fastify';
import websocketPlugin from '@fastify/websocket';
import corsPlugin from '@fastify/cors';
import staticPlugin from '@fastify/static';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { processRoutes } from './routes/processes.js';
import { websocketHandler } from './websocket.js';
import { startProcessMonitor, stopProcessMonitor } from './monitor.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const fastify = Fastify({
  logger: {
    level: process.env.NODE_ENV === 'production' ? 'warn' : 'warn'
  },
  // Prevent memory leaks and resource exhaustion
  connectionTimeout: 30000,
  keepAliveTimeout: 5000,
  maxParamLength: 1000,
  bodyLimit: 1048576, // 1MB limit
});

async function start() {
  // Register plugins
  await fastify.register(corsPlugin, {
    origin: process.env.NODE_ENV === 'production' ? false : 'http://localhost:5173'
  });
  
  await fastify.register(websocketPlugin);
  
  // API routes
  await fastify.register(processRoutes, { prefix: '/api' });
  
  // WebSocket endpoint
  fastify.register(async function (fastify) {
    fastify.get('/ws', { websocket: true }, websocketHandler);
  });
  
  // Serve static files in production
  if (process.env.NODE_ENV === 'production') {
    await fastify.register(staticPlugin, {
      root: join(__dirname, '../client/dist'),
      prefix: '/'
    });
  }
  
  // Start process monitoring
  await startProcessMonitor();
  
  // Start server
  const port = parseInt(process.env.PORT || '3000');
  const host = process.env.HOST || '0.0.0.0';
  
  try {
    await fastify.listen({ port, host });
    console.log(`🚀 Procscope server running at http://localhost:${port}`);
    console.log(`📡 WebSocket endpoint: ws://localhost:${port}/ws`);
    if (process.env.NODE_ENV !== 'production') {
      console.log(`💻 Start the client with: cd client && npm run dev`);
    }
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('🛑 Received SIGINT, shutting down gracefully...');
  try {
    stopProcessMonitor();
    await fastify.close();
    process.exit(0);
  } catch (err) {
    console.error('Error during shutdown:', err);
    process.exit(1);
  }
});

process.on('SIGTERM', async () => {
  console.log('🛑 Received SIGTERM, shutting down gracefully...');
  try {
    stopProcessMonitor();
    await fastify.close();
    process.exit(0);
  } catch (err) {
    console.error('Error during shutdown:', err);
    process.exit(1);
  }
});

start();