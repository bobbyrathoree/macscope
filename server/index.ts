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
const SHUTDOWN_TIMEOUT = 10000; // 10 seconds

async function gracefulShutdown(signal: string) {
  console.log(`Received ${signal}, shutting down gracefully...`);

  // Set a timeout to force exit if shutdown takes too long
  const timeoutHandle = setTimeout(() => {
    console.error('Shutdown timeout exceeded, forcing exit');
    process.exit(1);
  }, SHUTDOWN_TIMEOUT);

  // Allow the timeout to not keep the process alive unnecessarily
  timeoutHandle.unref();

  try {
    console.log('Stopping new requests...');
    // First stop accepting new requests
    await fastify.close();
    console.log('Server closed');

    console.log('Stopping process monitor...');
    // Then stop the process monitor
    stopProcessMonitor();
    console.log('Process monitor stopped');

    clearTimeout(timeoutHandle);
    console.log('Shutdown complete');
    process.exit(0);
  } catch (err) {
    console.error('Error during shutdown:', err);
    clearTimeout(timeoutHandle);
    process.exit(1);
  }
}

// Handle termination signals
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// Handle uncaught errors
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled rejection at:', promise, 'reason:', reason);
  gracefulShutdown('unhandledRejection');
});

start();