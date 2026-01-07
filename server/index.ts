import Fastify from 'fastify';
import websocketPlugin from '@fastify/websocket';
import corsPlugin from '@fastify/cors';
import staticPlugin from '@fastify/static';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { processRoutes } from './routes/processes';
import { websocketHandler, setLogger as setWebSocketLogger } from './websocket';
import { startProcessMonitor, stopProcessMonitor, setLogger as setMonitorLogger } from './monitor';
import { setLogger as setStoreLogger } from './store';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Configure Pino logger
const isDevelopment = process.env.NODE_ENV !== 'production';
const logLevel = process.env.LOG_LEVEL || (isDevelopment ? 'info' : 'warn');

// Try to use pino-pretty in development, fall back to JSON if not available
const loggerConfig: any = {
  level: logLevel,
};

if (isDevelopment) {
  try {
    loggerConfig.transport = {
      target: 'pino-pretty',
      options: {
        colorize: true,
        translateTime: 'HH:MM:ss',
        ignore: 'pid,hostname',
      }
    };
  } catch (err) {
    // pino-pretty not available, will use JSON format
  }
}

const fastify = Fastify({
  logger: loggerConfig,
  // Prevent memory leaks and resource exhaustion
  connectionTimeout: 30000,
  keepAliveTimeout: 5000,
  maxParamLength: 1000,
  bodyLimit: 1048576, // 1MB limit
});

// Export logger for use in other modules
export const logger = fastify.log;

// Inject logger into other modules
setMonitorLogger(logger);
setWebSocketLogger(logger);
setStoreLogger(logger);

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
    fastify.log.info({ port, host }, 'Procscope server running');
    fastify.log.info({ wsEndpoint: `ws://localhost:${port}/ws` }, 'WebSocket endpoint ready');
    if (process.env.NODE_ENV !== 'production') {
      fastify.log.info('Start the client with: cd client && npm run dev');
    }
  } catch (err) {
    fastify.log.error(err, 'Failed to start server');
    process.exit(1);
  }
}

// Graceful shutdown
const SHUTDOWN_TIMEOUT = 10000; // 10 seconds

async function gracefulShutdown(signal: string) {
  fastify.log.info({ signal }, 'Received signal, shutting down gracefully');

  // Set a timeout to force exit if shutdown takes too long
  const timeoutHandle = setTimeout(() => {
    fastify.log.error({ timeout: SHUTDOWN_TIMEOUT }, 'Shutdown timeout exceeded, forcing exit');
    process.exit(1);
  }, SHUTDOWN_TIMEOUT);

  // Allow the timeout to not keep the process alive unnecessarily
  timeoutHandle.unref();

  try {
    fastify.log.info('Stopping new requests');
    // First stop accepting new requests
    await fastify.close();
    fastify.log.info('Server closed');

    fastify.log.info('Stopping process monitor');
    // Then stop the process monitor
    stopProcessMonitor();
    fastify.log.info('Process monitor stopped');

    clearTimeout(timeoutHandle);
    fastify.log.info('Shutdown complete');
    process.exit(0);
  } catch (err) {
    fastify.log.error({ err }, 'Error during shutdown');
    clearTimeout(timeoutHandle);
    process.exit(1);
  }
}

// Handle termination signals
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// Handle uncaught errors
process.on('uncaughtException', (err) => {
  fastify.log.fatal({ err }, 'Uncaught exception');
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  fastify.log.fatal({ reason, promise }, 'Unhandled rejection');
  gracefulShutdown('unhandledRejection');
});

start();