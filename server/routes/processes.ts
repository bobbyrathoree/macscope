import type { FastifyPluginAsync } from 'fastify';
import { processStore } from '../store.js';
import { getMdmSummary } from '../../src/mdm.js';
import isRoot from 'is-root';
import os from 'node:os';

// Rate limiting store: IP -> { count, resetTime }
const rateLimitStore = new Map<string, { count: number; resetTime: number }>();

// Valid signals for kill operations
const VALID_SIGNALS = ['SIGTERM', 'SIGKILL', 'SIGINT', 'SIGHUP'];

// Protected PIDs that cannot be killed
const PROTECTED_PIDS = [0, 1, process.pid];

// Rate limit configuration
const RATE_LIMIT_WINDOW_MS = 60000; // 1 minute
const RATE_LIMIT_MAX_ATTEMPTS = 5;

export const processRoutes: FastifyPluginAsync = async (fastify) => {
  // Get all processes
  fastify.get('/processes', async (request, reply) => {
    return processStore.getProcesses();
  });
  
  // Get single process
  fastify.get('/processes/:pid', async (request, reply) => {
    const { pid } = request.params as { pid: string };
    const process = processStore.getProcess(parseInt(pid));
    
    if (!process) {
      return reply.code(404).send({ error: 'Process not found' });
    }
    
    return process;
  });
  
  // Get system stats
  fastify.get('/stats', async (request, reply) => {
    const stats = processStore.getStats();
    const systemInfo = {
      platform: os.platform(),
      arch: os.arch(),
      hostname: os.hostname(),
      uptime: os.uptime(),
      totalMem: os.totalmem(),
      freeMem: os.freemem(),
      cpuCount: os.cpus().length,
      isRoot: isRoot()
    };
    
    return {
      processes: stats,
      system: systemInfo
    };
  });
  
  // Get MDM status
  fastify.get('/mdm', async (request, reply) => {
    try {
      const mdmStatus = await getMdmSummary();
      return { status: mdmStatus };
    } catch (err) {
      return reply.code(500).send({ error: 'Failed to get MDM status' });
    }
  });
  
  // Kill a process (requires elevated permissions and authentication)
  fastify.post('/processes/:pid/kill', async (request, reply) => {
    const { pid } = request.params as { pid: string };
    const { signal = 'SIGTERM' } = request.body as { signal?: string };

    // Get client IP
    const clientIp = request.ip || 'unknown';

    // 1. Authentication check
    const authToken = request.headers['authorization']?.replace('Bearer ', '');
    const expectedToken = process.env.PROCSCOPE_API_TOKEN;

    if (!expectedToken) {
      fastify.log.error('PROCSCOPE_API_TOKEN not configured');
      return reply.code(500).send({
        error: 'Authentication not configured',
        message: 'Server authentication is not properly configured'
      });
    }

    if (!authToken || authToken !== expectedToken) {
      fastify.log.warn({ clientIp }, 'Unauthorized kill attempt - invalid token');
      return reply.code(401).send({
        error: 'Unauthorized',
        message: 'Valid authentication token required'
      });
    }

    // 2. Rate limiting check
    const now = Date.now();
    const rateLimitData = rateLimitStore.get(clientIp);

    if (rateLimitData) {
      if (now < rateLimitData.resetTime) {
        if (rateLimitData.count >= RATE_LIMIT_MAX_ATTEMPTS) {
          const resetInSeconds = Math.ceil((rateLimitData.resetTime - now) / 1000);
          fastify.log.warn({ clientIp, attempts: rateLimitData.count }, 'Rate limit exceeded');
          return reply.code(429).send({
            error: 'Rate limit exceeded',
            message: `Maximum ${RATE_LIMIT_MAX_ATTEMPTS} kill attempts per minute. Try again in ${resetInSeconds} seconds.`
          });
        }
        rateLimitData.count++;
      } else {
        // Reset window
        rateLimitData.count = 1;
        rateLimitData.resetTime = now + RATE_LIMIT_WINDOW_MS;
      }
    } else {
      // First request from this IP
      rateLimitStore.set(clientIp, {
        count: 1,
        resetTime: now + RATE_LIMIT_WINDOW_MS
      });
    }

    // 3. Validate PID is a positive integer
    const pidNum = parseInt(pid);
    if (isNaN(pidNum) || pidNum <= 0 || !Number.isInteger(Number(pid))) {
      fastify.log.warn({ clientIp, pid }, 'Invalid PID format');
      return reply.code(400).send({
        error: 'Invalid PID',
        message: 'PID must be a valid positive integer'
      });
    }

    // 4. Check if PID is protected
    if (PROTECTED_PIDS.includes(pidNum)) {
      fastify.log.warn({ clientIp, pid: pidNum }, 'Attempt to kill protected PID');
      return reply.code(403).send({
        error: 'Protected PID',
        message: `Cannot kill protected process (PID ${pidNum}). Protected PIDs: ${PROTECTED_PIDS.join(', ')}`
      });
    }

    // 5. Validate signal
    const signalUpper = signal.toUpperCase();
    if (!VALID_SIGNALS.includes(signalUpper)) {
      fastify.log.warn({ clientIp, signal }, 'Invalid signal');
      return reply.code(400).send({
        error: 'Invalid signal',
        message: `Signal must be one of: ${VALID_SIGNALS.join(', ')}`
      });
    }

    // 6. Attempt to kill the process
    try {
      process.kill(pidNum, signalUpper as NodeJS.Signals);
      fastify.log.info({ clientIp, pid: pidNum, signal: signalUpper }, 'Process kill successful');
      return { success: true, pid: pidNum, signal: signalUpper };
    } catch (err: any) {
      fastify.log.error({ clientIp, pid: pidNum, signal: signalUpper, error: err.message }, 'Failed to kill process');

      // Determine appropriate status code based on error
      let statusCode = 500;
      let errorMessage = err.message;

      if (err.code === 'ESRCH') {
        statusCode = 404;
        errorMessage = 'Process not found';
      } else if (err.code === 'EPERM') {
        statusCode = 403;
        errorMessage = 'Permission denied - insufficient privileges to kill this process';
      }

      return reply.code(statusCode).send({
        error: 'Failed to kill process',
        message: errorMessage,
        code: err.code
      });
    }
  });
};