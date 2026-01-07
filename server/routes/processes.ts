import type { FastifyPluginAsync } from 'fastify';
import { processStore } from '../store.js';
import { getMdmSummary } from '../../src/mdm.js';
import isRoot from 'is-root';
import os from 'node:os';

// Rate limiting store: IP -> { count, resetTime }
const rateLimitStore = new Map<string, { count: number; resetTime: number }>();

// Protected PIDs that cannot be killed
const PROTECTED_PIDS = [0, 1, process.pid];

// Rate limit configuration
const RATE_LIMIT_WINDOW_MS = 60000; // 1 minute
const RATE_LIMIT_MAX_ATTEMPTS = 5;

export const processRoutes: FastifyPluginAsync = async (fastify) => {
  // Get all processes
  fastify.get<{
    Querystring: { limit?: number; offset?: number }
  }>('/processes', {
    schema: {
      querystring: {
        type: 'object',
        properties: {
          limit: { type: 'integer', minimum: 1, maximum: 10000 },
          offset: { type: 'integer', minimum: 0 }
        }
      },
      response: {
        200: {
          type: 'array',
          items: { type: 'object' }
        }
      }
    }
  }, async (_request, _reply) => {
    return processStore.getProcesses();
  });
  
  // Get single process
  fastify.get<{
    Params: { pid: string }
  }>('/processes/:pid', {
    schema: {
      params: {
        type: 'object',
        required: ['pid'],
        properties: {
          pid: { type: 'string', pattern: '^[0-9]+$' }
        }
      },
      response: {
        200: {
          type: 'object'
        },
        404: {
          type: 'object',
          properties: {
            error: { type: 'string' }
          }
        }
      }
    }
  }, async (request, reply) => {
    const { pid } = request.params;
    const process = processStore.getProcess(parseInt(pid));

    if (!process) {
      return reply.code(404).send({ error: 'Process not found' });
    }

    return process;
  });
  
  // Get system stats
  fastify.get('/stats', {
    schema: {
      response: {
        200: {
          type: 'object',
          properties: {
            processes: { type: 'object' },
            system: {
              type: 'object',
              properties: {
                platform: { type: 'string' },
                arch: { type: 'string' },
                hostname: { type: 'string' },
                uptime: { type: 'number' },
                totalMem: { type: 'number' },
                freeMem: { type: 'number' },
                cpuCount: { type: 'number' },
                isRoot: { type: 'boolean' }
              }
            }
          }
        }
      }
    }
  }, async (_request, _reply) => {
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
  fastify.get('/mdm', {
    schema: {
      response: {
        200: {
          type: 'object',
          properties: {
            status: { type: 'string' }
          }
        },
        500: {
          type: 'object',
          properties: {
            error: { type: 'string' }
          }
        }
      }
    }
  }, async (_request, reply) => {
    try {
      const mdmStatus = await getMdmSummary();
      return { status: mdmStatus };
    } catch (err) {
      return reply.code(500).send({ error: 'Failed to get MDM status' });
    }
  });
  
  // Kill a process (requires elevated permissions and authentication)
  fastify.post<{
    Params: { pid: string };
    Body: { signal?: string };
  }>('/processes/:pid/kill', {
    schema: {
      params: {
        type: 'object',
        required: ['pid'],
        properties: {
          pid: { type: 'string', pattern: '^[0-9]+$' }
        }
      },
      body: {
        type: 'object',
        properties: {
          signal: {
            type: 'string',
            enum: ['SIGTERM', 'SIGKILL', 'SIGINT', 'SIGHUP']
          }
        }
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            pid: { type: 'number' },
            signal: { type: 'string' }
          }
        },
        400: {
          type: 'object',
          properties: {
            error: { type: 'string' },
            message: { type: 'string' }
          }
        },
        401: {
          type: 'object',
          properties: {
            error: { type: 'string' },
            message: { type: 'string' }
          }
        },
        403: {
          type: 'object',
          properties: {
            error: { type: 'string' },
            message: { type: 'string' }
          }
        },
        404: {
          type: 'object',
          properties: {
            error: { type: 'string' },
            message: { type: 'string' },
            code: { type: 'string' }
          }
        },
        429: {
          type: 'object',
          properties: {
            error: { type: 'string' },
            message: { type: 'string' }
          }
        },
        500: {
          type: 'object',
          properties: {
            error: { type: 'string' },
            message: { type: 'string' },
            code: { type: 'string' }
          }
        }
      }
    }
  }, async (request, reply) => {
    const { pid } = request.params;
    const { signal = 'SIGTERM' } = request.body;

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

    // 3. Parse PID (validation is already done by schema)
    const pidNum = parseInt(pid);

    // 4. Check if PID is protected
    if (PROTECTED_PIDS.includes(pidNum)) {
      fastify.log.warn({ clientIp, pid: pidNum }, 'Attempt to kill protected PID');
      return reply.code(403).send({
        error: 'Protected PID',
        message: `Cannot kill protected process (PID ${pidNum}). Protected PIDs: ${PROTECTED_PIDS.join(', ')}`
      });
    }

    // 5. Normalize signal (validation is already done by schema)
    const signalUpper = signal.toUpperCase();

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