import type { FastifyPluginAsync } from 'fastify';
import { processStore } from '../store.js';
import { getMdmSummary } from '../../src/mdm.js';
import isRoot from 'is-root';
import os from 'node:os';

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
  
  // Kill a process (requires elevated permissions)
  fastify.post('/processes/:pid/kill', async (request, reply) => {
    const { pid } = request.params as { pid: string };
    const { signal = 'SIGTERM' } = request.body as { signal?: string };
    
    try {
      process.kill(parseInt(pid), signal as any);
      return { success: true, pid: parseInt(pid) };
    } catch (err: any) {
      return reply.code(403).send({ 
        error: 'Failed to kill process',
        message: err.message 
      });
    }
  });
};