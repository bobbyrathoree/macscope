import { parentPort } from 'node:worker_threads';
import { getCodeSignInfo } from '../../src/codesign.js';

/**
 * Worker thread for offloading expensive codesign operations
 *
 * Message format:
 * - Inbound: { id: string, path: string }
 * - Outbound: { id: string, result: CodesignInfo | null, error?: string }
 */

if (!parentPort) {
  throw new Error('This module must be run as a worker thread');
}

parentPort.on('message', async (message: { id: string; path: string }) => {
  const { id, path } = message;

  try {
    // Perform the expensive codesign check
    const result = await getCodeSignInfo(path);

    // Send result back to main thread
    parentPort!.postMessage({
      id,
      result
    });
  } catch (error) {
    // Send error back to main thread
    parentPort!.postMessage({
      id,
      result: null,
      error: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

// Handle worker thread errors
parentPort.on('error', (error) => {
  console.error('[Codesign Worker] Error:', error);
});

// Optional: Send ready message when worker initializes
parentPort.postMessage({ type: 'ready' });
