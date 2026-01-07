import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

const ERROR_LOG_DIR = path.join(os.homedir(), '.procscope');
const ERROR_LOG_FILE = path.join(ERROR_LOG_DIR, 'errors.log');

/**
 * Logs errors to a persistent log file with structured JSON format.
 * Falls back to console.error if file logging fails.
 *
 * @param context - A descriptive context for where the error occurred (e.g., "lsof:getConnectionsByPid")
 * @param error - The error object or unknown value to log
 */
export async function logError(context: string, error: unknown): Promise<void> {
  const timestamp = new Date().toISOString();

  // Extract error details
  let errorMessage = 'Unknown error';
  let errorStack: string | undefined;
  let errorName = 'Error';

  if (error instanceof Error) {
    errorMessage = error.message;
    errorStack = error.stack;
    errorName = error.name;
  } else if (typeof error === 'string') {
    errorMessage = error;
  } else if (error && typeof error === 'object') {
    errorMessage = JSON.stringify(error);
  }

  const logEntry = {
    timestamp,
    context,
    error: {
      name: errorName,
      message: errorMessage,
      stack: errorStack
    }
  };

  try {
    // Ensure directory exists
    await fs.mkdir(ERROR_LOG_DIR, { recursive: true });

    // Append error to log file
    const logLine = JSON.stringify(logEntry) + '\n';
    await fs.appendFile(ERROR_LOG_FILE, logLine);
  } catch (fileError) {
    // Fallback to console.error if file logging fails
    console.error(`[${timestamp}] ${context}:`, error);
    console.error('Failed to write to error log file:', fileError);
  }
}
