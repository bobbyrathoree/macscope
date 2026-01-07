import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { logError } from './error-logger';

const LOG_DIR = path.join(os.homedir(), '.procscope');
const LOG_FILE = path.join(LOG_DIR, 'suspicious-processes.log');

// Track logged processes to avoid duplicates within same session
const loggedProcesses = new Set<string>();

export async function initLogger(): Promise<void> {
  try {
    await fs.mkdir(LOG_DIR, { recursive: true });
  } catch (error) {
    await logError('logger:initLogger', error);
    // Directory might already exist
  }
}

export async function logSuspiciousProcess(entry: {
  pid: number;
  ppid?: number;
  name: string;
  user?: string;
  cmd?: string;
  execPath?: string;
  level: 'HIGH' | 'CRITICAL';
  reasons: string[];
  connections: { outbound: number; listen: number; sampleRemotes: Set<string> | string[] };
  codesign: { signed: boolean; valid?: boolean; teamIdentifier?: string; notarized?: boolean };
  parent?: string | null;
}): Promise<void> {
  // Only log HIGH and CRITICAL processes
  if (entry.level !== 'HIGH' && entry.level !== 'CRITICAL') {
    return;
  }

  // Create unique key to avoid duplicate logging
  const key = `${entry.pid}-${entry.name}-${entry.level}`;
  if (loggedProcesses.has(key)) {
    return;
  }
  loggedProcesses.add(key);

  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    level: entry.level,
    pid: entry.pid,
    ppid: entry.ppid,
    name: entry.name,
    user: entry.user,
    cmd: entry.cmd,
    execPath: entry.execPath,
    parent: entry.parent,
    reasons: entry.reasons,
    connections: {
      outbound: entry.connections.outbound || 0,
      listen: entry.connections.listen || 0,
      remotes: Array.isArray(entry.connections.sampleRemotes) 
        ? entry.connections.sampleRemotes.slice(0, 5)
        : [...entry.connections.sampleRemotes].slice(0, 5)
    },
    codesign: {
      signed: entry.codesign?.signed,
      valid: entry.codesign?.valid,
      teamId: entry.codesign?.teamIdentifier,
      notarized: entry.codesign?.notarized
    }
  };

  try {
    const logLine = JSON.stringify(logEntry) + '\n';
    await fs.appendFile(LOG_FILE, logLine);
  } catch (error) {
    await logError('logger:logSuspiciousProcess', error);
    // Silently fail logging to not interrupt the UI
  }
}

export async function getRecentSuspiciousProcesses(hours: number = 24): Promise<any[]> {
  try {
    const content = await fs.readFile(LOG_FILE, 'utf-8');
    const lines = content.trim().split('\n').filter(line => line);
    const cutoff = new Date(Date.now() - hours * 60 * 60 * 1000);
    
    const recent = lines
      .map(line => {
        try {
          return JSON.parse(line);
        } catch (parseError) {
          logError('logger:getRecentSuspiciousProcesses:parse', parseError);
          return null;
        }
      })
      .filter(entry => entry && new Date(entry.timestamp) > cutoff);

    return recent;
  } catch (error) {
    await logError('logger:getRecentSuspiciousProcesses', error);
    return [];
  }
}

// Clean up old log entries (older than 7 days)
export async function cleanupOldLogs(): Promise<void> {
  try {
    const content = await fs.readFile(LOG_FILE, 'utf-8');
    const lines = content.trim().split('\n').filter(line => line);
    const cutoff = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    
    const recentLines = lines.filter(line => {
      try {
        const entry = JSON.parse(line);
        return new Date(entry.timestamp) > cutoff;
      } catch (parseError) {
        logError('logger:cleanupOldLogs:parse', parseError);
        return false;
      }
    });

    await fs.writeFile(LOG_FILE, recentLines.join('\n') + '\n');
  } catch (error) {
    await logError('logger:cleanupOldLogs', error);
    // Ignore cleanup errors
  }
}