import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { ProcessRow, SuspicionLevel } from './types.js';

const LOG_DIR = path.join(os.homedir(), '.procscope');
const LOG_FILE = path.join(LOG_DIR, 'suspicious-processes.log');

// Track logged processes to avoid duplicates within same session
const loggedProcesses = new Set<string>();

export async function initLogger(): Promise<void> {
  try {
    await fs.mkdir(LOG_DIR, { recursive: true });
  } catch (error) {
    // Directory might already exist
  }
}

export async function logSuspiciousProcess(process: ProcessRow): Promise<void> {
  // Only log HIGH and CRITICAL processes
  if (process.suspicion.level !== 'HIGH' && process.suspicion.level !== 'CRITICAL') {
    return;
  }

  // Create unique key to avoid duplicate logging
  const key = `${process.pid}-${process.name}-${process.suspicion.level}`;
  if (loggedProcesses.has(key)) {
    return;
  }
  loggedProcesses.add(key);

  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    level: process.suspicion.level,
    pid: process.pid,
    ppid: process.ppid,
    name: process.name,
    user: process.user,
    cmd: process.cmd,
    execPath: process.execPath,
    parent: process.parentName,
    reasons: process.suspicion.reasons,
    connections: {
      outbound: process.conn?.outbound || 0,
      listen: process.conn?.listen || 0,
      remotes: process.conn?.sampleRemotes ? [...process.conn.sampleRemotes].slice(0, 5) : []
    },
    codesign: {
      signed: process.csig?.signed,
      valid: process.csig?.valid,
      teamId: process.csig?.teamIdentifier,
      notarized: process.csig?.notarized
    }
  };

  try {
    const logLine = JSON.stringify(logEntry) + '\n';
    await fs.appendFile(LOG_FILE, logLine);
  } catch (error) {
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
        } catch {
          return null;
        }
      })
      .filter(entry => entry && new Date(entry.timestamp) > cutoff);
    
    return recent;
  } catch {
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
      } catch {
        return false;
      }
    });
    
    await fs.writeFile(LOG_FILE, recentLines.join('\n') + '\n');
  } catch {
    // Ignore cleanup errors
  }
}