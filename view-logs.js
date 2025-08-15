#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

const LOG_FILE = path.join(os.homedir(), '.procscope', 'suspicious-processes.log');

async function viewLogs(hours = 24) {
  try {
    const content = await fs.readFile(LOG_FILE, 'utf-8');
    const lines = content.trim().split('\n').filter(line => line);
    const cutoff = new Date(Date.now() - hours * 60 * 60 * 1000);
    
    console.log(`\n🔍 PROCSCOPE SUSPICIOUS PROCESS LOG (Last ${hours} hours)\n`);
    console.log('='.repeat(80));
    
    const entries = lines
      .map(line => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(entry => entry && new Date(entry.timestamp) > cutoff)
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    if (entries.length === 0) {
      console.log('No suspicious processes logged in the specified timeframe.');
      return;
    }
    
    // Group by level
    const critical = entries.filter(e => e.level === 'CRITICAL');
    const high = entries.filter(e => e.level === 'HIGH');
    
    if (critical.length > 0) {
      console.log('\n🔴 CRITICAL THREATS:');
      console.log('-'.repeat(80));
      critical.forEach(printEntry);
    }
    
    if (high.length > 0) {
      console.log('\n🟡 HIGH RISK PROCESSES:');
      console.log('-'.repeat(80));
      high.forEach(printEntry);
    }
    
    console.log('\n' + '='.repeat(80));
    console.log(`Total: ${entries.length} suspicious processes (${critical.length} critical, ${high.length} high)`);
    console.log(`Log file: ${LOG_FILE}\n`);
    
  } catch (error) {
    console.error('No log file found. Run procscope first to start logging.');
  }
}

function printEntry(entry) {
  const time = new Date(entry.timestamp).toLocaleString();
  console.log(`\n[${time}] ${entry.level}`);
  console.log(`PID: ${entry.pid} | Name: ${entry.name} | User: ${entry.user}`);
  if (entry.parent) console.log(`Parent: ${entry.parent} (PPID: ${entry.ppid})`);
  if (entry.cmd) console.log(`Command: ${entry.cmd.slice(0, 100)}${entry.cmd.length > 100 ? '...' : ''}`);
  if (entry.execPath) console.log(`Path: ${entry.execPath}`);
  
  // Network info
  if (entry.connections.outbound > 0 || entry.connections.listen > 0) {
    console.log(`Network: ${entry.connections.outbound} outbound, ${entry.connections.listen} listening`);
    if (entry.connections.remotes.length > 0) {
      console.log(`Remote IPs: ${entry.connections.remotes.join(', ')}`);
    }
  }
  
  // Codesign info
  if (entry.codesign.signed === false) {
    console.log(`⚠️  UNSIGNED BINARY`);
  } else if (entry.codesign.valid === false) {
    console.log(`❌ INVALID SIGNATURE`);
  } else if (entry.codesign.teamId) {
    console.log(`Signed by: ${entry.codesign.teamId}`);
  }
  
  console.log(`Reasons: ${entry.reasons.join(', ')}`);
}

// Parse command line args
const hours = process.argv[2] ? parseInt(process.argv[2]) : 24;
viewLogs(hours);