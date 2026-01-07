/**
 * Shared type definitions for procscope
 * Used by both server and client to eliminate duplication
 */

// ============================================
// Enums and Union Types
// ============================================

export type SuspicionLevel = 'CRITICAL' | 'HIGH' | 'MED' | 'LOW';

// ============================================
// Base Process Information
// ============================================

export interface BaseProcessInfo {
  pid: number;
  ppid?: number;
  name?: string;
  cmd?: string;
  user?: string;
  cpu?: number;
  mem?: number;
  execPath?: string;
}

// ============================================
// Connection and Network Types
// ============================================

export interface ConnectionSummary {
  outbound: number;
  listen: number;
  remotes: string[];
}

// Server-side connection type (uses Set instead of array)
export interface ConnSummary {
  listen: number;
  outbound: number;
  sampleRemotes: Set<string>;
  bytesIn?: number;
  bytesOut?: number;
}

export interface NetworkStats {
  pid: number;
  bytesIn: number;
  bytesOut: number;
  packetsIn: number;
  packetsOut: number;
  timestamp: Date;
}

// ============================================
// Code Signing Types
// ============================================

export interface CodesignData {
  signed: boolean;
  valid: boolean;
  teamId?: string | undefined;
  notarized?: boolean | undefined;
  appStore?: boolean | undefined;
}

// Server-side codesign type (more detailed)
export interface CodesignInfo {
  teamIdentifier?: string;
  authorities?: string[];
  signed: boolean;
  valid?: boolean;
  notarized?: boolean;
  identifier?: string;
  isAppStore?: boolean;
}

// ============================================
// Suspicion and Security Types
// ============================================

export interface SuspicionInfo {
  level: SuspicionLevel;
  reasons: string[];
}

// ============================================
// Process Wire Format (WebSocket)
// ============================================

/**
 * The format sent over WebSocket from server to client
 * This is the unified format used for network transmission
 */
export interface ProcessWireFormat {
  pid: number;
  ppid?: number | undefined;
  name: string;
  cmd: string;
  user: string;
  cpu: number;
  mem: number;
  execPath?: string | undefined;
  connections: ConnectionSummary;
  level: SuspicionLevel;
  reasons: string[];
  launchd?: string | undefined;
  codesign?: CodesignData | undefined;
  parent?: string | undefined;
}

// Alias for client-side usage
export type ProcessData = ProcessWireFormat;

// ============================================
// Server-side Process Row (internal)
// ============================================

/**
 * Server-side process representation with additional internal fields
 * This extends BaseProcessInfo with server-specific data
 */
export interface ProcessRow extends BaseProcessInfo {
  launchd?: string;
  conn?: ConnSummary;
  suspicion: SuspicionInfo;
  expanded?: boolean;
  csig?: CodesignInfo | null;
  parentName?: string;
  children?: number[];
  runningFromSuspiciousLocation?: boolean;
}

// ============================================
// WebSocket Message Types
// ============================================

export interface Delta {
  added: ProcessWireFormat[];
  updated: ProcessWireFormat[];
  removed: number[];
}

export interface WebSocketMessage {
  type: 'initial' | 'update' | 'delta' | 'pong';
  data?: ProcessWireFormat[] | Delta;
}

// ============================================
// System Stats Types
// ============================================

export interface SystemStats {
  processes: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    lastUpdate: number;
  };
  system: {
    platform: string;
    arch: string;
    hostname: string;
    uptime: number;
    totalMem: number;
    freeMem: number;
    cpuCount: number;
    isRoot: boolean;
  };
}

// ============================================
// Constants
// ============================================

export const SUSPICIOUS_PATTERNS = {
  keyloggers: [
    'keylog', 'keystroke', 'keypress', 'keycapture', 'inputmonitor',
    'keywatcher', 'keyspy', 'keyrecord', 'keytrack', 'keyboardspy',
    'inputcapture', 'inputrecord', 'inputlog', 'inputspy', 'eventlog',
    'tapkey', 'keytap', 'inputtap', 'eventtap', 'cgeventtap',
    'inputhook', 'keyhook', 'globalhook', 'systemhook',
    // Common spyware/RAT names
    'spytector', 'refog', 'ardamax', 'actual', 'elite', 'ghostpress',
    'perfect', 'invisible', 'family', 'employee', 'computer', 'monitoring'
  ],
  screenRecorders: [
    'screencapture', 'screenrecord', 'screengrab', 'screenshot',
    'screenspy', 'screenwatch', 'displaycapture', 'recordscreen'
  ],
  remoteAccess: [
    'teamviewer', 'anydesk', 'realvnc', 'tightvnc', 'ultravnc',
    'logmein', 'gotomypc', 'remotedesktop', 'rdp', 'ssh-agent',
    'nc', 'netcat', 'socat', 'reverse', 'backdoor', 'rat'
  ],
  cryptominers: [
    'xmrig', 'cgminer', 'bfgminer', 'ethminer', 'minergate',
    'nicehash', 'crypto', 'bitcoin', 'monero', 'ethereum'
  ],
  dataExfiltration: [
    'curl', 'wget', 'scp', 'rsync', 'ftp', 'sftp', 'dropbox',
    'gdrive', 'onedrive', 'megasync', 'restic', 'rclone'
  ],
  suspicious: [
    'payload', 'exploit', 'shellcode', 'injection', 'dropper',
    'trojan', 'rootkit', 'malware', 'virus', 'worm', 'spyware'
  ]
} as const;

export const SUSPICIOUS_LOCATIONS = [
  '/tmp',
  '/var/tmp',
  '/dev/shm',
  '~/Downloads',
  '~/Desktop',
  '~/.Trash',
  '/Users/Shared',
  '/Library/LaunchAgents',
  '/Library/LaunchDaemons',
  '~/Library/LaunchAgents'
] as const;

export const TRUSTED_TEAMS = [
  'Apple Inc.',
  'Microsoft Corporation',
  'Google LLC',
  'Adobe Inc.',
  'Mozilla Corporation'
] as const;
