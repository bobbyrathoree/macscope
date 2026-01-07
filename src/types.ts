export interface ProcInfo {
  pid: number;
  ppid?: number;
  name?: string;
  cmd?: string;
  user?: string;
  cpu?: number;
  mem?: number;
  execPath?: string;
  startTime?: Date;
}

export interface ConnSummary {
  listen: number;
  outbound: number;
  sampleRemotes: Set<string>;
  bytesIn?: number;
  bytesOut?: number;
}

export interface CodesignInfo {
  teamIdentifier?: string;
  authorities?: string[];
  signed: boolean;
  valid?: boolean;
  notarized?: boolean;
  identifier?: string;
  isAppStore?: boolean;
}

export type SuspicionLevel = 'LOW' | 'MED' | 'HIGH' | 'CRITICAL';

export interface SuspicionInfo {
  level: SuspicionLevel;
  reasons: string[];
}

export interface ProcessRow extends ProcInfo {
  launchd?: string;
  conn?: ConnSummary;
  suspicion: SuspicionInfo;
  expanded?: boolean;
  csig?: CodesignInfo | null;
  parentName?: string;
  children?: number[];
  runningFromSuspiciousLocation?: boolean;
}

export interface NetworkStats {
  pid: number;
  bytesIn: number;
  bytesOut: number;
  packetsIn: number;
  packetsOut: number;
  timestamp: Date;
}

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
  '/private/tmp',
  '~/Downloads',
  '~/Desktop',
  '~/.Trash',
  '/Users/Shared',
  '/Library/LaunchAgents',
  '/Library/LaunchDaemons',
  '/Library/StartupItems',
  '~/Library/LaunchAgents',
  '~/Library/Application Support',
  '~/Library/Scripts',
  '~/.local/bin',
  '~/.config'
] as const;

export const TRUSTED_TEAMS = [
  'Apple Inc.',
  'Microsoft Corporation',
  'Google LLC',
  'Adobe Inc.',
  'Mozilla Corporation'
] as const;