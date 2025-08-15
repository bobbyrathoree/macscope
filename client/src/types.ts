export type SuspicionLevel = 'CRITICAL' | 'HIGH' | 'MED' | 'LOW';

export interface ProcessData {
  pid: number;
  ppid?: number;
  name: string;
  cmd: string;
  user: string;
  cpu: number;
  mem: number;
  execPath?: string;
  connections: {
    outbound: number;
    listen: number;
    remotes: string[];
  };
  level: SuspicionLevel;
  reasons: string[];
  launchd?: string;
  codesign?: {
    signed: boolean;
    valid: boolean;
    teamId?: string;
    notarized?: boolean;
    appStore?: boolean;
  };
  parent?: string;
}

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