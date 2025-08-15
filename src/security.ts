import { ProcInfo, ConnSummary, CodesignInfo, SuspicionInfo, SuspicionLevel, SUSPICIOUS_PATTERNS, SUSPICIOUS_LOCATIONS, TRUSTED_TEAMS } from './types.js';
import { checkBinaryTrust } from './codesign.js';
import os from 'node:os';

export async function analyzeSecurity(
  proc: ProcInfo,
  conn?: ConnSummary,
  launchd?: string,
  csig?: CodesignInfo | null,
  parentProc?: ProcInfo
): Promise<SuspicionInfo> {
  const reasons: string[] = [];
  let level: SuspicionLevel = 'LOW';

  // CRITICAL: Keylogger with network activity (data exfiltration)
  const isKeylogger = SUSPICIOUS_PATTERNS.keyloggers.some(pattern => 
    (proc.name || '').toLowerCase().includes(pattern) ||
    (proc.cmd || '').toLowerCase().includes(pattern) ||
    (proc.execPath || '').toLowerCase().includes(pattern)
  );
  
  if (isKeylogger) {
    if (conn && conn.outbound > 0) {
      reasons.push('keylogger-with-network-activity');
      level = 'CRITICAL';
    } else {
      reasons.push('keylogger-pattern');
      level = 'HIGH';
    }
  }

  // CRITICAL: Input monitoring processes with suspicious network behavior
  const inputMonitoringApis = [
    'CGEventTap', 'IOHIDManager', 'NSEvent', 'kIOHIDElement',
    'eventtap', 'inputmethod', 'accessibility'
  ];
  
  const hasInputMonitoring = inputMonitoringApis.some(api => 
    (proc.cmd || '').includes(api) || (proc.execPath || '').includes(api)
  );
  
  if (hasInputMonitoring && conn && conn.outbound > 2) {
    reasons.push('input-monitoring-with-network');
    level = 'CRITICAL';
  }

  // HIGH: Processes with suspicious data upload patterns
  if (conn && conn.outbound > 10 && conn.sampleRemotes.size > 5) {
    const suspiciousRemotes = Array.from(conn.sampleRemotes).some(remote => {
      // Check for suspicious domains/IPs
      return !remote.includes('apple.com') && 
             !remote.includes('icloud.com') &&
             !remote.includes('localhost') &&
             !remote.includes('127.0.0.1') &&
             (remote.includes('.ru') || remote.includes('.cn') || 
              remote.includes('.tk') || remote.includes('.onion') ||
              /\d+\.\d+\.\d+\.\d+/.test(remote)); // Raw IP addresses
    });
    
    if (suspiciousRemotes) {
      reasons.push('suspicious-data-upload-pattern');
      if (level !== 'CRITICAL') level = 'HIGH';
    }
  }

  // CRITICAL: Unsigned binary with input monitoring capabilities
  if (hasInputMonitoring && csig && !csig.signed) {
    reasons.push('unsigned-input-monitor');
    level = 'CRITICAL';
  }

  // HIGH: Processes spawned from browsers/documents that monitor input
  if (hasInputMonitoring && parentProc) {
    const suspiciousParents = ['safari', 'chrome', 'firefox', 'edge', 'word', 'excel', 'powerpoint', 'preview'];
    const isSuspiciousParent = suspiciousParents.some(parent => 
      (parentProc.name || '').toLowerCase().includes(parent)
    );
    
    if (isSuspiciousParent) {
      reasons.push('browser-spawned-input-monitor');
      if (level !== 'CRITICAL') level = 'HIGH';
    }
  }

  // CRITICAL: Processes with accessibility permissions making network connections
  const hasAccessibilityAccess = (proc.cmd || '').includes('accessibility') || 
                                 (proc.execPath || '').includes('accessibility') ||
                                 launchd?.includes('accessibility');
  
  if (hasAccessibilityAccess && conn && conn.outbound > 1) {
    reasons.push('accessibility-with-network');
    level = 'CRITICAL';
  }

  // Check for different user
  if (proc.user && proc.user !== process.env.USER && proc.user !== 'root' && proc.user !== '_www') {
    reasons.push('different-user');
  }

  // Check for agent/daemon patterns
  if ((proc.cmd || '').match(/launchd|agent|daemon/i)) {
    reasons.push('agent-ish');
  }

  // Check if launchd managed
  if (launchd) {
    reasons.push('launchd-managed');
  }

  // Check for known management suites
  if ((proc.cmd || '').match(/(jamf|crowdstrike|zscaler|netskope|tanium|sentinel|carbon|defender|sophos|mcafee|symantec|kaspersky)/i)) {
    reasons.push('mgmt-suite');
  }

  // Check for many connections
  if (conn && (conn.outbound + conn.listen) > 20) {
    reasons.push('many-connections');
  }

  // Check for suspicious network patterns
  if (conn && conn.outbound > 50) {
    reasons.push('excessive-outbound');
    level = 'MED';
  }

  // Check for keyloggers
  const cmdLower = (proc.cmd || '').toLowerCase();
  const nameLower = (proc.name || '').toLowerCase();
  
  for (const pattern of SUSPICIOUS_PATTERNS.keyloggers) {
    if (cmdLower.includes(pattern) || nameLower.includes(pattern)) {
      reasons.push('keylogger-pattern');
      level = 'HIGH';
      break;
    }
  }

  // Check for screen recorders
  for (const pattern of SUSPICIOUS_PATTERNS.screenRecorders) {
    if (cmdLower.includes(pattern) || nameLower.includes(pattern)) {
      reasons.push('screen-recorder');
      level = 'MED';
      break;
    }
  }

  // Check for remote access tools
  for (const pattern of SUSPICIOUS_PATTERNS.remoteAccess) {
    if (cmdLower.includes(pattern) || nameLower.includes(pattern)) {
      reasons.push('remote-access');
      level = level === 'HIGH' ? 'HIGH' : 'MED';
      break;
    }
  }

  // Check for crypto miners
  for (const pattern of SUSPICIOUS_PATTERNS.cryptominers) {
    if (cmdLower.includes(pattern) || nameLower.includes(pattern)) {
      reasons.push('cryptominer');
      level = 'HIGH';
      break;
    }
  }

  // Check for data exfiltration tools (only suspicious if not signed by trusted team)
  for (const pattern of SUSPICIOUS_PATTERNS.dataExfiltration) {
    if (cmdLower.includes(pattern) || nameLower.includes(pattern)) {
      if (!csig || !csig.teamIdentifier || !TRUSTED_TEAMS.includes(csig.teamIdentifier as any)) {
        reasons.push('data-exfiltration');
        level = level === 'LOW' ? 'MED' : level;
      }
      break;
    }
  }

  // Check for explicitly suspicious patterns
  for (const pattern of SUSPICIOUS_PATTERNS.suspicious) {
    if (cmdLower.includes(pattern) || nameLower.includes(pattern)) {
      reasons.push('suspicious-name');
      level = 'CRITICAL';
      break;
    }
  }

  // Check for suspicious locations
  if (proc.execPath) {
    const homeDir = os.homedir();
    const execPath = proc.execPath.replace('~', homeDir);
    
    for (const location of SUSPICIOUS_LOCATIONS) {
      const checkPath = location.replace('~', homeDir);
      if (execPath.startsWith(checkPath)) {
        reasons.push(`suspicious-location:${location}`);
        level = level === 'LOW' ? 'MED' : level;
        break;
      }
    }
  }

  // Enhanced signature checking
  if (csig) {
    const trustCheck = await checkBinaryTrust(csig);
    
    if (trustCheck.trustLevel === 'malicious') {
      reasons.push('malicious-signature');
      level = 'CRITICAL';
    } else if (trustCheck.trustLevel === 'suspicious') {
      reasons.push(...trustCheck.reasons);
      level = level === 'LOW' ? 'HIGH' : level;
    } else if (trustCheck.trustLevel === 'unknown') {
      reasons.push('unknown-signature');
      if (proc.execPath && !proc.execPath.includes('/usr/local/')) {
        level = level === 'LOW' ? 'MED' : level;
      }
    } else if (trustCheck.trustLevel === 'verified') {
      // Notarized or developer-signed
      if (csig.notarized) {
        reasons.push('notarized');
      }
    } else if (trustCheck.trustLevel === 'trusted') {
      // From trusted vendor or App Store
      reasons.push('trusted-binary');
      // Reduce suspicion level if it's only based on other minor factors
      if (level === 'MED' && reasons.length <= 3) {
        level = 'LOW';
      }
    }
  }

  // Check for process injection patterns (parent-child analysis)
  if (parentProc) {
    // Check if a browser spawned a shell
    if ((parentProc.name || '').match(/Chrome|Safari|Firefox|Edge/i) && 
        (proc.name || '').match(/bash|sh|zsh|python|perl|ruby|node/i)) {
      reasons.push('browser-spawned-shell');
      level = 'HIGH';
    }

    // Check if a document viewer spawned a process
    if ((parentProc.name || '').match(/Preview|Adobe|Word|Excel|PowerPoint/i) &&
        (proc.name || '').match(/bash|sh|curl|wget|nc/i)) {
      reasons.push('document-spawned-process');
      level = 'CRITICAL';
    }
  }

  // Check for hidden processes (starting with .)
  if (proc.name && proc.name.startsWith('.')) {
    reasons.push('hidden-process');
    level = level === 'LOW' ? 'MED' : level;
  }

  // Check for processes with no name but have command
  if (!proc.name && proc.cmd) {
    reasons.push('unnamed-process');
  }

  // Adjust level based on combinations
  if (reasons.includes('mgmt-suite') || reasons.includes('launchd-managed')) {
    level = level === 'LOW' ? 'MED' : level;
  }

  if (reasons.length >= 3 && level === 'LOW') {
    level = 'MED';
  }

  if (reasons.length >= 5) {
    level = level === 'MED' ? 'HIGH' : level;
  }

  return { level, reasons };
}

export function checkNetworkAnomalies(
  conn: ConnSummary,
  historicalAvg?: { outbound: number; listen: number }
): string[] {
  const anomalies: string[] = [];

  // Check for unusual number of connections
  if (historicalAvg) {
    if (conn.outbound > historicalAvg.outbound * 3) {
      anomalies.push('spike-in-outbound');
    }
    if (conn.listen > historicalAvg.listen * 2) {
      anomalies.push('new-listeners');
    }
  }

  // Check for connections to multiple unique IPs (possible scanning)
  if (conn.sampleRemotes.size > 10) {
    anomalies.push('many-unique-destinations');
  }

  // Check for suspicious ports in remote addresses
  const suspiciousPorts = ['1337', '31337', '4444', '5555', '6666', '6667', '8888'];
  for (const remote of conn.sampleRemotes) {
    const port = remote.split(':')[1];
    if (port && suspiciousPorts.includes(port)) {
      anomalies.push(`suspicious-port:${port}`);
      break;
    }
  }

  return anomalies;
}