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
    const suspiciousParents = [
      'safari', 'chrome', 'firefox', 'edge', 'brave', 'opera', 'vivaldi', // browsers
      'word', 'excel', 'powerpoint', 'preview', 'pages', 'numbers', 'keynote', // office/docs
      'mail', 'outlook', 'thunderbird', // email clients
      'adobe', 'acrobat', 'skim', // PDF readers
      'vlc', 'quicktime', 'iina', 'mpv', // media players
      'unarchiver', 'keka', 'betterzip' // archive utilities
    ];
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

  // Prepare lowercase versions for pattern matching
  const cmdLower = (proc.cmd || '').toLowerCase();
  const nameLower = (proc.name || '').toLowerCase();

  // Note: Keylogger detection is handled above (lines 16-30) with network activity analysis

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

    // Check for hidden directories in path (e.g., /path/to/.hidden/binary)
    if (/\/\.[^/]+\//.test(execPath)) {
      reasons.push('hidden-directory-path');
      level = level === 'LOW' ? 'MED' : level;
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
    const parentName = (parentProc.name || '').toLowerCase();
    const procName = (proc.name || '').toLowerCase();

    // Define suspicious parent categories with their patterns
    const suspiciousParentPatterns = {
      // Email clients - critical if spawning shells/scripts (malicious attachments)
      emailClients: {
        patterns: ['mail', 'outlook', 'thunderbird', 'postbox', 'airmail', 'mailmate', 'spark'],
        dangerousChildren: /bash|sh|zsh|python|perl|ruby|node|curl|wget|nc|osascript/i,
        reason: 'email-client-spawned-shell',
        severity: 'CRITICAL' as SuspicionLevel
      },

      // PDF readers - critical if spawning shells/scripts (PDF exploits)
      pdfReaders: {
        patterns: ['preview', 'adobe', 'acrobat', 'skim', 'pdf expert', 'pdfpen', 'foxit'],
        dangerousChildren: /bash|sh|zsh|python|perl|ruby|node|curl|wget|nc|osascript/i,
        reason: 'pdf-reader-spawned-shell',
        severity: 'CRITICAL' as SuspicionLevel
      },

      // Browsers - high severity for shell spawning
      browsers: {
        patterns: ['chrome', 'safari', 'firefox', 'edge', 'brave', 'opera', 'vivaldi'],
        dangerousChildren: /bash|sh|zsh|python|perl|ruby|node/i,
        reason: 'browser-spawned-shell',
        severity: 'HIGH' as SuspicionLevel
      },

      // Office document viewers - critical for shell spawning
      officeApps: {
        patterns: ['word', 'excel', 'powerpoint', 'pages', 'numbers', 'keynote', 'libreoffice', 'openoffice'],
        dangerousChildren: /bash|sh|zsh|curl|wget|nc|python|perl|ruby/i,
        reason: 'document-spawned-process',
        severity: 'CRITICAL' as SuspicionLevel
      },

      // Media players - high severity (codec exploits)
      mediaPlayers: {
        patterns: ['vlc', 'quicktime', 'iina', 'mpv', 'mplayerx', 'quicktime player'],
        dangerousChildren: /bash|sh|zsh|python|perl|ruby|curl|wget|nc/i,
        reason: 'media-player-spawned-shell',
        severity: 'HIGH' as SuspicionLevel
      },

      // Archive utilities - high severity (malicious archives)
      archiveUtils: {
        patterns: ['archive utility', 'unarchiver', 'keka', 'betterzip', 'stuffit', 'winzip', 'unrar', '7-zip'],
        dangerousChildren: /bash|sh|zsh|python|perl|ruby|curl|wget|nc/i,
        reason: 'archive-util-spawned-shell',
        severity: 'HIGH' as SuspicionLevel
      }
    };

    // Check each category
    for (const [category, config] of Object.entries(suspiciousParentPatterns)) {
      const isMatchingParent = config.patterns.some(pattern => parentName.includes(pattern));
      const isDangerousChild = config.dangerousChildren.test(procName) ||
                               config.dangerousChildren.test(proc.cmd || '');

      if (isMatchingParent && isDangerousChild) {
        reasons.push(config.reason);
        // Only upgrade severity, never downgrade
        if (config.severity === 'CRITICAL') {
          level = 'CRITICAL';
        } else if (config.severity === 'HIGH' && level !== 'CRITICAL') {
          level = 'HIGH';
        }
        break; // Found a match, no need to check other categories
      }
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

  // Check for zero-width characters in process names (unicode steganography)
  if (proc.name) {
    const zeroWidthChars = /[\u200B-\u200D\uFEFF\u180E\u2060]/;
    if (zeroWidthChars.test(proc.name)) {
      reasons.push('zero-width-chars');
      level = 'HIGH';
    }
  }

  // Check for process names mimicking system processes (homoglyph/typosquatting)
  if (proc.name) {
    const systemProcesses = [
      'kernel_task', 'launchd', 'systemd', 'init', 'loginwindow',
      'WindowServer', 'Finder', 'Dock', 'mds', 'mdworker', 'cfprefsd',
      'systemstats', 'distnoted', 'configd', 'coreaudiod', 'audiomxd',
      'UserEventAgent', 'coreservicesd', 'apsd', 'securityd'
    ];

    for (const sysProc of systemProcesses) {
      if (proc.name !== sysProc && isSimilarProcessName(proc.name, sysProc)) {
        reasons.push(`mimicking-system-process:${sysProc}`);
        level = 'HIGH';
        break;
      }
    }
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

/**
 * Check if a process name is suspiciously similar to a system process
 * Detects homoglyph attacks (e.g., 'kerne1_task' vs 'kernel_task')
 * and typosquatting (e.g., 'kernel-task' vs 'kernel_task')
 */
function isSimilarProcessName(procName: string, sysProc: string): boolean {
  const procLower = procName.toLowerCase();
  const sysLower = sysProc.toLowerCase();

  // Exact match (already handled by caller, but safety check)
  if (procLower === sysLower) {
    return false;
  }

  // Check for common character substitutions (homoglyphs)
  const homoglyphs: { [key: string]: string[] } = {
    'o': ['0', 'ο', 'о'], // letter o, zero, greek omicron, cyrillic o
    'i': ['1', 'l', 'і', 'ı'], // letter i, one, lowercase L, cyrillic i, dotless i
    'a': ['а', '@'], // letter a, cyrillic a, at symbol
    'e': ['е', '3'], // letter e, cyrillic e, number 3
    's': ['5', '$'], // letter s, number 5, dollar sign
    'l': ['1', 'i', 'І'], // lowercase L, one, letter i, cyrillic I
    't': ['7'], // letter t, number 7
    'g': ['9'], // letter g, number 9
    'b': ['8'], // letter b, number 8
  };

  // Create a normalized version of sysProc replacing homoglyphs
  let normalizedProc = procLower;
  for (const [original, substitutes] of Object.entries(homoglyphs)) {
    for (const sub of substitutes) {
      normalizedProc = normalizedProc.replace(new RegExp(sub, 'g'), original);
    }
  }

  if (normalizedProc === sysLower) {
    return true;
  }

  // Check for common separators replaced (e.g., kernel-task vs kernel_task)
  const procNormalized = procLower.replace(/[-_.\s]/g, '');
  const sysNormalized = sysLower.replace(/[-_.\s]/g, '');

  if (procNormalized === sysNormalized) {
    return true;
  }

  // Check for Levenshtein distance of 1-2 characters (typosquatting)
  const distance = levenshteinDistance(procLower, sysLower);
  if (distance <= 2 && procLower.length >= 5) {
    return true;
  }

  return false;
}

/**
 * Calculate Levenshtein distance between two strings
 * Used to detect typosquatting attacks
 */
function levenshteinDistance(str1: string, str2: string): number {
  const len1 = str1.length;
  const len2 = str2.length;
  const matrix: number[][] = [];

  // Initialize matrix
  for (let i = 0; i <= len1; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= len2; j++) {
    if (matrix[0]) {
      matrix[0][j] = j;
    }
  }

  // Fill matrix
  for (let i = 1; i <= len1; i++) {
    for (let j = 1; j <= len2; j++) {
      const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
      const prevRow = matrix[i - 1];
      const currRow = matrix[i];
      if (prevRow && currRow) {
        const deletion = prevRow[j] ?? 0;
        const insertion = currRow[j - 1] ?? 0;
        const substitution = prevRow[j - 1] ?? 0;
        currRow[j] = Math.min(
          deletion + 1,
          insertion + 1,
          substitution + cost
        );
      }
    }
  }

  return matrix[len1]?.[len2] ?? 0;
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