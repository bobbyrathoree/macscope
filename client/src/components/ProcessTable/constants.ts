export const getLevelStyle = (level: string): string => {
  switch (level) {
    case 'CRITICAL':
      return 'bg-red-500 text-white shadow-sm border-l-4 border-red-600';
    case 'HIGH':
      return 'bg-orange-500 text-white shadow-sm border-l-4 border-orange-600';
    case 'MED':
      return 'bg-yellow-500 text-white shadow-sm border-l-4 border-yellow-600';
    case 'LOW':
      return 'bg-green-500 text-white shadow-sm border-l-4 border-green-600';
    default:
      return 'bg-gray-500 text-white shadow-sm border-l-4 border-gray-600';
  }
};

export const getNetworkStyle = (outbound: number, listen: number): string => {
  const total = outbound + listen;
  if (total >= 20) {
    return 'text-red-700 dark:text-red-300';
  } else if (total >= 10) {
    return 'text-orange-700 dark:text-orange-300';
  } else if (total >= 5) {
    return 'text-yellow-700 dark:text-yellow-300';
  }
  return 'text-blue-700 dark:text-blue-300';
};

export const getIndicatorStyle = (reason: string): string => {
  const keyloggerThreats = [
    'keylogger-with-network-activity',
    'input-monitoring-with-network',
    'unsigned-input-monitor',
    'accessibility-with-network',
  ];
  const highThreats = [
    'keylogger-pattern',
    'browser-spawned-input-monitor',
    'suspicious-data-upload-pattern',
  ];
  const mediumThreats = ['screen-recorder', 'remote-access', 'cryptominer'];
  const lowThreats = ['unsigned-binary', 'different-user', 'agent-ish', 'launchd-managed'];

  if (keyloggerThreats.includes(reason)) {
    return 'bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-300 border-l-4 border-red-500 shadow-sm';
  } else if (highThreats.includes(reason)) {
    return 'bg-orange-50 dark:bg-orange-950/30 text-orange-700 dark:text-orange-300 border-l-4 border-orange-500 shadow-sm';
  } else if (mediumThreats.includes(reason)) {
    return 'bg-yellow-50 dark:bg-yellow-950/30 text-yellow-700 dark:text-yellow-300 border-l-4 border-yellow-500 shadow-sm';
  } else if (lowThreats.includes(reason)) {
    return 'bg-blue-50 dark:bg-blue-950/30 text-blue-700 dark:text-blue-300 border-l-4 border-blue-500 shadow-sm';
  }
  return 'bg-gray-50 dark:bg-gray-800 text-gray-700 dark:text-gray-300 border-l-4 border-gray-400 shadow-sm';
};

export const levelDescriptions: Record<string, string> = {
  CRITICAL: '🚨 Immediate threat - likely malware or data theft',
  HIGH: '⚠️ High risk - investigate immediately',
  MED: '⚡ Medium risk - monitor closely',
  LOW: '✅ Low risk - normal system activity',
};

export const reasonDescriptions: Record<string, string> = {
  'keylogger-pattern': 'Matches known keylogger signatures',
  'keylogger-with-network-activity': '🚨 CRITICAL: Keylogger sending data over network!',
  'input-monitoring-with-network': '🚨 CRITICAL: Input monitoring + network activity',
  'unsigned-input-monitor': '🚨 CRITICAL: Unsigned binary with input access',
  'browser-spawned-input-monitor': 'Input monitoring process spawned from browser',
  'accessibility-with-network': '🚨 CRITICAL: Accessibility permissions + network use',
  'suspicious-data-upload-pattern': 'Unusual data upload patterns to suspicious domains',
  'screen-recorder': 'Screen capture or recording capabilities',
  'unsigned-binary': 'Binary is not code signed',
  'different-user': 'Process running under different user account',
  'agent-ish': 'Background agent or daemon process',
  'launchd-managed': 'Managed by macOS launch daemon system',
  'remote-access': 'Remote access or control capabilities',
  'cryptominer': 'Cryptocurrency mining software detected',
  'data-exfiltration': 'Data transfer or synchronization tool',
};

export const levelOrder: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MED: 2,
  LOW: 3,
};
