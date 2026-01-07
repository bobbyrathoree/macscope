import { X, Shield, AlertTriangle, Network, Terminal, FileText } from 'lucide-react';
import clsx from 'clsx';
import { useEffect, useRef } from 'react';
import type { ProcessData } from '../types';

interface ProcessDetailsProps {
  process: ProcessData;
  onClose: () => void;
}

export function ProcessDetails({ process, onClose }: ProcessDetailsProps) {
  const modalRef = useRef<HTMLDivElement>(null);
  const previousActiveElement = useRef<HTMLElement | null>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    // Store the element that was focused before opening the modal
    previousActiveElement.current = document.activeElement as HTMLElement;

    // Focus the close button when modal opens
    closeButtonRef.current?.focus();

    // Lock body scroll
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    // Handle Escape key
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    // Handle Tab key for focus trap
    const handleTab = (e: KeyboardEvent) => {
      if (e.key !== 'Tab' || !modalRef.current) return;

      const focusableElements = modalRef.current.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      );
      const focusableArray = Array.from(focusableElements);
      const firstElement = focusableArray[0];
      const lastElement = focusableArray[focusableArray.length - 1];

      if (e.shiftKey) {
        // Shift + Tab: if on first element, go to last
        if (document.activeElement === firstElement) {
          e.preventDefault();
          lastElement?.focus();
        }
      } else {
        // Tab: if on last element, go to first
        if (document.activeElement === lastElement) {
          e.preventDefault();
          firstElement?.focus();
        }
      }
    };

    document.addEventListener('keydown', handleEscape);
    document.addEventListener('keydown', handleTab);

    // Cleanup function
    return () => {
      document.removeEventListener('keydown', handleEscape);
      document.removeEventListener('keydown', handleTab);
      document.body.style.overflow = originalOverflow;

      // Return focus to the element that had it before the modal opened
      if (previousActiveElement.current) {
        previousActiveElement.current.focus();
      }
    };
  }, [onClose]);

  const handleBackdropClick = (e: React.MouseEvent<HTMLDivElement>) => {
    // Close modal if clicking the backdrop (not the modal content)
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  return (
    <div
      className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
      onClick={handleBackdropClick}
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
    >
      <div
        ref={modalRef}
        className="bg-white dark:bg-gray-900 rounded-xl shadow-2xl max-w-3xl w-full max-h-[80vh] overflow-y-auto"
      >
        <div className="sticky top-0 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 p-6">
          <div className="flex items-start justify-between">
            <div>
              <h2 id="modal-title" className="text-2xl font-bold">{process.name}</h2>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                PID: {process.pid} {process.ppid && `• PPID: ${process.ppid}`}
              </p>
            </div>
            <button
              ref={closeButtonRef}
              onClick={onClose}
              className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
              aria-label="Close modal"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
          
          <div className="mt-4">
            <span className={clsx(
              'px-3 py-1.5 text-sm font-semibold rounded-full',
              `level-${process.level.toLowerCase()}`
            )}>
              {process.level} RISK
            </span>
          </div>
        </div>
        
        <div className="p-6 space-y-6">
          <Section icon={<Terminal />} title="Process Information">
            <InfoRow label="User" value={process.user || 'Unknown'} />
            <InfoRow label="CPU Usage" value={`${process.cpu.toFixed(1)}%`} />
            <InfoRow label="Memory Usage" value={`${process.mem.toFixed(1)}%`} />
            {process.parent && <InfoRow label="Parent Process" value={process.parent} />}
            {process.launchd && <InfoRow label="LaunchD" value={process.launchd} />}
          </Section>
          
          {process.cmd && (
            <Section icon={<FileText />} title="Command">
              <pre className="text-xs bg-gray-100 dark:bg-gray-800 p-3 rounded-lg overflow-x-auto">
                {process.cmd}
              </pre>
            </Section>
          )}
          
          {process.execPath && (
            <Section icon={<FileText />} title="Executable Path">
              <code className="text-sm text-blue-600 dark:text-blue-400">
                {process.execPath}
              </code>
            </Section>
          )}
          
          <Section icon={<Network />} title="Network Activity">
            <InfoRow label="Outbound Connections" value={process.connections.outbound} />
            <InfoRow label="Listening Ports" value={process.connections.listen} />
            {process.connections.remotes.length > 0 && (
              <div className="mt-2">
                <p className="text-sm font-medium mb-1">Remote Addresses:</p>
                <div className="flex flex-wrap gap-2">
                  {process.connections.remotes.map((remote, i) => (
                    <span key={i} className="text-xs px-2 py-1 bg-gray-100 dark:bg-gray-800 rounded">
                      {remote}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </Section>
          
          {process.codesign && (
            <Section icon={<Shield />} title="Code Signature">
              <InfoRow 
                label="Signed" 
                value={process.codesign.signed ? 'Yes' : 'No'}
                valueClass={process.codesign.signed ? 'text-green-600' : 'text-red-600'}
              />
              {process.codesign.signed && (
                <>
                  <InfoRow 
                    label="Valid" 
                    value={process.codesign.valid ? 'Yes' : 'No'}
                    valueClass={process.codesign.valid ? 'text-green-600' : 'text-red-600'}
                  />
                  {process.codesign.teamId && (
                    <InfoRow label="Team ID" value={process.codesign.teamId} />
                  )}
                  {process.codesign.notarized && (
                    <InfoRow label="Notarized" value="Yes" valueClass="text-green-600" />
                  )}
                  {process.codesign.appStore && (
                    <InfoRow label="App Store" value="Yes" valueClass="text-blue-600" />
                  )}
                </>
              )}
            </Section>
          )}
          
          {process.reasons.length > 0 && (
            <Section icon={<AlertTriangle />} title="Security Indicators">
              <div className="space-y-2">
                {process.reasons.map((reason, i) => {
                  const isKeylogger = reason.includes('keylogger') || reason.includes('input-monitoring');
                  const isCritical = process.level === 'CRITICAL' && isKeylogger;
                  
                  const detailedDescriptions: Record<string, string> = {
                    'keylogger-pattern': 'Process name or binary matches known keylogger signatures. May capture keyboard input.',
                    'keylogger-with-network-activity': 'CRITICAL THREAT: Process shows keylogging patterns AND is making network connections - potential data theft!',
                    'input-monitoring-with-network': 'CRITICAL THREAT: Process uses input monitoring APIs and has active network connections - classic spyware behavior.',
                    'unsigned-input-monitor': 'CRITICAL THREAT: Unsigned binary with input monitoring capabilities - high risk of malware.',
                    'browser-spawned-input-monitor': 'Input monitoring process was spawned by a web browser or document viewer - potential exploit.',
                    'accessibility-with-network': 'CRITICAL THREAT: Process has accessibility permissions and network access - can capture everything.',
                    'suspicious-data-upload-pattern': 'Process shows unusual network patterns: many connections to suspicious domains or raw IP addresses.',
                    'screen-recorder': 'Process has screen capture or recording capabilities - may record sensitive information.',
                    'unsigned-binary': 'Binary is not code signed by a trusted developer - could be malware or tampered software.',
                    'different-user': 'Process is running under a different user account than expected - privilege escalation concern.',
                    'agent-ish': 'Background agent or daemon process - common vector for persistent threats.',
                    'launchd-managed': 'Managed by macOS launch system - has elevated privileges and persistence.',
                    'remote-access': 'Remote access or control tool detected - could allow unauthorized system access.',
                    'cryptominer': 'Cryptocurrency mining software - consumes resources and may be unauthorized.',
                    'data-exfiltration': 'Data transfer or cloud sync tool - monitor for unauthorized data movement.',
                  };
                  
                  return (
                    <div key={i} className={clsx(
                      "flex items-center gap-2 p-2 rounded cursor-help group relative",
                      isCritical && "bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800"
                    )}>
                      <div className={clsx(
                        "w-1.5 h-1.5 rounded-full",
                        isCritical ? "bg-red-600 animate-pulse" : "bg-orange-500"
                      )} />
                      <span className={clsx(
                        "text-sm",
                        isCritical && "text-red-700 dark:text-red-300 font-medium"
                      )}>
                        {reason.replace(/-/g, ' ')}
                      </span>
                      {isCritical && (
                        <span className="text-xs px-2 py-1 bg-red-600 text-white rounded-full">
                          KEYLOGGER THREAT
                        </span>
                      )}
                      <div className="absolute bottom-full left-0 mb-2 px-3 py-2 bg-gray-900 text-white text-xs rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none whitespace-normal z-50 max-w-md">
                        {detailedDescriptions[reason] || reason.replace(/-/g, ' ')}
                        <div className="absolute top-full left-4 w-0 h-0 border-l-4 border-r-4 border-t-4 border-transparent border-t-gray-900"></div>
                      </div>
                    </div>
                  );
                })}
              </div>
              
              {process.reasons.some(r => r.includes('keylogger') || r.includes('input-monitoring')) && (
                <div className="mt-4 p-3 bg-yellow-50 dark:bg-yellow-950/30 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                  <h4 className="text-sm font-medium text-yellow-800 dark:text-yellow-200 mb-2">
                    ⚠️ Input Monitoring Detected
                  </h4>
                  <p className="text-xs text-yellow-700 dark:text-yellow-300">
                    This process may be capturing keyboard input, mouse events, or screen content. 
                    If this is unexpected, investigate immediately as it could indicate malware or spyware.
                  </p>
                  {process.connections.outbound > 0 && (
                    <p className="text-xs text-red-700 dark:text-red-300 mt-1 font-medium">
                      🚨 Process is also making network connections - potential data exfiltration risk!
                    </p>
                  )}
                </div>
              )}
            </Section>
          )}
        </div>
      </div>
    </div>
  );
}

function Section({ icon, title, children }: { 
  icon: React.ReactNode; 
  title: string; 
  children: React.ReactNode;
}) {
  return (
    <div>
      <h3 className="flex items-center gap-2 text-lg font-semibold mb-3">
        {icon}
        {title}
      </h3>
      <div className="space-y-2">
        {children}
      </div>
    </div>
  );
}

function InfoRow({ label, value, valueClass }: { 
  label: string; 
  value: React.ReactNode;
  valueClass?: string;
}) {
  return (
    <div className="flex justify-between items-center py-1">
      <span className="text-sm text-gray-600 dark:text-gray-400">{label}:</span>
      <span className={clsx("text-sm font-medium", valueClass)}>{value}</span>
    </div>
  );
}