# procscope

A real-time macOS security monitoring tool built with React + Ink for terminal UI. Monitors running processes and detects suspicious patterns including keyloggers, screen recorders, remote access tools, and cryptominers.

## Features

- **Real-time Process Monitoring**: View all running processes with CPU, memory, and network usage
- **Security Detection**: Identifies suspicious patterns including:
  - Keyloggers and input capture tools
  - Screen recording/capture tools
  - Remote access tools (TeamViewer, AnyDesk, etc.)
  - Cryptocurrency miners
  - Data exfiltration tools
  - Process injection patterns
- **Code Signature Verification**: Checks if binaries are signed, notarized, or from trusted sources
- **Network Analysis**: Monitors network connections and identifies anomalies
- **Automatic Logging**: HIGH and CRITICAL threats are logged to `~/.procscope/suspicious-processes.log`
- **Interactive UI**: Filter processes, scroll through results, view detailed information
- **MDM Status**: Check device management enrollment status

## Installation

```bash
npm install
```

## Usage

Run the monitoring tool:
```bash
npm start
# or with elevated privileges for fuller visibility
sudo npm start
```

View logged suspicious processes:
```bash
node view-logs.js        # Last 24 hours
node view-logs.js 48     # Last 48 hours
```

## Keyboard Shortcuts

- **↑/↓**: Navigate through processes
- **Enter**: View detailed information about selected process
- **Type**: Filter processes by name
- **r**: Refresh process list
- **m**: View MDM enrollment status
- **q**: Quit

## Security Levels

- **CRITICAL**: Malicious signatures, known malware patterns, document-spawned shells
- **HIGH**: Keyloggers, cryptominers, browser-spawned shells, suspicious signatures
- **MED**: Screen recorders, remote access tools, excessive network connections
- **LOW**: Normal processes with minor concerns

## Log Files

Suspicious processes (HIGH/CRITICAL) are automatically logged to:
```
~/.procscope/suspicious-processes.log
```

Logs are automatically cleaned up after 7 days.

## Requirements

- macOS (uses macOS-specific tools like `launchctl`, `lsof`, `codesign`)
- Node.js 18+
- Optional: `sudo` access for full process visibility

## Architecture

- **React + Ink**: Terminal UI framework
- **TypeScript**: Strict type checking enabled
- **Process Analysis**: Combines ps-list, lsof, launchctl, and codesign data
- **Pattern Detection**: Comprehensive suspicious pattern matching
- **Network Monitoring**: Real-time connection tracking