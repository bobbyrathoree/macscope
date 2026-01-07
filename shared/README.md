# Shared Types

This directory contains shared TypeScript type definitions used by both the server and client applications to eliminate type duplication.

## Usage

### In Server Code (src/, server/)

```typescript
// Using relative path
import { ProcessWireFormat, SuspicionLevel, Delta } from '../shared/types.js';

// Or using alias (configured in tsconfig.json)
import { ProcessWireFormat, SuspicionLevel, Delta } from '@shared/types';
```

### In Client Code (client/src/)

```typescript
// Using relative path
import { ProcessData, SuspicionLevel, WebSocketMessage } from '../../shared/types';

// Or using alias (configured in tsconfig.json and vite.config.ts)
import { ProcessData, SuspicionLevel, WebSocketMessage } from '@shared/types';
```

## Type Definitions

### Core Process Types

- **`SuspicionLevel`** - Union type: 'CRITICAL' | 'HIGH' | 'MED' | 'LOW'
- **`BaseProcessInfo`** - Base process information (pid, ppid, name, cmd, user, cpu, mem, execPath)
- **`ProcessWireFormat`** / **`ProcessData`** - The format sent over WebSocket from server to client
- **`ProcessRow`** - Server-side process representation with additional internal fields

### Connection Types

- **`ConnectionSummary`** - Connection info for wire format (uses array for remotes)
- **`ConnSummary`** - Server-side connection type (uses Set for remotes)
- **`NetworkStats`** - Network statistics for a process

### Code Signing Types

- **`CodesignData`** - Simplified codesign data for wire format
- **`CodesignInfo`** - Detailed server-side codesign information

### Security Types

- **`SuspicionInfo`** - Contains suspicion level and reasons

### WebSocket Types

- **`Delta`** - WebSocket delta update (added, updated, removed)
- **`WebSocketMessage`** - WebSocket message envelope

### System Types

- **`SystemStats`** - System statistics and process counts

### Constants

- **`SUSPICIOUS_PATTERNS`** - Patterns for suspicious process detection
- **`SUSPICIOUS_LOCATIONS`** - File paths considered suspicious
- **`TRUSTED_TEAMS`** - List of trusted code signing teams

## Configuration

The shared types are configured to work with:

1. **Root tsconfig.json** - Includes shared types and path mapping
2. **client/tsconfig.json** - Includes shared types with relative path mapping
3. **tsconfig.server.json** - Extends root config, inherits path mappings
4. **client/vite.config.ts** - Alias for @shared in Vite builds

## Benefits

- **Single source of truth** - All type definitions in one place
- **No duplication** - Same types used by server and client
- **Type safety** - Compile-time checking across the entire stack
- **Easy maintenance** - Update types in one place, apply everywhere
