import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { stat } from 'node:fs/promises';
import type { CodesignInfo } from './types';

const execFileP = promisify(execFile);

// Cache configuration
const MAX_CACHE_SIZE = 500;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

interface CacheEntry {
  result: CodesignInfo;
  mtime: number;
  inode: number;
  cachedAt: number;
}

// LRU cache using Map (maintains insertion order)
const codesignCache = new Map<string, CacheEntry>();

function logCacheStats(hit: boolean, path: string) {
  if (process.env.DEBUG_CODESIGN_CACHE) {
    console.log(`[Codesign Cache] ${hit ? 'HIT' : 'MISS'}: ${path}`);
  }
}

async function isCacheValid(path: string, entry: CacheEntry): Promise<boolean> {
  try {
    const stats = await stat(path);
    const now = Date.now();

    // Check TTL
    if (now - entry.cachedAt > CACHE_TTL_MS) {
      return false;
    }

    // Check if file has been modified (compare mtime and inode)
    const mtimeMs = stats.mtimeMs;
    const inode = stats.ino;

    return mtimeMs === entry.mtime && inode === entry.inode;
  } catch {
    // File no longer exists or not accessible
    return false;
  }
}

function addToCache(path: string, result: CodesignInfo, mtime: number, inode: number) {
  // Implement LRU: if cache is full, delete oldest entry (first in Map)
  if (codesignCache.size >= MAX_CACHE_SIZE) {
    const oldestKey = codesignCache.keys().next().value;
    if (oldestKey) {
      codesignCache.delete(oldestKey);
    }
  }

  codesignCache.set(path, {
    result,
    mtime,
    inode,
    cachedAt: Date.now()
  });
}

async function getFromCache(path: string): Promise<CodesignInfo | null> {
  const entry = codesignCache.get(path);

  if (!entry) {
    return null;
  }

  // Validate cache entry
  if (!(await isCacheValid(path, entry))) {
    codesignCache.delete(path);
    return null;
  }

  // Move to end (LRU: most recently used)
  codesignCache.delete(path);
  codesignCache.set(path, entry);

  return entry.result;
}

export async function getCodeSignInfo(pathOrCmd: string): Promise<CodesignInfo | null> {
  if (!pathOrCmd) return null;

  const execPath = pathOrCmd.split(' ')[0];
  if (!execPath || !execPath.startsWith('/')) return null;

  // Check cache first
  const cached = await getFromCache(execPath);
  if (cached !== null) {
    logCacheStats(true, execPath);
    return cached;
  }

  logCacheStats(false, execPath);

  try {
    // Get file stats for caching (before codesign checks)
    let fileStats;
    try {
      fileStats = await stat(execPath);
    } catch {
      // File doesn't exist or not accessible
      return {
        signed: false,
        valid: false
      };
    }

    // Combine both codesign calls: Use detailed output which includes validity info
    // This is more efficient than making two separate calls
    let validityCheck: true | false | 'unsigned' = false;
    let detailOutput = '';

    try {
      // Try to get detailed info first
      const { stderr } = await execFileP('codesign', ['-dv', '--verbose=2', execPath], {
        timeout: 3000 // 3 second timeout
      });
      detailOutput = stderr.toString();

      // If we got details, now verify validity
      await execFileP('codesign', ['-v', '--verify', execPath], {
        timeout: 3000
      });
      validityCheck = true;
    } catch (error: any) {
      // Check the error to determine if unsigned or invalid
      const errorStr = error.stderr?.toString() || '';

      if (errorStr.includes('code object is not signed')) {
        validityCheck = 'unsigned';
        // Still try to get detail output (might have partial info)
        detailOutput = errorStr;
      } else {
        // Invalid signature or other error
        validityCheck = false;
        // Try to get detail output anyway
        try {
          const { stderr } = await execFileP('codesign', ['-dv', '--verbose=2', execPath], {
            timeout: 3000
          }).catch(() => ({ stderr: '' }));
          detailOutput = stderr.toString();
        } catch {
          detailOutput = '';
        }
      }
    }

    const out = detailOutput;

    // Extract team identifier
    const teamMatch = out.match(/TeamIdentifier=(.+)/);
    const teamIdentifier = teamMatch?.[1]?.trim();

    // Extract certificate authorities chain
    const authorities = [...out.matchAll(/Authority=(.+)/g)]
      .map(m => m[1]?.trim())
      .filter((auth): auth is string => auth !== undefined);

    // Check if it's notarized (more secure)
    const notarized = out.includes('Notarized=yes') ||
                     authorities.some(auth => auth.includes('Developer ID'));

    // Extract identifier/bundle ID
    const identifierMatch = out.match(/Identifier=(.+)/);
    const identifier = identifierMatch?.[1]?.trim();

    // Check if it's from App Store
    const isAppStore = authorities.some(auth =>
      auth.includes('Apple Mac OS Application Signing') ||
      auth.includes('Apple iPhone OS Application Signing')
    );

    const result: CodesignInfo = {
      ...(teamIdentifier !== undefined && { teamIdentifier }),
      ...(authorities.length > 0 && { authorities }),
      signed: validityCheck !== 'unsigned',
      valid: validityCheck === true,
      ...(notarized && { notarized }),
      ...(identifier !== undefined && { identifier }),
      ...(isAppStore && { isAppStore })
    };

    // Cache the result with file stats
    addToCache(execPath, result, fileStats.mtimeMs, fileStats.ino);

    return result;
  } catch (error) {
    // Binary might not exist or no permission
    const result: CodesignInfo = {
      signed: false,
      valid: false
    };

    // Don't cache errors as they might be transient
    return result;
  }
}

export async function checkBinaryTrust(info: CodesignInfo | null): Promise<{
  trustLevel: 'trusted' | 'verified' | 'unknown' | 'suspicious' | 'malicious';
  reasons: string[];
}> {
  const reasons: string[] = [];
  
  if (!info) {
    return { trustLevel: 'unknown', reasons: ['no-codesign-info'] };
  }
  
  if (!info.signed) {
    reasons.push('unsigned');
    return { trustLevel: 'suspicious', reasons };
  }
  
  if (info.valid === false) {
    reasons.push('invalid-signature');
    return { trustLevel: 'malicious', reasons };
  }
  
  // Check for trusted teams
  const trustedTeams = [
    'com.apple',
    'com.microsoft', 
    'com.google',
    'org.mozilla',
    'com.adobe'
  ];
  
  if (info.teamIdentifier && trustedTeams.some(team => 
    info.teamIdentifier?.toLowerCase().includes(team)
  )) {
    reasons.push('trusted-vendor');
    return { trustLevel: 'trusted', reasons };
  }
  
  if (info.isAppStore) {
    reasons.push('app-store');
    return { trustLevel: 'trusted', reasons };
  }
  
  if (info.notarized) {
    reasons.push('notarized');
    return { trustLevel: 'verified', reasons };
  }
  
  if (info.authorities && info.authorities.length > 0) {
    reasons.push('developer-signed');
    return { trustLevel: 'verified', reasons };
  }
  
  return { trustLevel: 'unknown', reasons: ['unverified'] };
}