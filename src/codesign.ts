import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { CodesignInfo } from './types.js';

const execFileP = promisify(execFile);

export async function getCodeSignInfo(pathOrCmd: string): Promise<CodesignInfo | null> {
  if (!pathOrCmd) return null;
  
  const execPath = pathOrCmd.split(' ')[0];
  if (!execPath || !execPath.startsWith('/')) return null;
  
  try {
    // First, verify the signature validity with timeout
    const validityCheck = await execFileP('codesign', ['-v', '--verify', execPath], {
      timeout: 3000 // 3 second timeout
    })
      .then(() => true)
      .catch((error) => {
        // Check if it's unsigned vs invalid signature
        const errorStr = error.stderr?.toString() || '';
        if (errorStr.includes('code object is not signed')) {
          return 'unsigned';
        }
        return false; // Invalid signature
      });
    
    // Get detailed info with timeout
    const { stderr } = await execFileP('codesign', ['-dv', '--verbose=2', execPath], {
      timeout: 3000 // 3 second timeout
    })
      .catch(() => ({ stderr: '' }));
    
    const out = stderr.toString();
    
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
    
    return {
      ...(teamIdentifier !== undefined && { teamIdentifier }),
      ...(authorities.length > 0 && { authorities }),
      signed: validityCheck !== 'unsigned',
      valid: validityCheck === true,
      ...(notarized && { notarized }),
      ...(identifier !== undefined && { identifier }),
      appStore: isAppStore
    };
  } catch (error) {
    // Binary might not exist or no permission
    return {
      signed: false,
      valid: false
    };
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
  
  if (info.appStore) {
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