/**
 * Session management with versioning support.
 * 
 * Features:
 * - HMAC-SHA256 token derivation (token never stored raw)
 * - Token rotation support (dual-key during rotation)
 * - Session versioning for concurrent logout
 * - Redis-backed with TTL refresh
 * 
 * Session versioning allows atomic operations on groups of sessions:
 * - Version key tracks current version for a user
 * - Individual sessions reference their version
 * - Rotating version invalidates all sessions at once
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 1
 */

import { createSession as redisCreateSession, verifySession as redisVerifySession, revokeSession as redisRevokeSession, revokeSessionsByVersion, SessionData } from './redis';
import { generateTokenPair, deriveStoredToken, verifyToken, getSessionTtlSeconds } from './tokens';
import { logSessionBindingMismatch } from './audit';
import { createHash } from 'crypto';

// Session binding configuration
const SESSION_BINDING_CONFIG = {
  // IP subnet tolerance (e.g., /24 for IPv4, /64 for IPv6)
  ipSubnetBits: 24,
  // User agent fuzzy match threshold (0-1, higher = more strict)
  uaMatchThreshold: 0.7,
  // Enable session binding validation
  enabled: true,
} as const;

// Session version configuration
const SESSION_VERSION_CONFIG = {
  // Key prefix for session versions
  versionKeyPrefix: 'sessver:',
  // Default version for new sessions
  defaultVersion: 1,
  // Version TTL: 30 days (auto-cleanup of old versions)
  versionTtlSeconds: 30 * 24 * 60 * 60,
} as const;

/**
 * Creates a new session for a user.
 * 
 * @param userId - User ID
 * @param metadata - Optional metadata (IP, user agent)
 * @returns Session object with raw token (one-time display)
 */
export async function createSession(
  userId: string,
  metadata?: { ipAddress?: string; userAgent?: string }
): Promise<{
  token: string;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
  version: number;
}> {
  // Generate token pair
  const { rawToken, storedToken, createdAt, expiresAt } = generateTokenPair();

  // Get or create session version for this user
  const version = await getOrCreateSessionVersion(userId);

  // Store in Redis with version tracking
  await redisCreateSession(storedToken, userId, metadata, version);

  // Return raw token to client (one-time display)
  return {
    token: rawToken,
    userId,
    createdAt,
    expiresAt,
    version,
  };
}

/**
 * Normalizes an IP address for comparison.
 * Handles IPv4 and IPv6 addresses.
 */
function normalizeIp(ip: string): string {
  if (!ip) return '';
  
  // Handle IPv4-mapped IPv6 addresses (::ffff:192.168.1.1)
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }
  
  return ip.toLowerCase().trim();
}

/**
 * Gets the subnet prefix for an IP address.
 * Uses /24 for IPv4 and /64 for IPv6.
 */
function getIpSubnet(ip: string, bits: number = SESSION_BINDING_CONFIG.ipSubnetBits): string {
  const normalized = normalizeIp(ip);
  if (!normalized) return '';
  
  // Check if IPv6
  if (normalized.includes(':')) {
    // For IPv6, use /64 subnet
    const parts = normalized.split(':');
    return parts.slice(0, 4).join(':');
  }
  
  // For IPv4, split by octets and take the prefix
  const octets = normalized.split('.');
  const octetsToKeep = Math.ceil(bits / 8);
  return octets.slice(0, octetsToKeep).join('.');
}

/**
 * Compares two IP addresses within a subnet tolerance.
 */
function compareIpSubnet(ip1: string | undefined, ip2: string | undefined, bits: number = SESSION_BINDING_CONFIG.ipSubnetBits): boolean {
  if (!ip1 && !ip2) return true;
  if (!ip1 || !ip2) return false;
  
  return getIpSubnet(ip1, bits) === getIpSubnet(ip2, bits);
}

/**
 * Compares user agents with fuzzy matching.
 * Returns a score between 0 and 1.
 */
function compareUserAgent(ua1: string | undefined, ua2: string | undefined): number {
  if (!ua1 && !ua2) return 1;
  if (!ua1 || !ua2) return 0;
  
  // Normalize: lowercase, remove specific version numbers
  const normalizeUA = (ua: string) => ua.toLowerCase().replace(/\/[^/]+\//g, '/').replace(/\s+/g, ' ').trim();
  
  const norm1 = normalizeUA(ua1);
  const norm2 = normalizeUA(ua2);
  
  if (norm1 === norm2) return 1;
  
  // Simple token-based similarity
  const tokens1 = new Set(norm1.split(' '));
  const tokens2 = new Set(norm2.split(' '));
  
  let intersection = 0;
  for (const token of tokens1) {
    if (tokens2.has(token)) {
      intersection++;
    }
  }
  
  const union = tokens1.size + tokens2.size - intersection;
  return union > 0 ? intersection / union : 0;
}

/**
 * Validates session binding (IP and user agent).
 * Logs security events on mismatch.
 */
async function validateSessionBinding(
  session: SessionData,
  currentIp: string | undefined,
  currentUa: string | undefined
): Promise<{ valid: boolean; reason?: string }> {
  if (!SESSION_BINDING_CONFIG.enabled) {
    return { valid: true };
  }
  
  // Check IP binding (if session has stored IP)
  if (session.ipAddress && currentIp) {
    if (!compareIpSubnet(session.ipAddress, currentIp, SESSION_BINDING_CONFIG.ipSubnetBits)) {
      // Log security event
      await logSessionBindingMismatch(
        session.userId,
        currentIp,
        currentUa,
        'ip_mismatch',
        {
          stored_ip_subnet: getIpSubnet(session.ipAddress),
          current_ip_subnet: getIpSubnet(currentIp),
          stored_ip_hash: createHash('sha256').update(session.ipAddress).digest('hex').substring(0, 16),
          current_ip_hash: createHash('sha256').update(currentIp).digest('hex').substring(0, 16),
        }
      );
      return { valid: false, reason: 'ip_mismatch' };
    }
  }
  
  // Check user agent binding (if session has stored UA)
  if (session.userAgent && currentUa) {
    const similarity = compareUserAgent(session.userAgent, currentUa);
    if (similarity < SESSION_BINDING_CONFIG.uaMatchThreshold) {
      // Log security event
      await logSessionBindingMismatch(
        session.userId,
        currentIp,
        currentUa,
        'ua_mismatch',
        {
          similarity,
          threshold: SESSION_BINDING_CONFIG.uaMatchThreshold,
        }
      );
      return { valid: false, reason: 'ua_mismatch' };
    }
  }
  
  return { valid: true };
}

/**
 * Verifies a session token.
 * 
 * @param rawToken - Raw token from client request
 * @param clientMetadata - Current client metadata for binding validation
 * @returns Session data if valid, null otherwise
 */
export async function verifySession(
  rawToken: string,
  clientMetadata?: { ipAddress?: string; userAgent?: string }
): Promise<SessionData | null> {
  if (!rawToken) {
    return null;
  }

  // Derive stored token from raw token
  const storedToken = deriveStoredToken(rawToken);

  // Verify against Redis
  const session = await redisVerifySession(storedToken);
  
  if (!session) {
    return null;
  }

  // Check if session version is still valid
  const versionValid = await checkSessionVersion(session.userId, session.version);
  if (!versionValid) {
    // Session version was rotated, invalidate this session
    await revokeSession(rawToken);
    return null;
  }

  // Validate session binding (IP/UA)
  if (clientMetadata) {
    const bindingCheck = await validateSessionBinding(
      session,
      clientMetadata.ipAddress,
      clientMetadata.userAgent
    );
    if (!bindingCheck.valid) {
      // Binding mismatch - reject session
      await revokeSession(rawToken);
      return null;
    }
  }

  return session;
}

/**
 * Revokes a session (logout).
 * 
 * @param rawToken - Raw token from client request
 * @returns true if session was revoked
 */
export async function revokeSession(rawToken: string): Promise<boolean> {
  if (!rawToken) {
    return false;
  }

  const storedToken = deriveStoredToken(rawToken);
  return redisRevokeSession(storedToken);
}

/**
 * Revokes all sessions for a user (concurrent logout).
 * Uses session versioning for atomic invalidation.
 * 
 * @param userId - User ID
 * @returns Number of sessions revoked
 */
export async function revokeAllSessions(userId: string): Promise<number> {
  // Increment version to invalidate all existing sessions
  const newVersion = await incrementSessionVersion(userId);
  
  if (newVersion === null) {
    // No existing sessions to revoke
    return 0;
  }

  // Revoke all sessions with old version
  return revokeSessionsByVersion(userId, newVersion - 1);
}

/**
 * Gets the current session version for a user.
 * 
 * @param userId - User ID
 * @returns Current version number, or default if none exists
 */
export async function getSessionVersion(userId: string): Promise<number> {
  const { getRedisClient } = await import('./redis');
  const redis = getRedisClient();
  const key = `${SESSION_VERSION_CONFIG.versionKeyPrefix}${userId}`;

  try {
    const version = await redis.get(key);
    if (version === null) {
      return SESSION_VERSION_CONFIG.defaultVersion;
    }
    return parseInt(version, 10);
  } catch {
    return SESSION_VERSION_CONFIG.defaultVersion;
  }
}

/**
 * Gets or creates a session version for a user.
 * 
 * @param userId - User ID
 * @returns Current version number
 */
async function getOrCreateSessionVersion(userId: string): Promise<number> {
  const { getRedisClient } = await import('./redis');
  const redis = getRedisClient();
  const key = `${SESSION_VERSION_CONFIG.versionKeyPrefix}${userId}`;

  try {
    // Try to get existing version
    const existing = await redis.get(key);
    if (existing !== null) {
      return parseInt(existing, 10);
    }

    // Create new version with TTL
    await redis.setex(key, SESSION_VERSION_CONFIG.versionTtlSeconds, '1');
    return 1;
  } catch {
    return SESSION_VERSION_CONFIG.defaultVersion;
  }
}

/**
 * Increments the session version for a user.
 * This invalidates all existing sessions for the user.
 * 
 * @param userId - User ID
 * @returns New version number, or null if no version existed
 */
async function incrementSessionVersion(userId: string): Promise<number | null> {
  const { getRedisClient } = await import('./redis');
  const redis = getRedisClient();
  const key = `${SESSION_VERSION_CONFIG.versionKeyPrefix}${userId}`;

  try {
    // Get current version
    const current = await redis.get(key);
    
    // Increment
    const newVersion = current !== null 
      ? parseInt(current, 10) + 1 
      : SESSION_VERSION_CONFIG.defaultVersion;

    // Store new version with TTL
    await redis.setex(key, SESSION_VERSION_CONFIG.versionTtlSeconds, newVersion.toString());
    
    return newVersion;
  } catch {
    return null;
  }
}

/**
 * Checks if a session version is still valid.
 * 
 * @param userId - User ID
 * @param sessionVersion - Version number from session
 * @returns true if version matches current
 */
async function checkSessionVersion(userId: string, sessionVersion: number): Promise<boolean> {
  const currentVersion = await getSessionVersion(userId);
  return sessionVersion === currentVersion;
}

/**
 * Gets session TTL in seconds.
 */
export function getSessionTtl(): number {
  return getSessionTtlSeconds();
}