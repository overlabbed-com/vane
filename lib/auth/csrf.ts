/**
 * CSRF token generation and validation.
 * 
 * Uses the Double Submit Cookie pattern:
 * - Token generated: 256-bit random (cryptographically secure)
 * - Stored in Redis keyed by session token
 * - Cookie: Accessible to JavaScript (httpOnly: false)
 * - Header: X-CSRF-Token required on state-changing requests
 * 
 * Reference: H3 finding
 */

import { randomBytes, timingSafeEqual } from 'crypto';
import { getRedisClient } from './redis';

// CSRF configuration
const CSRF_CONFIG = {
  // Token length: 32 bytes (256 bits)
  tokenLength: 32,
  // Key prefix for CSRF tokens in Redis
  keyPrefix: 'csrf:',
  // TTL: 15 minutes (matches session TTL)
  ttlSeconds: 15 * 60,
} as const;

/**
 * Generates a cryptographically random CSRF token.
 * 
 * @returns 64-character hex string (256 bits)
 */
export function generateCsrfToken(): string {
  return randomBytes(CSRF_CONFIG.tokenLength).toString('hex');
}

/**
 * Stores a CSRF token in Redis, associated with a session.
 * 
 * @param sessionToken - The session token (raw token from login)
 * @param csrfToken - The CSRF token to store
 * @returns Promise resolving when stored
 */
export async function storeCsrfToken(
  sessionToken: string,
  csrfToken: string
): Promise<void> {
  const redis = getRedisClient();
  const key = `${CSRF_CONFIG.keyPrefix}${sessionToken}`;
  
  await redis.setex(key, CSRF_CONFIG.ttlSeconds, csrfToken);
}

/**
 * Retrieves a stored CSRF token from Redis.
 * 
 * @param sessionToken - The session token
 * @returns The CSRF token, or null if not found/expired
 */
export async function getCsrfToken(sessionToken: string): Promise<string | null> {
  const redis = getRedisClient();
  const key = `${CSRF_CONFIG.keyPrefix}${sessionToken}`;
  
  return redis.get(key);
}

/**
 * Validates a CSRF token from a request.
 * Uses constant-time comparison to prevent timing attacks.
 * 
 * @param sessionToken - The session token from cookie
 * @param requestToken - The CSRF token from X-CSRF-Token header
 * @returns true if valid, false otherwise
 */
export async function validateCsrfToken(
  sessionToken: string,
  requestToken: string
): Promise<boolean> {
  if (!sessionToken || !requestToken) {
    return false;
  }

  const storedToken = await getCsrfToken(sessionToken);
  
  if (!storedToken) {
    return false;
  }

  // Constant-time comparison to prevent timing attacks
  try {
    const storedBuffer = Buffer.from(storedToken, 'hex');
    const requestBuffer = Buffer.from(requestToken, 'hex');

    if (storedBuffer.length !== requestBuffer.length) {
      return false;
    }

    return timingSafeEqual(storedBuffer, requestBuffer);
  } catch {
    return false;
  }
}

/**
 * Invalidates a CSRF token (logout or session change).
 * 
 * @param sessionToken - The session token
 * @returns true if token was deleted
 */
export async function deleteCsrfToken(sessionToken: string): Promise<boolean> {
  const redis = getRedisClient();
  const key = `${CSRF_CONFIG.keyPrefix}${sessionToken}`;
  
  const result = await redis.del(key);
  return result > 0;
}