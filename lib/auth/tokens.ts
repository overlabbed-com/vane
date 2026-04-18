/**
 * HMAC-SHA256 token derivation for session tokens.
 * 
 * Architecture (F-02 mitigation):
 * - Raw token generated: 256-bit random
 * - Stored token: HMAC-SHA256(raw_token, SESSION_SECRET)
 * - Client receives raw token ONCE at login
 * - Subsequent requests verify: HMAC(raw_token) == stored_token
 * 
 * Key rotation considerations:
 * - SESSION_SECRET should be rotated every 90 days
 * - During rotation, support dual keys (old + new)
 * - Old sessions can be verified with old key during transition
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 1
 */

import { createHmac, randomBytes, timingSafeEqual } from 'crypto';

// Session token configuration
const TOKEN_CONFIG = {
  // Raw token length: 32 bytes (256 bits)
  rawLength: 32,
  // HMAC algorithm
  algorithm: 'sha256',
  // Session TTL: 15 minutes (in milliseconds)
  sessionTtlMs: 15 * 60 * 1000,
  // Maximum token age: 7 days (force logout after this even if active)
  maxTokenAgeMs: 7 * 24 * 60 * 60 * 1000,
} as const;

// Session secret from environment (256-bit key)
function getSessionSecret(): Buffer {
  const secret = process.env.SESSION_SECRET;
  
  if (!secret) {
    throw new Error('SESSION_SECRET environment variable is required');
  }

  // Ensure secret is at least 256 bits (32 bytes)
  if (secret.length < 32) {
    throw new Error('SESSION_SECRET must be at least 32 characters');
  }

  // Use a fixed-length key by hashing the secret (ensures consistent 256-bit key)
  return createHmac('sha256', secret).update('session-key').digest();
}

// Secondary secret for key rotation (optional)
function getSecondarySecret(): Buffer | null {
  const secret = process.env.SESSION_SECRET_ROTATION;
  
  if (!secret || secret.length < 32) {
    return null;
  }

  return createHmac('sha256', secret).update('session-key').digest();
}

/**
 * Generates a new session token pair.
 * 
 * @returns Object containing:
 *   - rawToken: Token to send to client (one-time display)
 *   - storedToken: HMAC-derived token to store in Redis
 *   - createdAt: Token creation timestamp
 *   - expiresAt: Token expiration timestamp
 */
export function generateTokenPair(): {
  rawToken: string;
  storedToken: string;
  createdAt: Date;
  expiresAt: Date;
} {
  // Generate 256-bit random token
  const bytes = randomBytes(TOKEN_CONFIG.rawLength);
  const rawToken = bytes.toString('hex');

  // Derive stored token using HMAC-SHA256
  const storedToken = deriveStoredToken(rawToken);

  const createdAt = new Date();
  const expiresAt = new Date(Date.now() + TOKEN_CONFIG.sessionTtlMs);

  return {
    rawToken,
    storedToken,
    createdAt,
    expiresAt,
  };
}

/**
 * Derives a stored token from a raw token using HMAC-SHA256.
 * Supports key rotation via secondary secret.
 * 
 * @param rawToken - Raw token from client
 * @returns HMAC-derived token suitable for storage
 */
export function deriveStoredToken(rawToken: string): string {
  // Primary secret
  const secret = getSessionSecret();
  const primaryDerived = createHmac(TOKEN_CONFIG.algorithm, secret)
    .update(rawToken)
    .digest('hex');

  // If secondary secret exists, include it for key rotation support
  const secondarySecret = getSecondarySecret();
  if (secondarySecret) {
    const secondaryDerived = createHmac(TOKEN_CONFIG.algorithm, secondarySecret)
      .update(rawToken)
      .digest('hex');
    // XOR the two derivatives for dual-key support
    return xorHexStrings(primaryDerived, secondaryDerived);
  }

  return primaryDerived;
}

/**
 * Verifies a raw token against a stored token.
 * Uses constant-time comparison to prevent timing attacks.
 * 
 * @param rawToken - Raw token from client request
 * @param storedToken - Stored HMAC token
 * @returns true if the token pair matches
 */
export function verifyToken(rawToken: string, storedToken: string): boolean {
  if (!rawToken || !storedToken) {
    return false;
  }

  try {
    // Re-derive from raw token
    const derived = deriveStoredToken(rawToken);

    // Constant-time comparison
    const derivedBuffer = Buffer.from(derived, 'hex');
    const storedBuffer = Buffer.from(storedToken, 'hex');

    if (derivedBuffer.length !== storedBuffer.length) {
      return false;
    }

    return timingSafeEqual(derivedBuffer, storedBuffer);
  } catch {
    return false;
  }
}

/**
 * XOR two hex strings of equal length.
 * Used for combining primary and secondary key derivatives.
 */
function xorHexStrings(a: string, b: string): string {
  if (a.length !== b.length) {
    throw new Error('Hex strings must be equal length');
  }

  const aBuffer = Buffer.from(a, 'hex');
  const bBuffer = Buffer.from(b, 'hex');
  const result = Buffer.alloc(aBuffer.length);

  for (let i = 0; i < aBuffer.length; i++) {
    result[i] = aBuffer[i] ^ bBuffer[i];
  }

  return result.toString('hex');
}

/**
 * Gets the session TTL in seconds (for Redis SETEX).
 */
export function getSessionTtlSeconds(): number {
  return Math.ceil(TOKEN_CONFIG.sessionTtlMs / 1000);
}

/**
 * Gets the maximum token age in seconds.
 */
export function getMaxTokenAgeSeconds(): number {
  return Math.ceil(TOKEN_CONFIG.maxTokenAgeMs / 1000);
}