/**
 * Unified session creation for all authentication methods.
 * 
 * This module provides a single entry point for creating sessions regardless
 * of the authentication method used (password, API key, or social login).
 * 
 * Session features:
 * - HMAC-SHA256 token derivation
 * - Token rotation support
 * - Session versioning for concurrent logout
 * - Redis-backed with TTL refresh
 * - Session binding (IP, user agent)
 * - Session affinity for load balancer routing
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 1, Phase 4
 */

import { createHmac, timingSafeEqual } from 'crypto';

export { createSession, verifySession, revokeSession, revokeAllSessions, getSessionVersion } from './verify';
export type { SessionData } from './redis';

/**
 * Session affinity secret - required for HMAC.
 * Must be set at startup.
 */
const SESSION_AFFINITY_SECRET = process.env.SESSION_AFFINITY_SECRET;

// Validate at startup - secret is required
if (!SESSION_AFFINITY_SECRET) {
  throw new Error('SESSION_AFFINITY_SECRET environment variable is required');
}

/**
 * Regex for validating 64-character hex string.
 * Used before Buffer.from() to prevent silent truncation.
 */
const HEX_REGEX = /^[a-fA-F0-9]{64}$/;

/**
 * Gets the session affinity key.
 * Used by load balancer to route same session to same replica.
 * Uses full HMAC-SHA256 output (64 hex characters = 256 bits).
 * 
 * @param sessionToken - Session token
 * @returns Affinity key (64 characters, full HMAC-SHA256)
 */
export function getSessionAffinityKey(sessionToken: string): string {
  // Full HMAC-SHA256 output (64 hex chars = 256 bits)
  // No truncation - full entropy
  const hash = createHmac('sha256', SESSION_AFFINITY_SECRET!)
    .update(sessionToken)
    .digest('hex');
  return hash;
}

/**
 * Verifies a session affinity key.
 * Uses constant-time comparison to prevent timing attacks.
 * 
 * @param sessionToken - Session token
 * @param affinityKey - Affinity key to verify
 * @returns true if key matches
 */
export function verifySessionAffinity(
  sessionToken: string, 
  affinityKey: string
): boolean {
  // Validate affinityKey is exactly 64 hex chars before Buffer.from()
  // Invalid hex chars are silently truncated by Buffer.from()
  if (!HEX_REGEX.test(affinityKey)) {
    return false;
  }
  
  const expected = getSessionAffinityKey(sessionToken);
  const expectedBuffer = Buffer.from(expected, 'hex');
  const actualBuffer = Buffer.from(affinityKey, 'hex');
  
  // Constant-time comparison to prevent timing attacks
  if (expectedBuffer.length !== actualBuffer.length) {
    return false;
  }
  return timingSafeEqual(expectedBuffer, actualBuffer);
}