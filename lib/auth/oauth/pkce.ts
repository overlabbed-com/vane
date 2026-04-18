/**
 * PKCE (Proof Key for Code Exchange) utilities per RFC 7636.
 * 
 * Provides secure code challenge/verifier pair generation and validation
 * for OAuth 2.0 authorization code flow security.
 * 
 * Security features:
 * - CSPRNG for verifier generation (crypto.randomBytes)
 * - SHA256 challenge derivation
 * - Atomic verifier consumption via Redis Lua script
 * - 10-minute TTL (matches OAuth state TTL)
 * - Independent pkceId (not reusing state as key)
 * 
 * Reference:
 * - RFC 7636: https://datatracker.ietf.org/doc/html/rfc7636
 * - RFC 6749: https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.1
 */

import { createHash, randomBytes } from 'crypto';
import { getRedisClient } from '../redis';

// PKCE configuration
const PKCE_CONFIG = {
  // Verifier length: 32 bytes (RFC 7636 recommends 32-64)
  verifierLength: 32,
  
  // Code challenge length: 43 chars (base64url encoded SHA256)
  expectedChallengeLength: 43,
  
  // TTL: 10 minutes (matches OAuth state TTL)
  ttlSeconds: 600,
  
  // Key prefix in Redis
  keyPrefix: 'pkce:',
} as const;

/**
 * Generates a cryptographically random code verifier.
 * Uses crypto.randomBytes for CSPRNG, not Math.random().
 * 
 * @returns Base64URL-encoded verifier (43 characters)
 */
export function generateCodeVerifier(): string {
  const bytes = randomBytes(PKCE_CONFIG.verifierLength);
  return bytes.toString('base64url');
}

/**
 * Derives the code challenge from a verifier using S256 method.
 * Challenge = BASE64URL(SHA256(verifier))
 * 
 * @param verifier - The code verifier to hash
 * @returns Base64URL-encoded SHA256 hash (43 characters)
 */
export function deriveCodeChallenge(verifier: string): string {
  // SHA256 hash of verifier
  const hash = createHash('sha256').update(verifier).digest();
  return hash.toString('base64url');
}

/**
 * Generates a unique PKCE ID for key management.
 * Separate from state to avoid key reuse.
 * 
 * @returns 32-byte hex-encoded random ID
 */
function generatePkceId(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Stores a code verifier in Redis with TTL.
 * Uses SETEX for atomic TTL assignment.
 * 
 * @param pkceId - Unique identifier for this PKCE pair
 * @param verifier - The code verifier to store
 * @returns true if stored successfully
 */
export async function storeCodeVerifier(pkceId: string, verifier: string): Promise<boolean> {
  const redis = getRedisClient();
  const key = `${PKCE_CONFIG.keyPrefix}${pkceId}`;
  
  try {
    await redis.setex(key, PKCE_CONFIG.ttlSeconds, verifier);
    return true;
  } catch (error) {
    console.error(
      JSON.stringify({
        event: 'auth.pkce.store_error',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      })
    );
    return false;
  }
}

/**
 * Atomically consumes (retrieves and deletes) a code verifier.
 * Uses Lua script for atomic GET + DELETE operation.
 * 
 * CRITICAL: Deletes BEFORE returning to prevent race conditions.
 * Uses correct Lua syntax: redis.call('GET', KEYS[1])
 * 
 * @param pkceId - Unique identifier for this PKCE pair
 * @returns The verifier if found and deleted, null otherwise
 */
export async function consumeCodeVerifier(pkceId: string): Promise<string | null> {
  const redis = getRedisClient();
  const key = `${PKCE_CONFIG.keyPrefix}${pkceId}`;
  
  // Lua script for atomic consume:
  // 1. GET the verifier
  // 2. DELETE the key
  // 3. Return the verifier (or nil if not found)
  //
  // Note: Uses redis.call('GET', KEYS[1]) syntax, not GET KEYS[1]
  const luaScript = `
local verifier = redis.call('GET', KEYS[1])
if verifier then
  redis.call('DEL', KEYS[1])
  return verifier
end
return nil
  `.trim();
  
  try {
    const result = await redis.eval(luaScript, 1, key) as string | null;
    return result;
  } catch (error) {
    console.error(
      JSON.stringify({
        event: 'auth.pkce.consume_error',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      })
    );
    return null;
  }
}

/**
 * Generates a complete PKCE pair with stored verifier.
 * 
 * @returns Object containing verifier, challenge, and pkceId
 */
export async function generatePkce(): Promise<{
  codeVerifier: string;
  codeChallenge: string;
  pkceId: string;
}> {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = deriveCodeChallenge(codeVerifier);
  const pkceId = generatePkceId();
  
  // Store verifier with TTL
  await storeCodeVerifier(pkceId, codeVerifier);
  
  return { codeVerifier, codeChallenge, pkceId };
}

/**
 * Validates a code verifier format.
 * Used for input validation before storage or challenge derivation.
 * 
 * @param verifier - The verifier to validate
 * @returns true if format is valid
 */
export function isValidVerifierFormat(verifier: string): boolean {
  // Verifier must be:
  // - 43 characters (base64url encoded 32 bytes)
  // - URL-safe characters only
  if (!verifier || verifier.length !== PKCE_CONFIG.expectedChallengeLength) {
    return false;
  }
  
  // Check for valid base64url characters
  return /^[A-Za-z0-9_-]+$/.test(verifier);
}

/**
 * Validates a code challenge format.
 * 
 * @param challenge - The challenge to validate
 * @returns true if format is valid
 */
export function isValidChallengeFormat(challenge: string): boolean {
  // Challenge must be 43 characters (base64url encoded SHA256)
  if (!challenge || challenge.length !== PKCE_CONFIG.expectedChallengeLength) {
    return false;
  }
  
  // Check for valid base64url characters
  return /^[A-Za-z0-9_-]+$/.test(challenge);
}