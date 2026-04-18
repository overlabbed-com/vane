/**
 * API key hashing using Argon2id.
 * 
 * API keys are high-entropy tokens (256-bit random), so we use Argon2id
 * to derive a storage hash that is timing-safe to verify.
 * 
 * Security properties:
 * - API keys are never stored in plaintext
 * - Verification uses constant-time comparison via argon2.verify
 * - Memory-hard to resist GPU cracking
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 1
 */

import * as argon2 from 'argon2';
import { randomBytes } from 'crypto';

// Argon2id configuration (same as password hashing for consistency)
const API_KEY_ARGON2_CONFIG = {
  // Time cost: 3 iterations
  timeCost: 3,
  // Memory cost: 64MB (65536 KB)
  memoryCost: 65536,
  // Parallelism: 4 threads
  parallelism: 4,
  // Argon2id variant
  type: argon2.argon2id,
  // Salt length: 16 bytes (for uniqueness)
  saltLength: 16,
  // Hash length: 32 bytes (256 bits)
  hashLength: 32,
} as const;

// API key configuration
const API_KEY_CONFIG = {
  // Length of raw API key in bytes (256 bits)
  rawKeyLength: 32,
  // Output format: hex string
  encoding: 'hex' as const,
} as const;

/**
 * Generates a new API key pair.
 * 
 * @returns Object containing:
 *   - plain: The raw API key to display once to the user
 *   - hash: The Argon2id hash suitable for storage
 * 
 * @throws Error if key generation fails
 */
export async function generateApiKey(): Promise<{ plain: string; hash: string }> {
  try {
    // Generate 256-bit random key
    const rawKey = randomBytes(API_KEY_CONFIG.rawKeyLength);
    const plain = rawKey.toString(API_KEY_CONFIG.encoding);

    // Hash using Argon2id for storage
    const hash = await argon2.hash(plain, {
      timeCost: API_KEY_ARGON2_CONFIG.timeCost,
      memoryCost: API_KEY_ARGON2_CONFIG.memoryCost,
      parallelism: API_KEY_ARGON2_CONFIG.parallelism,
      type: API_KEY_ARGON2_CONFIG.type,
      saltLength: API_KEY_ARGON2_CONFIG.saltLength,
      hashLength: API_KEY_ARGON2_CONFIG.hashLength,
    });

    return { plain, hash };
  } catch (error) {
    if (error instanceof Error) {
      console.error('API key generation failed:', error.message);
    }
    throw new Error('API key generation failed');
  }
}

/**
 * Verifies an API key against a stored hash.
 * 
 * Uses argon2.verify for constant-time comparison.
 * The stored hash is an Argon2id hash of the original API key.
 * 
 * @param plainKey - Raw API key from the client request
 * @param hash - Stored Argon2id hash
 * @returns Promise resolving to true if the key matches
 * @throws Error if verification fails
 */
export async function verifyApiKey(
  plainKey: string,
  hash: string
): Promise<boolean> {
  // Input validation
  if (!plainKey || !hash) {
    return false;
  }

  // Validate key format (should be hex, 64 characters for 256-bit)
  if (plainKey.length !== 64 || !/^[a-fA-F0-9]+$/.test(plainKey)) {
    return false;
  }

  try {
    // argon2.verify uses constant-time comparison internally
    const isValid = await argon2.verify(hash, plainKey);

    return isValid;
  } catch (error) {
    // Log without sensitive data
    if (error instanceof Error) {
      console.error('API key verification error:', error.message);
    }
    return false;
  }
}

/**
 * Checks if an API key hash needs rehashing (e.g., if cost parameters increased).
 * 
 * @param hash - Existing hash to check
 * @returns true if the hash should be upgraded
 */
export async function needsRehash(hash: string): Promise<boolean> {
  try {
    // argon2.needsRehash checks if current parameters match desired config
    const rehashNeeded = argon2.needsRehash(hash, {
      timeCost: API_KEY_ARGON2_CONFIG.timeCost,
      memoryCost: API_KEY_ARGON2_CONFIG.memoryCost,
      parallelism: API_KEY_ARGON2_CONFIG.parallelism,
      type: API_KEY_ARGON2_CONFIG.type,
    });

    return rehashNeeded;
  } catch {
    return true;
  }
}