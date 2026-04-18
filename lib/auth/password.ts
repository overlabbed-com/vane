/**
 * Password hashing using Argon2id.
 * 
 * Cost parameters are bounded to prevent DoS (E-02 mitigation):
 * - Time: 3 iterations (fixed, not user-controlled)
 * - Memory: 64MB (hard cap)
 * - Parallelism: 4 (bounded)
 * - Semaphore limiting concurrent operations (max 10)
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 1, Phase 2
 */

import * as argon2 from 'argon2';
import { withSemaphore } from './semaphore';

// Argon2id cost parameters (hardcoded to prevent user-controlled DoS)
// These values are NIST-recommended for secure password hashing
const ARGON2_CONFIG = {
  // Time cost: number of iterations
  timeCost: 3,
  // Memory cost: 64MB (65536 KB)
  memoryCost: 65536,
  // Parallelism: 4 threads
  parallelism: 4,
  // Argon2id variant
  type: argon2.argon2id,
  // Output length: 32 bytes (256 bits)
  saltLength: 16,
  hashLength: 32,
} as const;

/**
 * Hashes a password using Argon2id.
 * 
 * @param password - Plaintext password to hash
 * @returns Promise resolving to the hashed password (includes salt)
 * @throws Error if hashing fails or times out
 */
export async function hashPassword(password: string): Promise<string> {
  if (!password || password.length === 0) {
    throw new Error('Password cannot be empty');
  }

  // Enforce maximum password length to prevent memory exhaustion
  const MAX_PASSWORD_LENGTH = 1024;
  if (password.length > MAX_PASSWORD_LENGTH) {
    throw new Error('Password exceeds maximum length');
  }

  try {
    // Use semaphore to limit concurrent Argon2id operations
    const hash = await withSemaphore(async () => {
      return argon2.hash(password, {
        timeCost: ARGON2_CONFIG.timeCost,
        memoryCost: ARGON2_CONFIG.memoryCost,
        parallelism: ARGON2_CONFIG.parallelism,
        type: ARGON2_CONFIG.type,
        saltLength: ARGON2_CONFIG.saltLength,
        hashLength: ARGON2_CONFIG.hashLength,
      });
    });

    return hash;
  } catch (error) {
    if (error instanceof Error) {
      // Log without PII
      console.error('Password hashing failed:', error.message);
    }
    throw new Error('Password hashing failed');
  }
}

/**
 * Verifies a password against a stored hash.
 * Uses constant-time comparison to prevent timing attacks.
 * 
 * @param password - Plaintext password to verify
 * @param hash - Stored Argon2id hash
 * @returns Promise resolving to true if password matches
 * @throws Error if verification fails
 */
export async function verifyPassword(
  password: string,
  hash: string
): Promise<boolean> {
  if (!password || !hash) {
    return false;
  }

  try {
    // Use semaphore to limit concurrent Argon2id operations
    const isValid = await withSemaphore(async () => {
      // argon2.verify uses constant-time comparison internally
      return argon2.verify(hash, password);
    });

    return isValid;
  } catch (error) {
    // Log without PII - don't reveal whether user exists
    if (error instanceof Error) {
      console.error('Password verification error:', error.message);
    }
    return false;
  }
}

/**
 * Checks if a hash needs rehashing (e.g., if cost parameters increased).
 * Use this before authentication success to upgrade old hashes.
 * 
 * @param hash - Existing hash to check
 * @returns true if the hash should be upgraded
 */
export async function needsRehash(hash: string): Promise<boolean> {
  try {
    // argon2.needsRehash checks if current parameters match desired config
    const rehashNeeded = argon2.needsRehash(hash, {
      timeCost: ARGON2_CONFIG.timeCost,
      memoryCost: ARGON2_CONFIG.memoryCost,
      parallelism: ARGON2_CONFIG.parallelism,
      type: ARGON2_CONFIG.type,
    });

    return rehashNeeded;
  } catch {
    return true;
  }
}