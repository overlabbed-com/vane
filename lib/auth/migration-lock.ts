/**
 * Distributed lock for migration coordination.
 * 
 * Features:
 * - SETNX with TTL for atomic lock acquisition
 * - Owner verification for safe release
 * - Lock status check without acquisition
 * - Automatic expiry on holder crash
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 3
 * STRIDE: Mitigates E-01 (Race condition in Redis migration)
 */

import { getRedisClient } from './redis';

// Lock configuration
const LOCK_CONFIG = {
  // Key prefix for migration locks
  keyPrefix: 'vane:migration:',
  // Lock TTL: 30 seconds (prevents abandoned locks)
  ttlSeconds: 30,
  // Refresh interval: 10 seconds (keepalive)
  refreshIntervalMs: 10000,
} as const;

// Clock skew tolerance: use Redis TTL for expiry checks, not local clock
// This prevents false positives when system clocks differ between nodes
const CLOCK_SKEW_TOLERANCE_MS = 5000;

// Migration lock types
export interface MigrationLock {
  key: string;
  owner: string;
  acquiredAt: string;
  expiresAt: string;
}

// Active lock state
let activeLock: MigrationLock | null = null;
let refreshInterval: ReturnType<typeof setInterval> | null = null;
let refreshFailures: number = 0;

// Maximum consecutive refresh failures before abort
const MAX_REFRESH_FAILURES = 3;

/**
 * Acquires the migration lock.
 * Uses SETNX with TTL for atomic acquisition.
 * Only one instance can hold the lock at a time.
 * 
 * @param lockName - Name of the lock (e.g., 'session-store')
 * @returns true if lock acquired, false if already held
 */
export async function acquireMigrationLock(lockName: string): Promise<boolean> {
  const redis = getRedisClient();
  const hostname = process.env.HOSTNAME || 'unknown';
  const key = `${LOCK_CONFIG.keyPrefix}${lockName}`;

  try {
    // SET NX EX (atomic set-if-not-exists with expiry)
    const result = await redis.set(
      key,
      JSON.stringify({
        owner: hostname,
        acquiredAt: new Date().toISOString(),
      }),
      'EX',
      LOCK_CONFIG.ttlSeconds,
      'NX'
    );

    if (result === 'OK') {
      // Lock acquired
      activeLock = {
        key,
        owner: hostname,
        acquiredAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + LOCK_CONFIG.ttlSeconds * 1000).toISOString(),
      };
      refreshFailures = 0;

      // Start refresh interval
      startRefreshInterval(lockName);

      console.log(`Migration lock acquired: ${key} by ${hostname}`);
      return true;
    }

    // Lock already held
    console.log(`Migration lock already held: ${key}`);
    return false;
  } catch (error) {
    console.error('Failed to acquire migration lock:', error instanceof Error ? error.message : 'Unknown error');
    return false;
  }
}

/**
 * Releases the migration lock.
 * Only releases if we own the lock.
 * Uses Lua script for atomic check-and-delete.
 */
export async function releaseMigrationLock(): Promise<boolean> {
  if (!activeLock) {
    return false;
  }

  const redis = getRedisClient();
  const hostname = process.env.HOSTNAME || 'unknown';

  try {
    // Lua script for atomic check-and-delete with error handling
    // Uses single EXPIRE with owner check - not separate GET then EXPIRE (TOCTOU race)
    const script = `
      local current = redis.call("get", KEYS[1])
      if current then
        local ok, data = pcall(cjson.decode, current)
        if not ok then
          redis.call("del", KEYS[1])
          return -1
        end
        if data.owner == ARGV[1] then
          return redis.call("del", KEYS[1])
        end
      end
      return 0
    `;

    const result = await redis.eval(script, 1, activeLock.key, hostname);

    // Stop refresh interval
    stopRefreshInterval();

    if (result === 1) {
      console.log(`Migration lock released: ${activeLock.key}`);
      activeLock = null;
      return true;
    }

    console.warn(`Migration lock release failed (not owner): ${activeLock.key}`);
    return false;
  } catch (error) {
    console.error('Failed to release migration lock:', error instanceof Error ? error.message : 'Unknown error');
    return false;
  }
}

/**
 * Checks if a migration lock is currently held.
 * Does not attempt to acquire the lock.
 * Uses Redis TTL for validity check to handle clock skew.
 * 
 * @param lockName - Name of the lock
 * @returns Lock info if held, null otherwise
 */
export async function isMigrationLockHeld(lockName: string): Promise<MigrationLock | null> {
  const redis = getRedisClient();
  const key = `${LOCK_CONFIG.keyPrefix}${lockName}`;

  try {
    // Use Redis TTL for validity check - prevents clock skew issues
    const script = `
      local ttl = redis.call("ttl", KEYS[1])
      if ttl < 0 then
        return nil  -- Key expired
      end
      if ttl <= ${CLOCK_SKEW_TOLERANCE_MS / 1000} then
        return nil  -- About to expire
      end
      return redis.call("get", KEYS[1])
    `;

    const data = await redis.eval(script, 1, key);

    if (!data) {
      return null;
    }

    const parsed = JSON.parse(data as string);
    return {
      key,
      owner: parsed.owner,
      acquiredAt: parsed.acquiredAt,
      expiresAt: parsed.expiresAt || 'unknown',
    };
  } catch {
    return null;
  }
}

/**
 * Extends the TTL of the active lock.
 * Called periodically to prevent lock expiry during long operations.
 */
async function refreshLock(): Promise<void> {
  if (!activeLock) {
    return;
  }

  const redis = getRedisClient();
  const hostname = process.env.HOSTNAME || 'unknown';

  try {
    // Lua script for atomic check-and-extend with error handling
    // Uses single EXPIRE with owner check - not separate GET then EXPIRE (TOCTOU race)
    const script = `
      local current = redis.call("get", KEYS[1])
      if current then
        local ok, data = pcall(cjson.decode, current)
        if not ok then
          redis.call("del", KEYS[1])
          return -1
        end
        if data.owner == ARGV[1] then
          return redis.call("expire", KEYS[1], ARGV[2])
        end
      end
      return 0
    `;

    const result = await redis.eval(script, 1, activeLock.key, hostname, LOCK_CONFIG.ttlSeconds);

    if (result === 1) {
      activeLock.expiresAt = new Date(Date.now() + LOCK_CONFIG.ttlSeconds * 1000).toISOString();
      refreshFailures = 0;
    } else {
      // Lock no longer ours or error
      refreshFailures++;
      console.warn(`Migration lock refresh failed (attempt ${refreshFailures}/${MAX_REFRESH_FAILURES})`);
      
      if (refreshFailures >= MAX_REFRESH_FAILURES) {
        console.error('Migration lock refresh failed: too many consecutive failures, aborting');
        stopRefreshInterval();
        activeLock = null;
        refreshFailures = 0;
        // Abort migration - don't continue with potentially expired lock
        await releaseMigrationLock();
        throw new Error('Migration lock refresh failed, aborting');
      }
    }
  } catch (error) {
    console.error('Migration lock refresh failed:', error instanceof Error ? error.message : 'Unknown error');
    refreshFailures++;
    
    if (refreshFailures >= MAX_REFRESH_FAILURES) {
      stopRefreshInterval();
      activeLock = null;
      refreshFailures = 0;
      // Abort migration - don't continue with potentially expired lock
      await releaseMigrationLock();
      throw new Error('Migration lock refresh failed, aborting');
    }
  }
}

let onRefreshError: ((error: Error) => void) | null = null;

/**
 * Starts the lock refresh interval.
 * @param lockName - Name of the lock (unused, kept for API compatibility)
 * @param errorCallback - Called when refreshLock throws
 */
function startRefreshInterval(lockName: string, errorCallback?: (error: Error) => void): void {
  stopRefreshInterval(); // Clear any existing
  onRefreshError = errorCallback || null;

  refreshInterval = setInterval(async () => {
    try {
      await refreshLock();
    } catch (error) {
      stopRefreshInterval();
      if (onRefreshError && error instanceof Error) {
        onRefreshError(error);
      }
    }
  }, LOCK_CONFIG.refreshIntervalMs);
}

/**
 * Stops the lock refresh interval.
 */
function stopRefreshInterval(): void {
  if (refreshInterval) {
    clearInterval(refreshInterval);
    refreshInterval = null;
  }
}

/**
 * Gets the active lock (if any).
 */
export function getActiveLock(): MigrationLock | null {
  return activeLock;
}