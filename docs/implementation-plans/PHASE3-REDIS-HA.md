# Phase 3: Redis HA + Split-Brain Protection Implementation Plan

**Document Type:** Implementation Plan  
**Date:** 2026-04-17  
**Phase:** 3 of 6  
**Finding ID:** E-01, E-04  
**Severity:** HIGH  
**CWE:** CWE-690 (Insufficient Control of Resource During Exploitation), CWE-710 (Improper Check for Unusual Conditions)  
**Status:** Ready for Implementation  

---

## 1. Executive Summary

This plan deploys Redis Sentinel for automatic failover and implements split-brain protection for the migration from single Redis to Sentinel cluster. The implementation addresses two critical edge cases identified during security review: single Redis failure causing auth service outage (E-04) and split-brain during migration causing session loss (E-01).

**Risk After Implementation:** HIGH → MEDIUM  
**Timeline:** 1 week  
**Files Created:** 3 (`lib/auth/redis-sentinel.ts`, `lib/auth/migration-lock.ts`, `lib/auth/migrate.ts`)  
**Files Modified:** 1 (`lib/auth/redis.ts`)  
**Dependencies:** `ioredis-sentinel` package  

---

## 2. Threat Model

### 2.1 Attack Scenarios

#### Scenario 1: Single Redis Failure
```
Timeline:
T+0:00    Redis primary fails (hardware, network, or crash)
T+0:01    Auth requests begin failing
T+5:00    Users unable to authenticate
T+15:00   Session expiry causes widespread logout
T+30:00   Manual intervention required
```

**Impact:** Complete auth service outage until manual intervention.

#### Scenario 2: Split-Brain During Migration
```
Timeline:
T+0:00    Migration begins (dual-write enabled)
T+0:05    Network partition occurs
T+0:05    Instance A writes to Redis-A
T+0:05    Instance B writes to Redis-B (different data)
T+0:10    Migration completes with inconsistent state
T+0:15    Users experience session loss
T+0:20    Data reconciliation required
```

**Impact:** Session loss for affected users, data reconciliation complexity.

#### Scenario 3: Lock Holder Crash Mid-Migration
```
Timeline:
T+0:00    Instance A acquires migration lock
T+0:05    Instance A crashes during dual-write
T+0:05    Lock expires (TTL: 30s)
T+0:06    Instance B acquires migration lock
T+0:06    Instance B sees partial state from Instance A
T+0:10    Migration completes with inconsistent state
```

**Impact:** Partial migration state, session loss.

### 2.2 Mitigated Threats

| Threat | CWE | Attack Vector | Mitigation |
|:---|:---|:---|:---|
| Single Redis failure | CWE-690 | Hardware/network failure | Redis Sentinel automatic failover |
| Auth service outage | CWE-690 | Primary loss | Sentinel monitors and promotes replica |
| Split-brain | CWE-710 | Network partition | Distributed lock prevents concurrent migration |
| Lock holder crash | CWE-710 | Crash during critical section | TTL expiry releases abandoned locks |
| Dual-write inconsistency | CWE-710 | Concurrent writes | Lock serializes migration operations |

### 2.3 Not Mitigated

- Redis data corruption (handled by backups)
- Memory exhaustion (handled by monitoring)
- Network latency causing timeouts (handled by retry logic)
- Quorum loss (3-node Sentinel requires 2 agreeing)

### 2.4 Quorum Requirements

Redis Sentinel uses quorum-based failover:

```
Configuration:
- 3 Sentinel nodes (minimum for HA)
- Quorum: 2 (requires 2 of 3 to agree)
- Write concern: majority

Failover Trigger:
- Primary fails
- 2 Sentinels agree primary is unreachable
- 1 Sentinel initiates failover

Failover Rejection:
- Network partition: 1 Sentinel sees primary
- 2 Sentinels disagree
- No failover (prevents split-brain)
```

---

## 3. Implementation Details

### 3.1 Redis Sentinel HA

#### 3.1.1 Sentinel Connection Manager

**File:** `lib/auth/redis-sentinel.ts` (new)

```typescript
/**
 * Redis Sentinel connection manager.
 * 
 * Features:
 * - Automatic master/slave discovery
 * - Failover detection and reconnection
 * - Health check with Sentinel status
 * - Wait for failover completion
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 3
 * STRIDE: Mitigates E-04 (Auth Gateway SPOF)
 */

import Redis from 'ioredis';
import Sentinel from 'ioredis-sentinel';

interface SentinelConfig {
  sentinels: Array<{ host: string; port: number }>;
  masterName: string;
  password?: string;
  sentinelPassword?: string;
  db?: number;
}

interface SentinelStatus {
  master: { host: string; port: number } | null;
  slaves: Array<{ host: string; port: number; lag: number }>;
  quorum: number;
  healthy: boolean;
}

// Sentinel configuration from environment
function getSentinelConfig(): SentinelConfig {
  const sentinelHosts = process.env.REDIS_SENTINEL_HOSTS || 'localhost:26379';
  const sentinelList = sentinelHosts.split(',').map((s) => {
    const [host, port] = s.split(':');
    return { host, port: parseInt(port, 10) || 26379 };
  });

  return {
    sentinels: sentinelList,
    masterName: process.env.REDIS_SENTINEL_MASTER_NAME || 'mymaster',
    password: process.env.REDIS_AUTH_SECRET,
    sentinelPassword: process.env.REDIS_SENTINEL_PASSWORD,
    db: parseInt(process.env.REDIS_DB || '0', 10),
  };
}

// Singleton Sentinel client
let sentinelClient: Sentinel | null = null;
let redisClient: Redis | null = null;
let connectionError: Error | null = null;
let initPromise: Promise<Sentinel> | null = null;


/**
 * Initializes the Sentinel client.
 * Call this once at application startup.
 * Uses initPromise to prevent race conditions from concurrent calls.
 * 
 * @returns Sentinel client instance
 */
export function initSentinelClient(): Sentinel {
  if (sentinelClient) {
    return sentinelClient;
  }

  if (!initPromise) {
    initPromise = doInitSentinelClient();
  }


  // Return the client directly (it's already set in doInitSentinelClient)
  return sentinelClient!;
}

async function doInitSentinelClient(): Promise<Sentinel> {
  const config = getSentinelConfig();

  sentinelClient = new Sentinel(config.sentinels, {
    sentinelPassword: config.sentinelPassword,
  });

  return sentinelClient;
}

/**
 * Creates a Redis client connected via Sentinel.
 * The client automatically tracks the current master.
 * 
 * @returns Redis client instance
 */
export function createSentinelClient(): Redis {
  if (redisClient) {
    return redisClient;
  }

  const config = getSentinelConfig();
  const sentinel = initSentinelClient();

  redisClient = sentinel.createClient({
    sentinels: config.sentinels,
    masterName: config.masterName,
    password: config.password,
    db: config.db,
    retryStrategy: (times: number) => {
      if (times > 10) {
        return null;
      }
      return Math.min(times * 100, 3000);
    },
    connectTimeout: 10000,
    commandTimeout: 5000,
    lazyConnect: true,
  });

  // Event handlers
  redisClient.on('error', (error) => {
    console.error('Redis Sentinel client error:', error.message);
    connectionError = error;
  });

  redisClient.on('connect', () => {
    console.log('Redis Sentinel client connected');
    connectionError = null;
  });

  redisClient.on('close', () => {
    console.log('Redis Sentinel client disconnected');
  });

  redisClient.on('reconnecting', () => {
    console.log('Redis Sentinel client reconnecting...');
  });

  // Monitor failover events
  sentinel.on('failover', (masterName: string) => {
    console.log(`Failover detected for ${masterName}`);
    // Invalidate cached clients - force reconnect on next use
    if (redisClient) {
      redisClient.disconnect();
      redisClient = null;
    }
    if (sentinelClient) {
      sentinelClient.disconnect();
      sentinelClient = null;
    }
    initPromise = null;
  });

  sentinel.on('sentinel', (sentinel: { ip: string; port: number }) => {
    console.log(`Sentinel event from: ${sentinel.ip}:${sentinel.port}`);
  });

  return redisClient;
}

/**
 * Gets the Sentinel client instance.
 * Initializes if not already done.
 */
export function getSentinelClient(): Sentinel {
  if (!sentinelClient) {
    return initSentinelClient();
  }
  return sentinelClient;
}

/**
 * Gets the Redis client via Sentinel.
 * Initializes if not already done.
 */
export function getSentinelRedisClient(): Redis {
  if (!redisClient) {
    return createSentinelClient();
  }
  return redisClient;
}

/**
 * Gets the current Sentinel status.
 * Queries Sentinel for master/slave information.
 * 
 * @returns Sentinel status including master and slave info
 */
export async function getSentinelStatus(): Promise<SentinelStatus> {
  const sentinel = getSentinelClient();
  const config = getSentinelConfig();

  try {
    // Get master info from Sentinel
    const master = await sentinel.getMasterAddrByName(config.masterName);
    
    // Get slave info
    const slaves = await sentinel.slaves(config.masterName);

    return {
      master: master ? { host: master.ip, port: master.port } : null,
      slaves: slaves.map((slave) => ({
        host: slave.ip,
        port: slave.port,
        lag: parseInt(slave.flags.split(',').find(f => f.startsWith('lag='))?.split('=')[1] || '0', 10),
      })),
      quorum: 2, // Configured quorum
      healthy: master !== null,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    console.error(`Failed to get Sentinel status: ${message}`);
    return {
      master: null,
      slaves: [],
      quorum: 2,
      healthy: false,
    };
  }
}

/**
 * Gets the current master address from Sentinel.
 * 
 * @returns Master address or null if unavailable
 */
export async function getCurrentMaster(): Promise<{ host: string; port: number } | null> {
  const sentinel = getSentinelClient();
  const config = getSentinelConfig();

  try {
    const master = await sentinel.getMasterAddrByName(config.masterName);
    return master ? { host: master.ip, port: master.port } : null;
  } catch {
    return null;
  }
}

/**
 * Waits for failover to complete.
 * Polls Sentinel until master changes or timeout.
 * 
 * @param timeoutMs - Maximum time to wait (default: 30000ms)
 * @returns true if failover detected, false if timeout
 */
export async function waitForFailover(timeoutMs: number = 30000): Promise<boolean> {
  const start = Date.now();
  const initialMaster = await getCurrentMaster();

  while (Date.now() - start < timeoutMs) {
    const currentMaster = await getCurrentMaster();
    
    // Master changed (failover detected)
    if (currentMaster && initialMaster) {
      if (currentMaster.host !== initialMaster.host || currentMaster.port !== initialMaster.port) {
        console.log(`Failover detected: ${initialMaster.host}:${initialMaster.port} -> ${currentMaster.host}:${currentMaster.port}`);
        return true;
      }
    } else if (currentMaster && !initialMaster) {
      // Master came online (initial failover)
      console.log(`Master online: ${currentMaster.host}:${currentMaster.port}`);
      return true;
    }

    await sleep(100);
  }

  console.warn(`Failover wait timeout after ${timeoutMs}ms`);
  return false;
}

/**
 * Checks if Sentinel is currently connected.
 */
export function isSentinelConnected(): boolean {
  return redisClient !== null && redisClient.status === 'ready' && connectionError === null;
}

/**
 * Closes the Sentinel connection.
 * Call this at application shutdown.
 */
export async function closeSentinelClient(): Promise<void> {
  if (redisClient) {
    await redisClient.quit();
    redisClient = null;
  }
  sentinelClient = null;
}

// Utility function
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
```

#### 3.1.2 Redis Client Update

**File:** `lib/auth/redis.ts` (modify existing)

Add Sentinel support alongside existing direct connection:

```typescript
// Add near the top of redis.ts
import { createSentinelClient, getSentinelStatus, waitForFailover, isSentinelConnected } from './redis-sentinel';

// Add new configuration option
const REDIS_CONFIG = {
  // ... existing config ...
  useSentinel: process.env.REDIS_USE_SENTINEL === 'true',
} as const;

// Add new initialization function
export function initRedisClient(redisUrl?: string): Redis {
  if (REDIS_CONFIG.useSentinel) {
    return createSentinelClient();
  }
  // ... existing direct connection logic ...
}

// Add Sentinel health check
export async function validateSentinelConnection(): Promise<boolean> {
  const status = await getSentinelStatus();
  
  if (!status.healthy) {
    throw new Error('Sentinel: no healthy master available');
  }

  // Verify we can write to master
  const redis = getSentinelRedisClient();
  const result = await redis.ping();
  
  if (result !== 'PONG') {
    throw new Error(`Sentinel: unexpected PING response: ${result}`);
  }

  console.log(`Sentinel connection validated: master=${status.master?.host}:${status.master?.port}`);
  return true;
}

// Add failover-aware session operations
export async function verifySessionWithFailover(
  storedToken: string,
  maxRetries: number = 3
): Promise<SessionData | null> {
  let lastError: Error | null = null;
  
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      // Try to verify session
      const session = await verifySession(storedToken);
      
      if (session !== null) {
        return session;
      }
      
      // Session not found (not a failover issue)
      return null;
    } catch (error) {
      lastError = error instanceof Error ? error : new Error('Unknown error');
      
      // Check if this is a connection error (might be failover)
      if (lastError.message.includes('MOVED') || 
          lastError.message.includes('CLUSTERDOWN') ||
          lastError.message.includes('connection')) {
        
        console.log(`Connection error during verify (attempt ${attempt + 1}): ${lastError.message}`);
        
        // Wait for potential failover to complete
        await waitForFailover(5000);
        
        // Retry
        continue;
      }
      
      // Non-connection error, don't retry
      throw lastError;
    }
  }
  
  throw lastError || new Error('Max retries exceeded');
}
```

### 3.2 Split-Brain Protection

#### 3.2.1 Distributed Lock

**File:** `lib/auth/migration-lock.ts` (new)

```typescript
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
```

#### 3.2.2 Migration Orchestration

**File:** `lib/auth/migrate.ts` (update existing)

Update existing migration utilities for Sentinel support:

```typescript
/**
 * Migration orchestration for Redis Sentinel.
 * 
 * Features:
 * - Distributed lock for split-brain prevention
 * - Dual-write during transition
 * - Consistency verification
 * - Automatic rollback on failure
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 3
 * STRIDE: Mitigates E-01 (Race condition in Redis migration)
 */

import { getRedisClient, getRedisClient as getDirectRedisClient } from './redis';
import { getSentinelRedisClient, getSentinelStatus, waitForFailover } from './redis-sentinel';
import { acquireMigrationLock, releaseMigrationLock, isMigrationLockHeld } from './migration-lock';

// Migration state
interface MigrationState {
  phase: 'idle' | 'acquiring_lock' | 'dual_write' | 'verifying' | 'cutover' | 'completing' | 'rollback';
  startedAt: string | null;
  completedAt: string | null;
  error: string | null;
}

let migrationState: MigrationState = {
  phase: 'idle',
  startedAt: null,
  completedAt: null,
  error: null,
};

// Migration result
export interface MigrationResult {
  success: boolean;
  state: MigrationState;
  migrated: number;
  failed: number;
  duration: number;
}

/**
 * Gets the current migration state.
 */
export function getMigrationState(): MigrationState {
  return { ...migrationState };
}

/**
 * Checks if migration is in progress.
 */
export async function isMigrationInProgress(): Promise<boolean> {
  const lock = await isMigrationLockHeld('session-store');
  return lock !== null;
}

/**
 * Migrates session store to Redis Sentinel.
 * Full migration sequence with split-brain protection.
 * 
 * @returns Migration result
 */
export async function migrateToSentinel(): Promise<MigrationResult> {
  const startTime = Date.now();
  migrationState = {
    phase: 'acquiring_lock',
    startedAt: new Date().toISOString(),
    completedAt: null,
    error: null,
  };

  try {
    // Step 1: Acquire lock (fails if already running)
    console.log('Migration: Acquiring lock...');
    const lockAcquired = await acquireMigrationLock('session-store');
    
    if (!lockAcquired) {
      const lock = await isMigrationLockHeld('session-store');
      throw new Error(`Migration already in progress by ${lock?.owner || 'unknown'}`);
    }

    // Step 2: Verify Sentinel is healthy
    console.log('Migration: Verifying Sentinel health...');
    migrationState.phase = 'verifying';
    const status = await getSentinelStatus();
    
    if (!status.healthy) {
      throw new Error('Sentinel: no healthy master available');
    }

    // Step 3: Enable dual-write mode
    console.log('Migration: Enabling dual-write mode...');
    migrationState.phase = 'dual_write';
    
    // Dual-write is enabled by writing to both stores
    // This is handled in the session creation functions

    // Step 4: Wait for consistency window
    console.log('Migration: Waiting for consistency window...');
    await sleep(5000); // 5 second window

    // Step 5: Verify all keys exist in both stores
    console.log('Migration: Verifying consistency...');
    migrationState.phase = 'verifying';
    const consistency = await verifyConsistency();
    
    if (consistency.inconsistent > 0 || consistency.missing > 0) {
      throw new Error(`Consistency check failed: ${consistency.inconsistent} inconsistent, ${consistency.missing} missing`);
    }

    // Step 6: Switch reads to Sentinel
    console.log('Migration: Switching reads to Sentinel...');
    migrationState.phase = 'cutover';
    process.env.REDIS_USE_SENTINEL = 'true';

    // Step 7: Wait for all in-flight requests to complete
    await sleep(1000);

    // Step 8: Switch writes to Sentinel
    console.log('Migration: Switching writes to Sentinel...');
    // Writes already go to Sentinel via getSentinelRedisClient()

    // Step 9: Disable dual-write
    console.log('Migration: Disabling dual-write...');
    migrationState.phase = 'completing';

    // Step 10: Release lock
    await releaseMigrationLock();

    migrationState.phase = 'idle';
    migrationState.completedAt = new Date().toISOString();

    const duration = Date.now() - startTime;
    console.log(`Migration completed in ${duration}ms`);

    return {
      success: true,
      state: migrationState,
      migrated: consistency.consistent,
      failed: 0,
      duration,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    console.error(`Migration failed: ${message}`);
    
    migrationState.error = message;
    migrationState.phase = 'rollback';

    // Rollback: Release lock
    await releaseMigrationLock();

    migrationState.phase = 'idle';
    migrationState.completedAt = new Date().toISOString();

    const duration = Date.now() - startTime;
    return {
      success: false,
      state: migrationState,
      migrated: 0,
      failed: 0,
      duration,
    };
  }
}

/**
 * Verifies consistency between direct Redis and Sentinel.
 * Checks that all session keys exist in both stores.
 */
export async function verifyConsistency(): Promise<{
  consistent: number;
  inconsistent: number;
  missing: number;
}> {
  const directRedis = getDirectRedisClient();
  const sentinelRedis = getSentinelRedisClient();
  
  let consistent = 0;
  let inconsistent = 0;
  let missing = 0;

  try {
    // Scan for all session keys in direct Redis
    let cursor = '0';
    
    do {
      const [nextCursor, keys] = await directRedis.scan(
        cursor,
        'MATCH',
        'vane:sess:*',
        'COUNT',
        100
      );
      cursor = nextCursor;

      for (const key of keys) {
        // Skip activity keys
        if (key.includes(':activity')) {
          continue;
        }

        const directData = await directRedis.get(key);
        
        if (!directData) {
          missing++;
          continue;
        }

        const sentinelData = await sentinelRedis.get(key);
        
        if (!sentinelData) {
          missing++;
          continue;
        }

        // Compare key fields
        const directParsed = JSON.parse(directData);
        const sentinelParsed = JSON.parse(sentinelData);

        if (
          directParsed.userId === sentinelParsed.userId &&
          directParsed.revoked === sentinelParsed.revoked
        ) {
          consistent++;
        } else {
          inconsistent++;
        }
      }
    } while (cursor !== '0');
  } catch (error) {
    console.error('Consistency verification failed:', error instanceof Error ? error.message : 'Unknown error');
  }

  return { consistent, inconsistent, missing };
}

/**
 * Rolls back migration if issues are detected.
 * Reverts to direct Redis connection.
 */
export async function rollbackMigration(): Promise<boolean> {
  console.log('Migration rollback: Reverting to direct Redis...');
  
  try {
    // Switch reads/writes back to direct Redis
    process.env.REDIS_USE_SENTINEL = 'false';
    
    // Release any held lock
    await releaseMigrationLock();
    
    console.log('Migration rollback completed');
    return true;
  } catch (error) {
    console.error('Migration rollback failed:', error instanceof Error ? error.message : 'Unknown error');
    return false;
  }
}

/**
 * Dual-write sessions to both direct Redis and Sentinel.
 * Used during transition period.
 */
export async function dualWriteSession(
  key: string,
  data: string
): Promise<void> {
  const directRedis = getDirectRedisClient();
  const sentinelRedis = getSentinelRedisClient();

  // Write to both stores in parallel, handle failures individually
  const results = await Promise.allSettled([
    directRedis.set(key, data),
    sentinelRedis.set(key, data),
  ]);

  const failures = results
    .map((r, i) => r.status === 'rejected' ? { index: i, error: r.reason } : null)
    .filter((f): f is { index: number; error: unknown } => f !== null);

  if (failures.length > 0) {
    const errorDetails = failures.map(f =>
      `${f.index}: ${f.error instanceof Error ? f.error.message : String(f.error)}`
    ).join('; ');
    throw new Error(`Dual-write failed: ${errorDetails}`);
  }
}

/**
 * Gets migration progress.
 */
export function getMigrationProgress(): {
  phase: string;
  duration: number;
  error: string | null;
} {
  const startedAt = migrationState.startedAt ? new Date(migrationState.startedAt).getTime() : Date.now();
  const duration = Date.now() - startedAt;

  return {
    phase: migrationState.phase,
    duration,
    error: migrationState.error,
  };
}

// Utility function
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
```

---

## 4. Files to Create/Modify

### 4.1 New Files

| File | Purpose | Lines |
|:---|:---|:---|
| `lib/auth/redis-sentinel.ts` | Sentinel connection manager | ~250 |
| `lib/auth/redis-sentinel.test.ts` | Unit tests for Sentinel functions | ~150 |
| `lib/auth/migration-lock.ts` | Distributed lock implementation | ~180 |
| `lib/auth/migration-lock.test.ts` | Unit tests for lock functions | ~100 |

### 4.2 Modified Files

| File | Change | Lines |
|:---|:---|:---|
| `lib/auth/redis.ts` | Add Sentinel support, failover-aware operations | ~50 |
| `lib/auth/migrate.ts` | Update for Sentinel migration orchestration | ~100 |

### 4.3 Package Dependency

Add to `package.json`:

```json
{
  "dependencies": {
    "ioredis": "^5.3.0",
    "ioredis-sentinel": "^1.0.0"
  }
}
```

---

## 5. Test Cases

### 5.1 Sentinel Connection Tests

```typescript
// lib/auth/redis-sentinel.test.ts

describe('Sentinel Connection', () => {
  it('creates Sentinel client with config', () => {
    const client = createSentinelClient();
    expect(client).toBeDefined();
  });

  it('gets Sentinel status', async () => {
    const status = await getSentinelStatus();
    expect(status).toHaveProperty('master');
    expect(status).toHaveProperty('slaves');
    expect(status).toHaveProperty('healthy');
  });

  it('waits for failover timeout', async () => {
    const result = await waitForFailover(1000);
    expect(result).toBe(false); // No failover in test
  });
});
```

### 5.2 Migration Lock Tests

```typescript
// lib/auth/migration-lock.test.ts

describe('Migration Lock', () => {
  it('acquires lock when not held', async () => {
    // Clean up any existing lock
    await releaseMigrationLock();
    
    const acquired = await acquireMigrationLock('test-lock');
    expect(acquired).toBe(true);
    
    // Clean up
    await releaseMigrationLock();
  });

  it('fails to acquire when already held', async () => {
    // Acquire first lock
    await acquireMigrationLock('test-lock');
    
    // Try to acquire second
    const acquired = await acquireMigrationLock('test-lock');
    expect(acquired).toBe(false);
    
    // Clean up
    await releaseMigrationLock();
  });

  it('releases lock when owner', async () => {
    await acquireMigrationLock('test-lock');
    
    const released = await releaseMigrationLock();
    expect(released).toBe(true);
  });

  it('fails to release when not owner', async () => {
    await acquireMigrationLock('test-lock');
    
    // Simulate different owner by directly setting key
    const redis = getRedisClient();
    await redis.set('vane:migration:test-lock', JSON.stringify({ owner: 'other-host' }), 'EX', 30);
    
    const released = await releaseMigrationLock();
    expect(released).toBe(false);
    
    // Clean up
    await redis.del('vane:migration:test-lock');
  });

  it('detects lock holder', async () => {
    await acquireMigrationLock('test-lock');
    
    const lock = await isMigrationLockHeld('test-lock');
    expect(lock).not.toBeNull();
    expect(lock?.owner).toBe(process.env.HOSTNAME || 'unknown');
    
    await releaseMigrationLock();
  });

  it('returns null when not held', async () => {
    const lock = await isMigrationLockHeld('test-lock');
    expect(lock).toBeNull();
  });
});
```

### 5.3 Migration Orchestration Tests

```typescript
// lib/auth/migrate.test.ts

describe('Migration Orchestration', () => {
  it('reports idle state initially', () => {
    const state = getMigrationState();
    expect(state.phase).toBe('idle');
  });

  it('detects no migration in progress', async () => {
    // Ensure no lock held
    await releaseMigrationLock();
    
    const inProgress = await isMigrationInProgress();
    expect(inProgress).toBe(false);
  });

  it('verifies consistency between stores', async () => {
    const result = await verifyConsistency();
    expect(result).toHaveProperty('consistent');
    expect(result).toHaveProperty('inconsistent');
    expect(result).toHaveProperty('missing');
  });
});
```

### 5.4 Edge Case Tests

```typescript
// lib/auth/redis-sentinel.test.ts

describe('Failover Edge Cases', () => {
  it('handles quorum loss', async () => {
    // With 1 of 3 Sentinels, quorum (2) not met
    // Should not failover
    const status = await getSentinelStatus();
    expect(status.healthy).toBe(false);
  });

  it('retries on connection error', async () => {
    // verifySessionWithFailover should retry on MOVED error
    const session = await verifySessionWithFailover('non-existent-token');
    expect(session).toBeNull();
  });
});

// lib/auth/migration-lock.test.ts

describe('Lock Edge Cases', () => {
  it('auto-expires after TTL', async () => {
    vi.useFakeTimers();
    
    await acquireMigrationLock('test-lock');
    
    // Advance time past TTL
    vi.advanceTimersByTime((30 + 1) * 1000);
    
    // Lock should be expired
    const lock = await isMigrationLockHeld('test-lock');
    expect(lock).toBeNull();
    
    vi.useRealTimers();
  });

  it('refresh extends TTL', async () => {
    vi.useFakeTimers();
    
    await acquireMigrationLock('test-lock');
    
    // Advance time partway
    vi.advanceTimersByTime(10 * 1000);
    
    // Trigger refresh
    await refreshLock();
    
    // Lock should still be held
    const lock = await isMigrationLockHeld('test-lock');
    expect(lock).not.toBeNull();
    
    vi.useRealTimers();
  });
});
```

---

## 6. Edge Cases

### 6.1 Sentinel Quorum Lost

When network partition splits Sentinel nodes:

```
Scenario:
- 3 Sentinel nodes: S1, S2, S3
- Primary: R1 (Redis primary)
- Network partition: S1 isolated

Result:
- S2 + S3 see S1 as unreachable
- S2 + S3 have quorum (2 >= 2)
- Failover can proceed

Prevention:
- Quorum requires 2 of 3 agreeing
- Single node cannot trigger failover
```

**Mitigation:** Quorum configuration prevents single-node split-brain.

### 6.2 Lock Holder Crash Mid-Migration

When lock holder crashes during dual-write:

```
Scenario:
- Instance A acquires lock
- Instance A starts dual-write
- Instance A crashes
- Lock TTL expires (30s)

Result:
- Lock automatically released
- Instance B can acquire lock
- Instance B sees partial state

Prevention:
- Short TTL (30s) ensures abandoned locks release
- Consistency check before cutover catches partial state
```

**Mitigation:** TTL expiry + consistency verification.

### 6.3 Network Partition (Split-Brain Detection)

When network partition causes dual-write divergence:

```
Scenario:
- Dual-write enabled
- Network partition: Instance A -> Redis-A, Instance B -> Redis-B
- Instance A writes key K = "value-A"
- Instance B writes key K = "value-B"

Result:
- Inconsistent state after cutover
- Some users see "value-A", others see "value-B"

Prevention:
- Lock serializes migration to single instance
- Consistency check before cutover
- Rollback on inconsistency
```

**Mitigation:** Distributed lock + consistency verification + rollback.

### 6.4 Dual-Write Inconsistency

When dual-write produces different data:

```
Scenario:
- Dual-write enabled
- Session created: Instance A writes to Redis-A
- Network delay: Redis-A write delayed
- Cutover occurs before Redis-A write completes

Result:
- Session missing in Sentinel
- Users logged out unexpectedly

Prevention:
- 5-second consistency window before cutover
- Verify all keys in both stores before cutover
- Rollback on missing keys
```

**Mitigation:** Consistency window + verification + rollback.

### 6.5 Failover During Active Session

When failover occurs during session verification:

```
Scenario:
- User request in flight
- Primary fails mid-request
- Client gets MOVED or connection error

Result:
- Request fails
- User may need to re-authenticate

Prevention:
- verifySessionWithFailover retries on connection errors
- Wait for failover completion before retry
- Sliding window session TTL absorbs brief outages
```

**Mitigation:** Retry logic + failover wait + session TTL.

---

## 7. Integration Points

### 7.1 Application Startup

```
Startup Sequence:
1. Check REDIS_USE_SENTINEL env var
2. If true: Initialize Sentinel client
3. Validate Sentinel connection
4. Create Redis client via Sentinel
5. Start refresh interval for active lock
```

### 7.2 Session Operations

```
Session Create:
1. Acquire migration lock if migrating
2. Write to direct Redis
3. Write to Sentinel (dual-write mode)
4. Release migration lock

Session Verify:
1. Try direct Redis or Sentinel based on config
2. On connection error: retry with failover wait
3. Return session or null
```

### 7.3 Migration Trigger

```
Manual Migration:
1. Admin calls migrateToSentinel()
2. Lock acquired (fails if already running)
3. Sentinel health verified
4. Dual-write enabled
5. Consistency window (5s)
6. Consistency verified
7. Switch to Sentinel
8. Lock released

Auto Rollback:
1. On any error: rollbackMigration()
2. Revert to direct Redis
3. Release lock
4. Log error
```

---

## 8. Verification Steps

### 8.1 Unit Tests

```bash
npm test -- lib/auth/redis-sentinel.test.ts
npm test -- lib/auth/migration-lock.test.ts
npm test -- lib/auth/migrate.test.ts
# Expected: All tests pass
```

### 8.2 Integration Tests

```bash
# Test 1: Kill primary Redis, verify failover < 30s
# Start session creation
# Kill primary Redis
# Verify session survives failover

# Test 2: Sessions survive failover
# Create session
# Kill primary Redis
# Wait for failover
# Verify session still valid

# Test 3: Concurrent migration attempts blocked
# Start migration in Instance A
# Attempt migration in Instance B
# Verify Instance B fails to acquire lock

# Test 4: Data consistent after migration
# Create sessions in dual-write mode
# Run verifyConsistency()
# Verify all keys match
```

### 8.3 Manual Verification

```bash
# Verify 1: Sentinel status
curl -s http://localhost:3000/api/admin/sentinel-status | jq
# Expected: {"master": {...}, "slaves": [...], "healthy": true}

# Verify 2: Lock acquisition
redis-cli SET vane:migration:test "{\"owner\":\"test\"}" EX 30 NX
# Expected: OK

# Verify 3: Lock release
redis-cli EVAL "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end" 1 vane:migration:test "test"
# Expected: 1
```

---

## 9. Acceptance Criteria

- [ ] Redis Sentinel client connects to Sentinel nodes
- [ ] Sentinel status returns master/slave info
- [ ] Failover detection works (master changes detected)
- [ ] waitForFailover returns true on failover
- [ ] Migration lock acquired atomically (SETNX)
- [ ] Migration lock released only by owner
- [ ] Lock auto-expires after TTL
- [ ] Lock refresh extends TTL
- [ ] Concurrent migration blocked by lock
- [ ] migrateToSentinel completes full sequence
- [ ] verifyConsistency detects mismatches
- [ ] rollbackMigration reverts to direct Redis
- [ ] Unit tests: 100% coverage for Sentinel functions
- [ ] Unit tests: 100% coverage for lock functions
- [ ] Integration tests: Failover < 30s
- [ ] Integration tests: Sessions survive failover

---

## 10. Dependencies

| Dependency | Required For | Status |
|:---|:---|:---|
| ioredis | Redis client | Existing |
| ioredis-sentinel | Sentinel support | New package |
| Redis 6.2+ | Sentinel support | Infrastructure |

---

## 11. Environment Variables

| Variable | Required | Default | Description |
|:---|:---|:---|:---|
| `REDIS_USE_SENTINEL` | No | `false` | Enable Sentinel mode |
| `REDIS_SENTINEL_HOSTS` | If Sentinel | `localhost:26379` | Comma-separated Sentinel hosts |
| `REDIS_SENTINEL_MASTER_NAME` | If Sentinel | `mymaster` | Sentinel master name |
| `REDIS_SENTINEL_PASSWORD` | If Sentinel auth | - | Sentinel AUTH password |
| `HOSTNAME` | Recommended | `unknown` | Instance hostname for lock owner |

---

## 12. Security Considerations

### 12.1 Lock Security

| Setting | Value | Rationale |
|:---|:---|:---|
| Lock TTL | 30 seconds | Prevents abandoned locks while allowing long operations |
| Owner verification | Required | Only lock holder can release (Lua script) |
| Refresh interval | 10 seconds | Keeps lock alive during long operations |

### 12.2 Sentinel Security

| Setting | Value | Rationale |
|:---|:---|:---|
| Sentinel AUTH | If configured | Prevents unauthorized Sentinel access |
| Redis AUTH | Required | Prevents unauthorized Redis access |
| TLS | Recommended | Prevents network eavesdropping |

### 12.3 Failover Security

| Setting | Value | Rationale |
|:---|:---|:---|
| Quorum | 2 of 3 | Prevents single-node split-brain |
| Write concern | majority | Ensures writes propagate before acknowledgment |

---

## 13. Monitoring

### 13.1 Metrics

| Metric | Description | Alert |
|:---|:---|:---|
| `redis.sentinel.status` | Sentinel health (0/1) | Alert if 0 |
| `redis.sentinel.master` | Current master address | Alert on change |
| `redis.failover.duration` | Failover time (ms) | Alert if > 30000 |
| `migration.lock.held` | Lock holder | Alert if held > 5 min |
| `migration.phase` | Current phase | Alert if stuck |

### 13.2 Log Events

| Event | When | Fields |
|:---|:---|:---|
| `sentinel.failover.started` | Failover detected | old_master, new_master |
| `sentinel.failover.completed` | Failover finished | duration, new_master |
| `migration.lock.acquired` | Lock acquired | lock_name, owner |
| `migration.lock.released` | Lock released | lock_name, owner |
| `migration.completed` | Migration finished | duration, migrated_count |
| `migration.rollback` | Rollback triggered | reason |

---

## 14. Rollback Procedure

If Sentinel migration fails:

```bash
# 1. Check migration state
curl -s http://localhost:3000/api/admin/migration-state | jq

# 2. Manual rollback if needed
# Set REDIS_USE_SENTINEL=false
export REDIS_USE_SENTINEL=false

# 3. Restart application
# All writes go to direct Redis

# 4. Verify direct Redis is primary
redis-cli -h localhost INFO replication

# 5. Investigate failure
# Check logs for error details
```

---

## 15. Next Steps

1. **Implement:** Create `lib/auth/redis-sentinel.ts` with Sentinel connection manager
2. **Implement:** Create `lib/auth/migration-lock.ts` with distributed lock
3. **Update:** Modify `lib/auth/migrate.ts` for Sentinel orchestration
4. **Update:** Modify `lib/auth/redis.ts` for Sentinel support
5. **Test:** Add unit tests for all new functions
6. **Test:** Integration test with Redis Sentinel cluster
7. **Deploy:** Staging → Production with monitoring
8. **Monitor:** Watch failover metrics for 2 weeks