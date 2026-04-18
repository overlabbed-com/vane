/**
 * Redis session store implementation.
 * 
 * Features:
 * - Connection pooling with ioredis
 * - Session TTL with sliding refresh
 * - Session versioning for concurrent logout
 * - Automatic reconnection
 * - Error handling for Redis failures
 * - Redis AUTH password support (REDIS_AUTH_SECRET)
 * - TLS for rediss:// connections
 * - HMAC integrity signatures on session JSON
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 1
 * STRIDE: Mitigates R-01 (Redis AUTH), R-02 (session tampering)
 */

import Redis from 'ioredis';
import { createHmac, timingSafeEqual } from 'crypto';
import { getSessionTtlSeconds, getMaxTokenAgeSeconds } from './tokens';
import { createSentinelClient, getSentinelStatus, waitForFailover, isSentinelConnected, getSentinelRedisClient } from './redis-sentinel';

// Session data stored in Redis
export interface SessionData {
  userId: string;
  createdAt: string; // ISO8601
  expiresAt: string; // ISO8601
  revoked: boolean;
  version: number; // Session version for concurrent logout
  ipAddress?: string;
  userAgent?: string;
}

// Redis key prefix for sessions
const SESSION_KEY_PREFIX = 'sess:';

// HMAC key for session integrity (separate from session token derivation)
function getSessionIntegrityKey(): Buffer {
  const secret = process.env.SESSION_INTEGRITY_KEY || process.env.SESSION_SECRET;

  if (!secret) {
    throw new Error('SESSION_SECRET environment variable is required');
  }

  if (secret.length < 32) {
    throw new Error('SESSION_SECRET must be at least 32 characters');
  }

  // Derive a separate key for HMAC integrity (different from token derivation)
  return createHmac('sha256', secret).update('session-integrity').digest();
}

/**
 * Computes HMAC signature for session data.
 * Uses a separate key from token derivation to prevent key extension attacks.
 */
function computeSessionHmac(sessionData: SessionData): string {
  const key = getSessionIntegrityKey();
  const payload = JSON.stringify(sessionData);
  return createHmac('sha256', key).update(payload).digest('hex');
}

/**
 * Verifies HMAC signature on session data.
 * Returns the session if valid, null if tampered.
 */
function verifySessionHmac(sessionData: SessionData, hmac: string): boolean {
  if (!hmac) {
    return false;
  }

  try {
    const key = getSessionIntegrityKey();
    const payload = JSON.stringify(sessionData);
    const expectedHmac = createHmac('sha256', key).update(payload).digest('hex');

    const hmacBuffer = Buffer.from(hmac, 'hex');
    const expectedBuffer = Buffer.from(expectedHmac, 'hex');

    if (hmacBuffer.length !== expectedBuffer.length) {
      return false;
    }

    return timingSafeEqual(hmacBuffer, expectedBuffer);
  } catch {
    return false;
  }
}

// Redis configuration
const REDIS_CONFIG = {
  // Connection pool settings
  maxRetriesPerRequest: 3,
  // Retry strategy: exponential backoff
  retryStrategy: (times: number) => {
    if (times > 10) {
      // After 10 retries, give up and return null to trigger connection error
      return null;
    }
    return Math.min(times * 100, 3000);
  },
  // Connection timeout
  connectTimeout: 10000,
  // Command timeout
  commandTimeout: 5000,
  // Enable auto-reconnect
  lazyConnect: true,
  // Sentinel mode flag
  useSentinel: process.env.REDIS_USE_SENTINEL === 'true',
} as const;

// Singleton Redis client
let redisClient: Redis | null = null;
let connectionError: Error | null = null;

/**
 * Initializes the Redis client.
 * Call this once at application startup.
 * 
 * Security features:
 * - AUTH password from REDIS_AUTH_SECRET env var
 * - TLS for rediss:// connections (automatic)
 * - Connection validation on startup
 * - Sentinel support via REDIS_USE_SENTINEL env var
 * 
 * @param redisUrl - Redis connection URL (e.g., redis://localhost:6379 or rediss://localhost:6379)
 * @returns Redis client instance
 * @throws Error if connection validation fails
 */
export function initRedisClient(redisUrl?: string): Redis {
  if (redisClient) {
    return redisClient;
  }

  // Use Sentinel client if configured
  if (REDIS_CONFIG.useSentinel) {
    return createSentinelClient();
  }

  const url = redisUrl || process.env.REDIS_URL || 'redis://localhost:6379';
  const authPassword = process.env.REDIS_AUTH_SECRET;

  // Determine TLS setting based on URL scheme
  const isTls = url.startsWith('rediss://');

  // Build connection options
  const connectionOptions: Record<string, unknown> = {
    maxRetriesPerRequest: REDIS_CONFIG.maxRetriesPerRequest,
    retryStrategy: REDIS_CONFIG.retryStrategy,
    connectTimeout: REDIS_CONFIG.connectTimeout,
    commandTimeout: REDIS_CONFIG.commandTimeout,
    lazyConnect: REDIS_CONFIG.lazyConnect,
    // Key prefix for all keys (namespace isolation)
    keyPrefix: 'vane:',
  };

  // Add AUTH password if provided
  if (authPassword) {
    connectionOptions.password = authPassword;
  }

  // Add TLS configuration for rediss:// or if explicitly requested
  if (isTls) {
    connectionOptions.tls = {};
  }

  redisClient = new Redis(url, connectionOptions);

  // Event handlers
  redisClient.on('error', (error) => {
    console.error('Redis client error:', error.message);
    connectionError = error;
  });

  redisClient.on('connect', () => {
    console.log('Redis client connected');
    connectionError = null;
  });

  redisClient.on('reconnecting', () => {
    console.log('Redis client reconnecting...');
  });

  return redisClient;
}

/**
 * Gets the Redis client instance.
 * Initializes if not already done.
 */
export function getRedisClient(): Redis {
  if (!redisClient) {
    return initRedisClient();
  }
  return redisClient;
}

/**
 * Checks if Redis is currently connected.
 */
export function isRedisConnected(): boolean {
  if (!redisClient) {
    return false;
  }
  return redisClient.status === 'ready' && connectionError === null;
}

/**
 * Validates Redis connection on startup.
 * Performs a PING to ensure credentials and network are correct.
 * If Sentinel mode is enabled, also validates Sentinel status.
 * 
 * @returns true if connection is valid
 * @throws Error with diagnostic message if connection fails
 */
export async function validateRedisConnection(): Promise<boolean> {
  // Validate Sentinel if in Sentinel mode
  if (REDIS_CONFIG.useSentinel) {
    return validateSentinelConnection();
  }

  const redis = getRedisClient();

  try {
    const result = await redis.ping();

    if (result !== 'PONG') {
      throw new Error(`Unexpected PING response: ${result}`);
    }

    // Verify we can perform a simple operation
    const testKey = 'vane:health:check';
    await redis.setex(testKey, 10, 'ok');
    const value = await redis.get(testKey);

    if (value !== 'ok') {
      throw new Error(`Health check read failed: ${value}`);
    }

    await redis.del(testKey);

    console.log('Redis connection validated successfully');
    return true;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    console.error(`Redis connection validation failed: ${message}`);
    throw new Error(`Redis connection validation failed: ${message}`);
  }
}

/**
 * Validates Sentinel connection on startup.
 * Verifies Sentinel status and master availability.
 * 
 * @returns true if Sentinel connection is valid
 * @throws Error with diagnostic message if connection fails
 */
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

/**
 * Verifies session with failover awareness.
 * Retries on connection errors that may be caused by failover.
 * 
 * @param storedToken - HMAC-derived token
 * @param maxRetries - Maximum retry attempts (default: 3)
 * @returns Session data if valid, null otherwise
 */
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

/**
 * Creates a new session in Redis with HMAC integrity signature.
 * 
 * @param storedToken - HMAC-derived token (not the raw token)
 * @param userId - User ID
 * @param metadata - Optional session metadata
 * @param version - Session version for concurrent logout tracking
 * @returns Session data as stored
 */
export async function createSession(
  storedToken: string,
  userId: string,
  metadata?: { ipAddress?: string; userAgent?: string },
  version: number = 1
): Promise<SessionData> {
  const redis = getRedisClient();
  const ttlSeconds = getSessionTtlSeconds();
  const maxAgeSeconds = getMaxTokenAgeSeconds();

  const now = new Date();
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000);

  const session: SessionData = {
    userId,
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    revoked: false,
    version,
    ipAddress: metadata?.ipAddress,
    userAgent: metadata?.userAgent,
  };

  const key = `${SESSION_KEY_PREFIX}${storedToken}`;

  try {
    // Compute HMAC integrity signature
    const hmac = computeSessionHmac(session);

    // Use pipeline for atomic operation
    const pipeline = redis.pipeline();

    // Set session with TTL (includes integrity signature)
    pipeline.setex(key, ttlSeconds, JSON.stringify({ session, hmac }));

    // Also set a "last activity" key for sliding window tracking
    pipeline.setex(`${key}:activity`, maxAgeSeconds, now.toISOString());

    await pipeline.exec();

    return session;
  } catch (error) {
    console.error('Failed to create session in Redis:', error instanceof Error ? error.message : 'Unknown error');
    throw new Error('Session creation failed');
  }
}

/**
 * Verifies and retrieves a session from Redis.
 * Performs TTL refresh (sliding window) on successful verification.
 * Validates HMAC integrity signature to detect tampering.
 * 
 * @param storedToken - HMAC-derived token
 * @returns Session data if valid, null otherwise
 */
export async function verifySession(storedToken: string): Promise<SessionData | null> {
  const redis = getRedisClient();
  const key = `${SESSION_KEY_PREFIX}${storedToken}`;

  try {
    const data = await redis.get(key);

    if (!data) {
      return null;
    }

    // Parse stored data: { session: SessionData, hmac: string }
    const stored = JSON.parse(data);
    const session: SessionData = stored.session;
    const hmac: string = stored.hmac;

    // Verify HMAC integrity signature
    if (!verifySessionHmac(session, hmac)) {
      // SECURITY: Session data has been tampered with
      console.log(
        JSON.stringify({
          event: 'auth.session.tamper_detected',
          token_prefix: storedToken.substring(0, 8),
          timestamp: new Date().toISOString(),
        })
      );
      // Reject tampered session
      await redis.del(key);
      return null;
    }

    // Check if revoked
    if (session.revoked) {
      await redis.del(key);
      return null;
    }

    // Check if expired
    const expiresAt = new Date(session.expiresAt);
    if (new Date() > expiresAt) {
      await redis.del(key);
      return null;
    }

    // TTL refresh (sliding window) - extend session on activity
    const ttlSeconds = getSessionTtlSeconds();
    session.expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();

    // Compute new HMAC for refreshed session
    const newHmac = computeSessionHmac(session);

    // Update TTL atomically with new HMAC
    await redis.setex(key, ttlSeconds, JSON.stringify({ session, hmac: newHmac }));

    return session;
  } catch (error) {
    console.error('Failed to verify session:', error instanceof Error ? error.message : 'Unknown error');
    return null;
  }
}

/**
 * Revokes a session (logout).
 * 
 * @param storedToken - HMAC-derived token
 * @returns true if session was revoked
 */
export async function revokeSession(storedToken: string): Promise<boolean> {
  const redis = getRedisClient();
  const key = `${SESSION_KEY_PREFIX}${storedToken}`;

  try {
    // Get current session
    const data = await redis.get(key);

    if (!data) {
      return false;
    }

    // Parse stored data: { session: SessionData, hmac: string }
    const stored = JSON.parse(data);
    const session: SessionData = stored.session;
    session.revoked = true;

    // Compute new HMAC for revoked session
    const newHmac = computeSessionHmac(session);

    // Update with revoked flag but short TTL (grace period for concurrent requests)
    await redis.setex(key, 10, JSON.stringify({ session, hmac: newHmac }));

    return true;
  } catch (error) {
    console.error('Failed to revoke session:', error instanceof Error ? error.message : 'Unknown error');
    return false;
  }
}

/**
 * Revokes all sessions for a user with a specific version.
 * Used for concurrent logout via session versioning.
 * 
 * @param userId - User ID
 * @param version - Version number to revoke
 * @returns Number of sessions revoked
 */
export async function revokeSessionsByVersion(
  userId: string,
  version: number
): Promise<number> {
  const redis = getRedisClient();
  let cursor = '0';
  let revokedCount = 0;

  try {
    do {
      // Use SCAN for large keyspaces
      const [nextCursor, keys] = await redis.scan(
        cursor,
        'MATCH',
        `${SESSION_KEY_PREFIX}*`,
        'COUNT',
        100
      );
      cursor = nextCursor;

      for (const key of keys) {
        // Skip activity keys
        if (key.includes(':activity')) {
          continue;
        }

        const data = await redis.get(key);
        if (data) {
          // Parse stored data: { session: SessionData, hmac: string }
          const stored = JSON.parse(data);
          const session: SessionData = stored.session;
          if (
            session.userId === userId &&
            session.version === version &&
            !session.revoked
          ) {
            session.revoked = true;
            // Compute new HMAC for revoked session
            const newHmac = computeSessionHmac(session);
            // Short TTL for revoked sessions (grace period)
            await redis.setex(key, 10, JSON.stringify({ session, hmac: newHmac }));
            revokedCount++;
          }
        }
      }
    } while (cursor !== '0');

    return revokedCount;
  } catch (error) {
    console.error('Failed to revoke sessions by version:', error instanceof Error ? error.message : 'Unknown error');
    return 0;
  }
}

/**
 * Revokes all sessions for a user.
 * Useful for "logout everywhere" functionality.
 * 
 * @param userId - User ID
 * @returns Number of sessions revoked
 */
export async function revokeAllUserSessions(userId: string): Promise<number> {
  const redis = getRedisClient();

  try {
    // Scan for all session keys belonging to user
    let cursor = '0';
    let revokedCount = 0;

    do {
      // Use SCAN for large keyspaces
      const [nextCursor, keys] = await redis.scan(
        cursor,
        'MATCH',
        `${SESSION_KEY_PREFIX}*`,
        'COUNT',
        100
      );
      cursor = nextCursor;

      for (const key of keys) {
        // Skip activity keys
        if (key.includes(':activity')) {
          continue;
        }

        const data = await redis.get(key);
        if (data) {
          // Parse stored data: { session: SessionData, hmac: string }
          const stored = JSON.parse(data);
          const session: SessionData = stored.session;
          if (session.userId === userId && !session.revoked) {
            session.revoked = true;
            // Compute new HMAC for revoked session
            const newHmac = computeSessionHmac(session);
            await redis.setex(key, 10, JSON.stringify({ session, hmac: newHmac }));
            revokedCount++;
          }
        }
      }
    } while (cursor !== '0');

    return revokedCount;
  } catch (error) {
    console.error('Failed to revoke user sessions:', error instanceof Error ? error.message : 'Unknown error');
    return 0;
  }
}

/**
 * Closes the Redis connection.
 * Call this at application shutdown.
 */
export async function closeRedisClient(): Promise<void> {
  if (redisClient) {
    await redisClient.quit();
    redisClient = null;
  }
}