/**
 * Distributed rate limiting using Redis sliding window algorithm.
 * 
 * Features:
 * - Sliding window using Redis sorted sets
 * - 5 req/min/IP baseline with burst allowance (15 req/10s after idle)
 * - NAT exemption: 3 concurrent sessions per IP
 * - Replaces in-memory Map in login route
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 1
 * STRIDE: Mitigates L-02 (brute force / credential stuffing)
 */

import { getRedisClient } from './redis';

// Rate limiting configuration
const RATE_LIMIT_CONFIG = {
  // Baseline: 5 requests per minute
  baselineLimit: 5,
  baselineWindowMs: 60 * 1000, // 1 minute
  
  // Burst allowance: 15 requests per 10 seconds after idle
  burstLimit: 15,
  burstWindowMs: 10 * 1000, // 10 seconds
  
  // NAT exemption: allow 3 concurrent sessions per IP
  natConcurrentSessions: 3,
  
  // Key prefix for rate limiting
  keyPrefix: 'rl:',
  
  // Session key prefix (for concurrent session tracking)
  sessionKeyPrefix: 'rlsess:',
} as const;

// Rate limit result
export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterMs?: number;
  isNatClient: boolean;
}

/**
 * Checks rate limit for an IP address using sliding window algorithm.
 * Uses Redis sorted sets for precise sliding window tracking.
 * 
 * @param ipAddress - Client IP address
 * @param action - Action type for logging (e.g., 'login', 'api_request')
 * @returns Rate limit result with allowed status and metadata
 */
export async function checkRateLimit(
  ipAddress: string,
  action: string = 'request'
): Promise<RateLimitResult> {
  const redis = getRedisClient();
  const now = Date.now();
  
  // Use separate keys for baseline and burst windows
  const baselineKey = `${RATE_LIMIT_CONFIG.keyPrefix}baseline:${ipAddress}`;
  const burstKey = `${RATE_LIMIT_CONFIG.keyPrefix}burst:${ipAddress}`;
  
  try {
    // Use pipeline for atomic operations
    const pipeline = redis.pipeline();
    
    // Remove expired entries from baseline window (older than window)
    pipeline.zremrangebyscore(baselineKey, '-inf', now - RATE_LIMIT_CONFIG.baselineWindowMs);
    
    // Remove expired entries from burst window (older than burst window)
    pipeline.zremrangebyscore(burstKey, '-inf', now - RATE_LIMIT_CONFIG.burstWindowMs);
    
    // Count entries in baseline window
    pipeline.zcard(baselineKey);
    
    // Count entries in burst window
    pipeline.zcard(burstKey);
    
    const results = await pipeline.exec();
    
    if (!results) {
      throw new Error('Pipeline execution failed');
    }
    
    const baselineCount = (results[2]?.[1] as number) || 0;
    const burstCount = (results[3]?.[1] as number) || 0;
    
    // Check NAT exemption first (3 concurrent sessions = NAT client)
    const isNatClient = baselineCount >= RATE_LIMIT_CONFIG.natConcurrentSessions;
    
    // Check burst allowance first (more permissive)
    if (burstCount >= RATE_LIMIT_CONFIG.burstLimit) {
      // Get oldest entry in burst window to calculate retry time
      const oldestEntries = await redis.zrange(burstKey, 0, 0, 'WITHSCORES');
      const oldestTimestamp = oldestEntries.length >= 2 ? parseInt(oldestEntries[1], 10) : now;
      const retryAfterMs = Math.max(0, (oldestTimestamp + RATE_LIMIT_CONFIG.burstWindowMs) - now);
      
      return {
        allowed: false,
        remaining: 0,
        retryAfterMs,
        isNatClient,
      };
    }
    
    // Check baseline limit
    if (baselineCount >= RATE_LIMIT_CONFIG.baselineLimit) {
      // Get oldest entry in baseline window to calculate retry time
      const oldestEntries = await redis.zrange(baselineKey, 0, 0, 'WITHSCORES');
      const oldestTimestamp = oldestEntries.length >= 2 ? parseInt(oldestEntries[1], 10) : now;
      const retryAfterMs = Math.max(0, (oldestTimestamp + RATE_LIMIT_CONFIG.baselineWindowMs) - now);
      
      return {
        allowed: false,
        remaining: 0,
        retryAfterMs,
        isNatClient,
      };
    }
    
    // Request is allowed - add to both windows
    const addPipeline = redis.pipeline();
    
    // Add to baseline window with current timestamp as score
    addPipeline.zadd(baselineKey, now, `${now}:${Math.random()}`);
    
    // Add to burst window
    addPipeline.zadd(burstKey, now, `${now}:${Math.random()}`);
    
    // Set TTL on keys to auto-cleanup
    addPipeline.expire(baselineKey, Math.ceil(RATE_LIMIT_CONFIG.baselineWindowMs / 1000) + 60);
    addPipeline.expire(burstKey, Math.ceil(RATE_LIMIT_CONFIG.burstWindowMs / 1000) + 60);
    
    await addPipeline.exec();
    
    // Log rate limit check (without PII)
    console.log(
      JSON.stringify({
        event: 'rate_limit.check',
        action,
        ip_hash: ipAddress.replace(/./g, 'x'),
        baseline_count: baselineCount,
        burst_count: burstCount,
        is_nat: isNatClient,
        timestamp: new Date().toISOString(),
      })
    );
    
    return {
      allowed: true,
      remaining: Math.max(0, RATE_LIMIT_CONFIG.baselineLimit - baselineCount - 1),
      isNatClient,
    };
  } catch (error) {
    console.error(
      JSON.stringify({
        event: 'rate_limit.error',
        action,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      })
    );
    
    // On Redis error, allow request but log the failure
    // This prevents Redis failures from blocking all requests
    return {
      allowed: true,
      remaining: 0,
      isNatClient: false,
    };
  }
}

/**
 * Tracks a concurrent session for NAT exemption.
 * Called when a user successfully authenticates.
 * 
 * @param ipAddress - Client IP address
 * @param userId - User ID
 * @returns true if session was tracked (NAT client if >= 3 sessions)
 */
export async function trackConcurrentSession(
  ipAddress: string,
  userId: string
): Promise<boolean> {
  const redis = getRedisClient();
  const key = `${RATE_LIMIT_CONFIG.sessionKeyPrefix}${ipAddress}`;
  const now = Date.now();
  
  try {
    // Add session with user ID as member
    await redis.zadd(key, now, `${userId}:${now}:${Math.random()}`);
    
    // Set TTL for session tracking (15 minutes - matches session TTL)
    await redis.expire(key, 15 * 60);
    
    // Count concurrent sessions for this IP
    const sessionCount = await redis.zcard(key);
    
    const isNatClient = sessionCount >= RATE_LIMIT_CONFIG.natConcurrentSessions;
    
    // Log concurrent session tracking
    console.log(
      JSON.stringify({
        event: 'rate_limit.session_track',
        ip_hash: ipAddress.replace(/./g, 'x'),
        user_id: userId,
        session_count: sessionCount,
        is_nat: isNatClient,
        timestamp: new Date().toISOString(),
      })
    );
    
    return isNatClient;
  } catch (error) {
    console.error(
      JSON.stringify({
        event: 'rate_limit.session_track.error',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      })
    );
    return false;
  }
}

/**
 * Removes a concurrent session tracking.
 * Called when a user logs out.
 * 
 * @param ipAddress - Client IP address
 * @param userId - User ID
 */
export async function removeConcurrentSession(
  ipAddress: string,
  userId: string
): Promise<void> {
  const redis = getRedisClient();
  const key = `${RATE_LIMIT_CONFIG.sessionKeyPrefix}${ipAddress}`;
  
  try {
    // Remove all entries for this user from the IP's session set
    const entries = await redis.zrange(key, 0, -1);
    
    for (const entry of entries) {
      if (entry.startsWith(`${userId}:`)) {
        await redis.zrem(key, entry);
      }
    }
  } catch (error) {
    console.error(
      JSON.stringify({
        event: 'rate_limit.session_remove.error',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
      })
    );
  }
}

/**
 * Gets current rate limit status for an IP without incrementing.
 * Useful for checking before showing rate limit info.
 * 
 * @param ipAddress - Client IP address
 * @returns Current rate limit status
 */
export async function getRateLimitStatus(
  ipAddress: string
): Promise<{
  baselineCount: number;
  burstCount: number;
  sessionCount: number;
  isNatClient: boolean;
}> {
  const redis = getRedisClient();
  const now = Date.now();
  
  const baselineKey = `${RATE_LIMIT_CONFIG.keyPrefix}baseline:${ipAddress}`;
  const burstKey = `${RATE_LIMIT_CONFIG.keyPrefix}burst:${ipAddress}`;
  const sessionKey = `${RATE_LIMIT_CONFIG.sessionKeyPrefix}${ipAddress}`;
  
  try {
    // Clean up expired entries first
    await redis.zremrangebyscore(baselineKey, '-inf', now - RATE_LIMIT_CONFIG.baselineWindowMs);
    await redis.zremrangebyscore(burstKey, '-inf', now - RATE_LIMIT_CONFIG.burstWindowMs);
    
    // Get counts
    const [baselineCount, burstCount, sessionCount] = await Promise.all([
      redis.zcard(baselineKey),
      redis.zcard(burstKey),
      redis.zcard(sessionKey),
    ]);
    
    return {
      baselineCount,
      burstCount,
      sessionCount,
      isNatClient: sessionCount >= RATE_LIMIT_CONFIG.natConcurrentSessions,
    };
  } catch (error) {
    return {
      baselineCount: 0,
      burstCount: 0,
      sessionCount: 0,
      isNatClient: false,
    };
  }
}

/**
 * Resets rate limit for an IP (for testing or admin purposes).
 * 
 * @param ipAddress - Client IP address
 */
export async function resetRateLimit(ipAddress: string): Promise<void> {
  const redis = getRedisClient();
  
  const baselineKey = `${RATE_LIMIT_CONFIG.keyPrefix}baseline:${ipAddress}`;
  const burstKey = `${RATE_LIMIT_CONFIG.keyPrefix}burst:${ipAddress}`;
  const sessionKey = `${RATE_LIMIT_CONFIG.sessionKeyPrefix}${ipAddress}`;
  
  await Promise.all([
    redis.del(baselineKey),
    redis.del(burstKey),
    redis.del(sessionKey),
  ]);
}