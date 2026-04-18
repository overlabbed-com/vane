/**
 * Unit tests for distributed rate limiting.
 * These tests mock Redis to run without a real Redis instance.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock ioredis before importing
vi.mock('ioredis', () => {
  class MockRedis {
    status = 'ready';
    on = vi.fn();
    pipeline = vi.fn().mockReturnValue({
      zremrangebyscore: vi.fn().mockReturnThis(),
      zcard: vi.fn().mockReturnThis(),
      zadd: vi.fn().mockReturnThis(),
      expire: vi.fn().mockReturnThis(),
      exec: vi.fn().mockResolvedValue([
        [null, 0], // zremrangebyscore baseline
        [null, 0], // zremrangebyscore burst
        [null, 0], // zcard baseline
        [null, 0], // zcard burst
      ]),
    });
    zremrangebyscore = vi.fn().mockResolvedValue(0);
    zcard = vi.fn().mockResolvedValue(0);
    zrange = vi.fn().mockResolvedValue([]);
    zadd = vi.fn().mockResolvedValue(1);
    expire = vi.fn().mockResolvedValue(1);
    del = vi.fn().mockResolvedValue(1);
    get = vi.fn();
    setex = vi.fn().mockResolvedValue('OK');
    quit = vi.fn().mockResolvedValue('OK');
  }
  return {
    default: MockRedis,
  };
});

// Set required env vars
process.env.REDIS_URL = 'redis://localhost:6379';
process.env.SESSION_SECRET = 'test-secret-key-that-is-at-least-32-chars';

import { checkRateLimit, getRateLimitStatus, resetRateLimit } from './rate-limit';

describe('Distributed rate limiting', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should allow request under baseline limit', async () => {
    const result = await checkRateLimit('192.168.1.1', 'login');
    
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBeGreaterThanOrEqual(0);
  });

  it('should allow request under burst limit', async () => {
    const result = await checkRateLimit('192.168.1.2', 'api_request');
    
    expect(result.allowed).toBe(true);
  });

  it('should track NAT clients with concurrent sessions', async () => {
    // NAT detection is based on session count in the session key, not rate limit counts
    // This test verifies the isNatClient flag is properly returned
    const { getRedisClient } = await import('./redis');
    const mockClient = getRedisClient() as any;
    
    // When baseline count is 0, isNatClient should be false
    // (NAT exemption requires >= 3 concurrent sessions tracked separately)
    const result = await checkRateLimit('192.168.1.100', 'login');
    
    // isNatClient is determined by session count, not rate limit count
    // Since we haven't tracked sessions, it should be false
    expect(result.isNatClient).toBe(false);
  });

  it('should get rate limit status without incrementing', async () => {
    const status = await getRateLimitStatus('192.168.1.50');
    
    expect(status).toHaveProperty('baselineCount');
    expect(status).toHaveProperty('burstCount');
    expect(status).toHaveProperty('sessionCount');
    expect(status).toHaveProperty('isNatClient');
  });

  it('should reset rate limit for an IP', async () => {
    await resetRateLimit('192.168.1.99');
    
    const { getRedisClient } = await import('./redis');
    const mockClient = getRedisClient() as any;
    
    expect(mockClient.del).toHaveBeenCalled();
  });

  it('should handle Redis errors gracefully', async () => {
    const { getRedisClient } = await import('./redis');
    const mockClient = getRedisClient() as any;
    
    // Make pipeline exec fail
    mockClient.pipeline.mockReturnValue({
      zremrangebyscore: vi.fn().mockReturnThis(),
      zcard: vi.fn().mockReturnThis(),
      zadd: vi.fn().mockReturnThis(),
      expire: vi.fn().mockReturnThis(),
      exec: vi.fn().mockRejectedValue(new Error('Redis connection failed')),
    });
    
    const result = await checkRateLimit('192.168.1.200', 'login');
    
    // Should allow on error (fail open)
    expect(result.allowed).toBe(true);
  });

  it('should reject request when burst limit exceeded', async () => {
    const { getRedisClient } = await import('./redis');
    const mockClient = getRedisClient() as any;
    
    // Mock pipeline to return counts indicating burst limit reached
    mockClient.pipeline.mockReturnValue({
      zremrangebyscore: vi.fn().mockReturnThis(),
      zcard: vi.fn().mockReturnThis(),
      zadd: vi.fn().mockReturnThis(),
      expire: vi.fn().mockReturnThis(),
      exec: vi.fn().mockResolvedValue([
        [null, 0], // zremrangebyscore baseline
        [null, 0], // zremrangebyscore burst
        [null, 0], // zcard baseline = 0
        [null, 15], // zcard burst = 15 (at limit)
      ]),
    });
    
    const result = await checkRateLimit('192.168.1.50', 'api_request');
    
    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
    expect(result.retryAfterMs).toBeGreaterThan(0);
  });

  it('should allow burst after idle period', async () => {
    vi.useFakeTimers();
    
    const { getRedisClient } = await import('./redis');
    const mockClient = getRedisClient() as any;
    
    // First call: burst at limit
    mockClient.pipeline.mockReturnValue({
      zremrangebyscore: vi.fn().mockReturnThis(),
      zcard: vi.fn().mockReturnThis(),
      zadd: vi.fn().mockReturnThis(),
      expire: vi.fn().mockReturnThis(),
      exec: vi.fn().mockResolvedValue([
        [null, 0],
        [null, 0],
        [null, 0],
        [null, 15], // burst exhausted
      ]),
    });
    
    const exhausted = await checkRateLimit('192.168.1.60', 'api_request');
    expect(exhausted.allowed).toBe(false);
    
    // Advance time past burst window (10 seconds)
    vi.advanceTimersByTime(11000);
    
    // Second call: burst window expired, should allow
    mockClient.pipeline.mockReturnValue({
      zremrangebyscore: vi.fn().mockReturnThis(),
      zcard: vi.fn().mockReturnThis(),
      zadd: vi.fn().mockReturnThis(),
      expire: vi.fn().mockReturnThis(),
      exec: vi.fn().mockResolvedValue([
        [null, 0],
        [null, 0],
        [null, 0],
        [null, 0], // burst cleared
      ]),
    });
    
    const result = await checkRateLimit('192.168.1.60', 'api_request');
    expect(result.allowed).toBe(true);
    
    vi.useRealTimers();
  });

  it('should handle concurrent requests from different IPs', async () => {
    // Simulate 20 concurrent requests from different IPs
    const promises = Array.from({ length: 20 }, (_, i) => 
      checkRateLimit(`192.168.1.${70 + i}`, 'api_request')
    );
    
    const results = await Promise.all(promises);
    
    // All should be allowed (different IPs)
    expect(results.every(r => r.allowed)).toBe(true);
  });
});