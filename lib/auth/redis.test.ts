/**
 * Unit tests for Redis session store.
 * These tests mock Redis to run without a real Redis instance.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock ioredis before importing
vi.mock('ioredis', () => {
  class MockRedis {
    status = 'ready';
    on = vi.fn();
    setex = vi.fn().mockResolvedValue('OK');
    get = vi.fn();
    del = vi.fn().mockResolvedValue(1);
    set = vi.fn().mockResolvedValue('OK');
    scan = vi.fn().mockResolvedValue(['0', []]);
    pipeline = vi.fn().mockReturnValue({
      setex: vi.fn().mockReturnThis(),
      zadd: vi.fn().mockReturnThis(),
      zremrangebyscore: vi.fn().mockReturnThis(),
      zcard: vi.fn().mockReturnThis(),
      zrange: vi.fn().mockReturnThis(),
      expire: vi.fn().mockReturnThis(),
      exec: vi.fn().mockResolvedValue([]),
    });
    eval = vi.fn().mockResolvedValue(1);
    quit = vi.fn().mockResolvedValue('OK');
    ping = vi.fn().mockResolvedValue('PONG');
  }
  return {
    default: MockRedis,
  };
});

// Set required env vars
process.env.REDIS_URL = 'redis://localhost:6379';
process.env.SESSION_SECRET = 'test-secret-key-that-is-at-least-32-chars';

import { initRedisClient, createSession, verifySession, revokeSession, validateRedisConnection } from './redis';

describe('Redis session store', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should initialize Redis client', () => {
    const client = initRedisClient();
    expect(client).toBeDefined();
  });

  it('should create a session with HMAC integrity signature', async () => {
    const session = await createSession('test-stored-token', 'test-user-id', {
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
    });

    expect(session).toBeDefined();
    expect(session.userId).toBe('test-user-id');
    expect(session.revoked).toBe(false);
  });

  it('should verify a valid session with HMAC integrity', async () => {
    // Mock Redis get to return valid session with HMAC
    const { getRedisClient } = await import('./redis');
    const mockClient = getRedisClient() as any;
    
    // Create a valid session with HMAC
    const sessionData = {
      userId: 'test-user-id',
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 900000).toISOString(),
      revoked: false,
      version: 1,
    };
    
    // Compute HMAC for this session
    const { createHmac } = await import('crypto');
    const hmacKey = createHmac('sha256', 'test-secret-key-that-is-at-least-32-chars')
      .update('session-integrity')
      .digest();
    const hmac = createHmac('sha256', hmacKey)
      .update(JSON.stringify(sessionData))
      .digest('hex');
    
    mockClient.get.mockResolvedValue(JSON.stringify({ session: sessionData, hmac }));

    const session = await verifySession('some-token');
    expect(session).toBeDefined();
    expect(session?.userId).toBe('test-user-id');
  });

  it('should reject tampered session', async () => {
    const { getRedisClient } = await import('./redis');
    const mockClient = getRedisClient() as any;
    
    // Create a tampered session with invalid HMAC
    const sessionData = {
      userId: 'test-user-id',
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 900000).toISOString(),
      revoked: false,
      version: 1,
    };
    
    // Use invalid HMAC to simulate tampering
    mockClient.get.mockResolvedValue(JSON.stringify({ session: sessionData, hmac: 'invalid-hmac' }));

    const session = await verifySession('tampered-token');
    expect(session).toBeNull();
  });

  it('should return null for expired session', async () => {
    const { getRedisClient } = await import('./redis');
    const mockClient = getRedisClient() as any;
    
    const sessionData = {
      userId: 'test-user-id',
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() - 1000).toISOString(), // Expired
      revoked: false,
      version: 1,
    };
    
    const { createHmac } = await import('crypto');
    const hmacKey = createHmac('sha256', 'test-secret-key-that-is-at-least-32-chars')
      .update('session-integrity')
      .digest();
    const hmac = createHmac('sha256', hmacKey)
      .update(JSON.stringify(sessionData))
      .digest('hex');
    
    mockClient.get.mockResolvedValue(JSON.stringify({ session: sessionData, hmac }));

    const session = await verifySession('expired-token');
    expect(session).toBeNull();
  });

  it('should return null for revoked session', async () => {
    const { getRedisClient } = await import('./redis');
    const mockClient = getRedisClient() as any;
    
    const sessionData = {
      userId: 'test-user-id',
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 900000).toISOString(),
      revoked: true,
      version: 1,
    };
    
    const { createHmac } = await import('crypto');
    const hmacKey = createHmac('sha256', 'test-secret-key-that-is-at-least-32-chars')
      .update('session-integrity')
      .digest();
    const hmac = createHmac('sha256', hmacKey)
      .update(JSON.stringify(sessionData))
      .digest('hex');
    
    mockClient.get.mockResolvedValue(JSON.stringify({ session: sessionData, hmac }));

    const session = await verifySession('revoked-token');
    expect(session).toBeNull();
  });

  it('should revoke a session', async () => {
    const { getRedisClient } = await import('./redis');
    const mockClient = getRedisClient() as any;
    
    const sessionData = {
      userId: 'test-user-id',
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 900000).toISOString(),
      revoked: false,
      version: 1,
    };
    
    const { createHmac } = await import('crypto');
    const hmacKey = createHmac('sha256', 'test-secret-key-that-is-at-least-32-chars')
      .update('session-integrity')
      .digest();
    const hmac = createHmac('sha256', hmacKey)
      .update(JSON.stringify(sessionData))
      .digest('hex');
    
    mockClient.get.mockResolvedValue(JSON.stringify({ session: sessionData, hmac }));

    const revoked = await revokeSession('some-token');
    expect(revoked).toBe(true);
  });

  it('should validate Redis connection on startup', async () => {
    const { getRedisClient } = await import('./redis');
    const mockClient = getRedisClient() as any;
    
    // Mock successful ping and health check
    mockClient.ping.mockResolvedValue('PONG');
    mockClient.get.mockResolvedValue('ok');
    mockClient.del.mockResolvedValue(1);

    const result = await validateRedisConnection();
    expect(result).toBe(true);
  });
});