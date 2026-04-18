/**
 * Unit tests for health check endpoint.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Set required env vars before importing
process.env.REDIS_URL = 'redis://localhost:6379';
process.env.SESSION_SECRET = 'test-secret-key-that-is-at-least-32-chars';
process.env.SESSION_AFFINITY_SECRET = 'test-affinity-secret-key-32chars!';

// Mock ioredis
vi.mock('ioredis', () => {
  const mockRedis = {
    status: 'ready',
    on: vi.fn(),
    ping: vi.fn().mockResolvedValue('PONG'),
  };

  return {
    default: vi.fn(() => mockRedis),
  };
});

// Mock the database module
vi.mock('../../../lib/database/db', () => ({
  db: {
    raw: vi.fn().mockResolvedValue({ rows: [{ '?column?': 1 }] }),
  },
}));

import { GET } from './route';
import { resetShutdownState, initiateShutdown } from '../../../lib/auth/shutdown';

describe('Health Check', () => {
  beforeEach(() => {
    resetShutdownState();
    vi.clearAllMocks();
    // Mock process.exit to prevent vitest from failing
    vi.spyOn(process, 'exit').mockImplementation((() => {}) as any);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns 200 when healthy', async () => {
    const response = await GET();
    const data = await response.json();
    
    expect(response.status).toBe(200);
    expect(data.status).toBe('healthy');
    expect(data.checks.redis).toBe(true);
    expect(data.checks.database).toBe(true);
  });

  it('returns 503 when Redis down', async () => {
    const { getRedisClient } = await import('../../../lib/auth/redis');
    const mockClient = getRedisClient() as any;
    
    // Mock Redis failure
    mockClient.ping.mockRejectedValueOnce(new Error('Connection refused'));
    
    const response = await GET();
    const data = await response.json();
    
    expect(response.status).toBe(503);
    expect(data.status).toBe('unhealthy');
    expect(data.checks.redis).toBe(false);
  });

  it('returns 503 when database down', async () => {
    const { db } = await import('../../../lib/database/db');
    
    // Mock DB failure
    (db.raw as any).mockRejectedValueOnce(new Error('ECONNREFUSED'));
    
    const response = await GET();
    const data = await response.json();
    
    expect(response.status).toBe(503);
    expect(data.status).toBe('unhealthy');
    expect(data.checks.database).toBe(false);
  });

  it('includes timestamp', async () => {
    const response = await GET();
    const data = await response.json();
    
    expect(data.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  });

  it('strips sensitive fields from response', async () => {
    const response = await GET();
    const data = await response.json();
    
    // Should NOT include memory, internal IPs, or error details
    expect(data.memory).toBeUndefined();
    expect(data.checks.redisError).toBeUndefined();
    expect(data.checks.databaseError).toBeUndefined();
  });

  it('Redis health check has timeout wrapper', async () => {
    const { getRedisClient } = await import('../../../lib/auth/redis');
    const mockClient = getRedisClient() as any;
    
    // Mock slow Redis (takes 5 seconds)
    mockClient.ping.mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve('PONG'), 5000))
    );
    
    const start = Date.now();
    const response = await GET();
    const elapsed = Date.now() - start;
    
    // Should fail fast due to timeout wrapper
    expect(response.status).toBe(503);
    expect(elapsed).toBeLessThan(3000); // Should timeout before 5s
  });

  it('returns 503 when shutting down', async () => {
    const server = { close: vi.fn((cb) => cb()) };
    
    initiateShutdown(server, 'SIGTERM');
    
    const response = await GET();
    const data = await response.json();
    
    expect(response.status).toBe(503);
    expect(data.status).toBe('shutting_down');
    expect(data.checks.redis).toBe(false);
    expect(data.checks.database).toBe(false);
  });
});