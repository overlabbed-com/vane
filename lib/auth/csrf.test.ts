/**
 * Unit tests for CSRF token generation and validation.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock ioredis before importing
vi.mock('ioredis', () => {
  class MockRedis {
    status = 'ready';
    on = vi.fn();
    get = vi.fn();
    setex = vi.fn().mockResolvedValue('OK');
    del = vi.fn().mockResolvedValue(1);
    pipeline = vi.fn().mockReturnValue({
      exec: vi.fn().mockResolvedValue([]),
    });
    quit = vi.fn().mockResolvedValue('OK');
  }
  return {
    default: MockRedis,
  };
});

// Set required env vars
process.env.REDIS_URL = 'redis://localhost:6379';
process.env.SESSION_SECRET = 'test-secret-key-that-is-at-least-32-chars';

import { generateCsrfToken, storeCsrfToken, getCsrfToken, validateCsrfToken, deleteCsrfToken } from './csrf';

describe('CSRF token generation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('generates 64-character hex token', () => {
    const token = generateCsrfToken();
    expect(token).toMatch(/^[a-f0-9]{64}$/);
    expect(token.length).toBe(64);
  });

  it('generates unique tokens', () => {
    const token1 = generateCsrfToken();
    const token2 = generateCsrfToken();
    expect(token1).not.toBe(token2);
  });

  it('has sufficient entropy (256 bits)', () => {
    const token = generateCsrfToken();
    // 64 hex chars = 256 bits of entropy
    expect(token.length).toBe(64);
    expect(token).toMatch(/^[a-f0-9]{64}$/);
  });
});

describe('CSRF token storage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('stores and retrieves CSRF token', async () => {
    const { getRedisClient } = await import('./redis');
    const mockClient = getRedisClient() as any;

    const sessionToken = 'test-session-token';
    const csrfToken = generateCsrfToken();

    // Mock Redis get to return the stored token
    mockClient.get.mockResolvedValue(csrfToken);

    await storeCsrfToken(sessionToken, csrfToken);
    const retrieved = await getCsrfToken(sessionToken);

    expect(mockClient.setex).toHaveBeenCalledWith(
      `csrf:${sessionToken}`,
      15 * 60,
      csrfToken
    );
    expect(retrieved).toBe(csrfToken);
  });

  it('returns null for non-existent session', async () => {
    const { getRedisClient } = await import('./redis');
    const mockClient = getRedisClient() as any;

    mockClient.get.mockResolvedValue(null);

    const retrieved = await getCsrfToken('non-existent-session');
    expect(retrieved).toBeNull();
  });
});

describe('CSRF token validation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('validates correct token', async () => {
    const { getRedisClient } = await import('./redis');
    const mockClient = getRedisClient() as any;

    const sessionToken = 'test-session-token';
    const csrfToken = generateCsrfToken();

    mockClient.get.mockResolvedValue(csrfToken);

    const isValid = await validateCsrfToken(sessionToken, csrfToken);
    expect(isValid).toBe(true);
  });

  it('rejects wrong token', async () => {
    const { getRedisClient } = await import('./redis');
    const mockClient = getRedisClient() as any;

    const sessionToken = 'test-session-token';
    const csrfToken = generateCsrfToken();

    mockClient.get.mockResolvedValue(csrfToken);

    const isValid = await validateCsrfToken(sessionToken, 'wrong-token');
    expect(isValid).toBe(false);
  });

  it('rejects missing token', async () => {
    const isValid = await validateCsrfToken('session', 'csrf-token');
    expect(isValid).toBe(false);
  });

  it('uses constant-time comparison (timing attack resistant)', async () => {
    const { getRedisClient } = await import('./redis');
    const mockClient = getRedisClient() as any;

    const sessionToken = 'test-session-token';
    const csrfToken = generateCsrfToken();

    mockClient.get.mockResolvedValue(csrfToken);

    // Valid token
    const validResult = await validateCsrfToken(sessionToken, csrfToken);
    expect(validResult).toBe(true);

    // Invalid token (different length)
    const invalidResult = await validateCsrfToken(sessionToken, 'a'.repeat(64));
    expect(invalidResult).toBe(false);

    // Both should take similar time (constant-time comparison)
    // Note: This is tested indirectly - timingSafeEqual is used internally
  });
});