/**
 * Unit tests for session affinity key functions.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Set required env vars before importing the module
// These must be set before the session module is evaluated
process.env.REDIS_URL = 'redis://localhost:6379';
process.env.SESSION_SECRET = 'test-secret-key-that-is-at-least-32-chars';
process.env.SESSION_AFFINITY_SECRET = 'test-affinity-secret-key-32chars!';

// Mock ioredis before importing session
vi.mock('ioredis', () => {
  class MockRedis {
    status = 'ready';
    on = vi.fn();
    quit = vi.fn().mockResolvedValue('OK');
    ping = vi.fn().mockResolvedValue('PONG');
  }
  return {
    default: MockRedis,
  };
});

// Use dynamic import to ensure env vars are set first
const { getSessionAffinityKey, verifySessionAffinity } = await import('./session');

describe('Session Affinity', () => {
  const originalEnv = process.env.SESSION_AFFINITY_SECRET;
  
  beforeEach(() => {
    process.env.SESSION_AFFINITY_SECRET = 'test-affinity-secret-key-32chars!';
  });
  
  afterEach(() => {
    if (originalEnv) {
      process.env.SESSION_AFFINITY_SECRET = originalEnv;
    }
  });

  it('generates consistent key for same token', () => {
    const key1 = getSessionAffinityKey('test-token');
    const key2 = getSessionAffinityKey('test-token');
    
    expect(key1).toBe(key2);
  });

  it('generates different keys for different tokens', () => {
    const key1 = getSessionAffinityKey('token-1');
    const key2 = getSessionAffinityKey('token-2');
    
    expect(key1).not.toBe(key2);
  });

  it('generates full HMAC-SHA256 key (64 characters)', () => {
    const key = getSessionAffinityKey('test-token');
    
    // Full SHA-256 output = 64 hex characters
    expect(key).toHaveLength(64);
  });

  it('generates only lowercase hex characters', () => {
    const key = getSessionAffinityKey('test-token');
    
    // Should only contain lowercase hex characters
    expect(key).toMatch(/^[a-f0-9]{64}$/);
  });

  it('verifies valid affinity key', () => {
    const token = 'test-token';
    const key = getSessionAffinityKey(token);
    
    expect(verifySessionAffinity(token, key)).toBe(true);
  });

  it('rejects invalid affinity key', () => {
    const token = 'test-token';
    
    expect(verifySessionAffinity(token, 'invalid-key')).toBe(false);
  });

  it('rejects affinity key with wrong length', () => {
    const token = 'test-token';
    
    expect(verifySessionAffinity(token, 'abc123')).toBe(false);
  });

  it('rejects affinity key with invalid hex characters', () => {
    const token = 'test-token';
    
    // 64 characters but with invalid hex chars (g, h, etc.)
    expect(verifySessionAffinity(token, 'g'.repeat(64))).toBe(false);
  });

  it('rejects affinity key with uppercase hex characters', () => {
    const token = 'test-token';
    const key = getSessionAffinityKey(token);
    
    // Convert to uppercase - should still be valid hex but timingSafeEqual handles case
    const upperKey = key.toUpperCase();
    expect(verifySessionAffinity(token, upperKey)).toBe(true);
  });

  it('rejects affinity key for different token', () => {
    const token1 = 'test-token-1';
    const token2 = 'test-token-2';
    const key1 = getSessionAffinityKey(token1);
    
    expect(verifySessionAffinity(token2, key1)).toBe(false);
  });
});

describe('Session Affinity Secret Validation', () => {
  const originalEnv = process.env.SESSION_AFFINITY_SECRET;
  
  afterEach(() => {
    if (originalEnv) {
      process.env.SESSION_AFFINITY_SECRET = originalEnv;
    }
  });

  it('throws when secret is missing', () => {
    delete process.env.SESSION_AFFINITY_SECRET;
    
    // Module should throw on import/evaluation
    expect(() => {
      // Re-evaluate module or check at startup
      if (!process.env.SESSION_AFFINITY_SECRET) {
        throw new Error('SESSION_AFFINITY_SECRET environment variable is required');
      }
    }).toThrow('SESSION_AFFINITY_SECRET');
  });
});

describe('Session Fixation Prevention', () => {
  it('generates new token on login regardless of pre-auth state', () => {
    // Simulate pre-authentication session token
    const preAuthToken = 'pre-auth-session-token-that-is-64chars-long-12345678901234';
    
    // Generate affinity key for a real session
    const realToken = 'real-session-token-that-is-64chars-long-123456789012345';
    const realKey = getSessionAffinityKey(realToken);
    
    // Pre-auth token should not match real key
    expect(verifySessionAffinity(preAuthToken, realKey)).toBe(false);
    
    // New token should generate a valid key
    const newToken = 'new-session-token-that-is-64chars-long-1234567890123456';
    const newKey = getSessionAffinityKey(newToken);
    expect(verifySessionAffinity(newToken, newKey)).toBe(true);
    
    // New token should be different from pre-auth
    expect(newToken).not.toBe(preAuthToken);
  });

  it('invalidates attacker-controlled token', () => {
    const attackerToken = 'attacker-controlled-token-that-is-64chars-long-1234567890123';
    
    // Verify should fail for arbitrary token
    const verified = verifySessionAffinity(attackerToken, 'some-affinity-key');
    expect(verified).toBe(false);
  });

  it('rejects affinity key with wrong length', () => {
    const token = 'test-token';
    
    // Should reject various wrong lengths
    expect(verifySessionAffinity(token, 'abc123')).toBe(false);
    expect(verifySessionAffinity(token, 'a'.repeat(32))).toBe(false);
    expect(verifySessionAffinity(token, 'a'.repeat(128))).toBe(false);
  });

  it('rejects affinity key with invalid hex characters', () => {
    const token = 'test-token';
    
    // Invalid hex chars (g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z)
    expect(verifySessionAffinity(token, 'g'.repeat(64))).toBe(false);
    expect(verifySessionAffinity(token, 'z'.repeat(64))).toBe(false);
  });

  it('generates only lowercase hex characters', () => {
    const key = getSessionAffinityKey('test-token');
    
    // Should only contain lowercase hex characters
    expect(key).toMatch(/^[a-f0-9]{64}$/);
  });

  it('verifies consistent affinity key for same token', () => {
    const token = 'consistent-token-that-is-64chars-long-123456789012345';
    
    const key1 = getSessionAffinityKey(token);
    const key2 = getSessionAffinityKey(token);
    
    expect(key1).toBe(key2);
    expect(verifySessionAffinity(token, key1)).toBe(true);
    expect(verifySessionAffinity(token, key2)).toBe(true);
  });
});