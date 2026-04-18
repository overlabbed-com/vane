/**
 * Unit tests for token derivation.
 */

import { describe, it, expect, beforeAll } from 'vitest';

// Set required env vars before importing tokens module
beforeAll(() => {
  process.env.SESSION_SECRET = 'test-secret-key-that-is-at-least-32-chars';
});

import { generateTokenPair, deriveStoredToken, verifyToken } from './tokens';

describe('token derivation', () => {
  it('should generate a valid token pair', () => {
    const { rawToken, storedToken, createdAt, expiresAt } = generateTokenPair();

    expect(rawToken).toBeDefined();
    expect(rawToken.length).toBe(64); // 32 bytes = 64 hex chars
    expect(storedToken).toBeDefined();
    expect(storedToken.length).toBe(64); // SHA256 = 64 hex chars
    expect(createdAt).toBeInstanceOf(Date);
    expect(expiresAt).toBeInstanceOf(Date);
    expect(expiresAt.getTime()).toBeGreaterThan(createdAt.getTime());
  });

  it('should derive consistent stored token', () => {
    const { rawToken, storedToken } = generateTokenPair();

    const derived = deriveStoredToken(rawToken);
    expect(derived).toBe(storedToken);
  });

  it('should verify a valid token', () => {
    const { rawToken, storedToken } = generateTokenPair();

    const isValid = verifyToken(rawToken, storedToken);
    expect(isValid).toBe(true);
  });

  it('should reject an invalid token', () => {
    const { storedToken } = generateTokenPair();

    const isValid = verifyToken('invalid-raw-token', storedToken);
    expect(isValid).toBe(false);
  });

  it('should reject empty raw token', () => {
    const { storedToken } = generateTokenPair();

    const isValid = verifyToken('', storedToken);
    expect(isValid).toBe(false);
  });

  it('should produce different raw tokens', () => {
    const token1 = generateTokenPair();
    const token2 = generateTokenPair();

    expect(token1.rawToken).not.toBe(token2.rawToken);
  });

  it('should verify token with secondary secret', () => {
    // Set secondary secret
    process.env.SESSION_SECRET_ROTATION = 'rotation-secret-key-that-is-32-chars!!';

    const { rawToken, storedToken } = generateTokenPair();

    // Should still verify with combined key
    const isValid = verifyToken(rawToken, storedToken);
    expect(isValid).toBe(true);

    // Clean up
    delete process.env.SESSION_SECRET_ROTATION;
  });
});