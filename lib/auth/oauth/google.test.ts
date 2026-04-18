/**
 * Unit tests for Google OAuth provider.
 */

import { describe, it, expect, beforeAll, vi, afterEach } from 'vitest';

// Set required env vars before importing google module
beforeAll(() => {
  process.env.SESSION_SECRET = 'test-secret-key-that-is-at-least-32-chars';
  process.env.GOOGLE_CLIENT_ID = 'test-client-id';
  process.env.GOOGLE_CLIENT_SECRET = 'test-client-secret';
  process.env.GOOGLE_REDIRECT_URI = 'https://test.example.com/callback';
});

// Mock Redis before importing google module
vi.mock('../redis', () => ({
  getRedisClient: vi.fn(() => ({
    setex: vi.fn().mockResolvedValue('OK'),
    del: vi.fn().mockResolvedValue(1),
  })),
}));

import { generateStateNonce, validateStateNonce, getGoogleAuthUrl } from './google';

describe('Google OAuth', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('generateStateNonce', () => {
    it('should generate a valid state and nonce pair', async () => {
      const { state, nonce } = await generateStateNonce();

      expect(state).toBeDefined();
      expect(state.length).toBeGreaterThan(0);
      expect(nonce).toBeDefined();
      expect(nonce.length).toBe(64); // 32 bytes = 64 hex chars
    });

    it('should generate different nonces each time', async () => {
      const { nonce: nonce1 } = await generateStateNonce();
      const { nonce: nonce2 } = await generateStateNonce();

      expect(nonce1).not.toBe(nonce2);
    });
  });

  describe('validateStateNonce', () => {
    it('should validate a correct state and nonce', async () => {
      const { state, nonce } = await generateStateNonce();

      const isValid = await validateStateNonce(state, nonce);
      expect(isValid).toBe(true);
    });

    it('should reject an invalid nonce', async () => {
      const { state } = await generateStateNonce();

      const isValid = await validateStateNonce(state, 'invalid-nonce');
      expect(isValid).toBe(false);
    });

    it('should reject empty state', async () => {
      const { nonce } = await generateStateNonce();

      const isValid = await validateStateNonce('', nonce);
      expect(isValid).toBe(false);
    });

    it('should reject empty nonce', async () => {
      const { state } = await generateStateNonce();

      const isValid = await validateStateNonce(state, '');
      expect(isValid).toBe(false);
    });
  });

  describe('getGoogleAuthUrl', () => {
    it('should generate a valid auth URL', () => {
      const authUrl = getGoogleAuthUrl('test-state');

      expect(authUrl).toContain('https://accounts.google.com/o/oauth2/v2/auth');
      expect(authUrl).toContain('client_id=test-client-id');
      expect(authUrl).toContain('redirect_uri=');
      expect(authUrl).toContain('response_type=code');
      expect(authUrl).toContain('scope=');
      expect(authUrl).toContain('state=test-state');
    });

    it('should include required scopes', () => {
      const authUrl = getGoogleAuthUrl('test-state');

      expect(authUrl).toContain('openid');
      expect(authUrl).toContain('email');
      expect(authUrl).toContain('profile');
    });
  });
});