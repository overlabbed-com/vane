/**
 * Unit tests for PKCE utilities per RFC 7636.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// Set required env vars
process.env.SESSION_SECRET = 'test-secret-key-that-is-at-least-32-chars';

// Mock Redis before importing pkce module
const mockSetex = vi.fn().mockResolvedValue('OK');
const mockEval = vi.fn().mockResolvedValue(null);

vi.mock('../redis', () => ({
  getRedisClient: vi.fn(() => ({
    setex: mockSetex,
    eval: mockEval,
  })),
}));

import {
  generateCodeVerifier,
  deriveCodeChallenge,
  storeCodeVerifier,
  consumeCodeVerifier,
  generatePkce,
  isValidVerifierFormat,
  isValidChallengeFormat,
} from './pkce';

describe('PKCE Utilities', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSetex.mockResolvedValue('OK');
    mockEval.mockResolvedValue(null);
  });

  describe('generateCodeVerifier', () => {
    it('should generate a 43-character base64url verifier', () => {
      const verifier = generateCodeVerifier();

      expect(verifier).toBeDefined();
      expect(verifier.length).toBe(43); // 32 bytes base64url encoded = 43 chars
    });

    it('should generate URL-safe characters only', () => {
      const verifier = generateCodeVerifier();

      // Base64url uses A-Z, a-z, 0-9, -, _
      expect(/^[A-Za-z0-9_-]+$/.test(verifier)).toBe(true);
    });

    it('should generate different verifiers each time', () => {
      const verifier1 = generateCodeVerifier();
      const verifier2 = generateCodeVerifier();

      expect(verifier1).not.toBe(verifier2);
    });
  });

  describe('deriveCodeChallenge', () => {
    it('should derive a 43-character challenge from verifier', () => {
      const verifier = generateCodeVerifier();
      const challenge = deriveCodeChallenge(verifier);

      expect(challenge).toBeDefined();
      expect(challenge.length).toBe(43); // SHA256 = 32 bytes, base64url encoded = 43 chars
    });

    it('should generate URL-safe characters only', () => {
      const verifier = generateCodeVerifier();
      const challenge = deriveCodeChallenge(verifier);

      expect(/^[A-Za-z0-9_-]+$/.test(challenge)).toBe(true);
    });

    it('should produce consistent challenge for same verifier', () => {
      const verifier = generateCodeVerifier();
      const challenge1 = deriveCodeChallenge(verifier);
      const challenge2 = deriveCodeChallenge(verifier);

      expect(challenge1).toBe(challenge2);
    });

    it('should produce different challenges for different verifiers', () => {
      const verifier1 = generateCodeVerifier();
      const verifier2 = generateCodeVerifier();
      const challenge1 = deriveCodeChallenge(verifier1);
      const challenge2 = deriveCodeChallenge(verifier2);

      expect(challenge1).not.toBe(challenge2);
    });
  });

  describe('storeCodeVerifier', () => {
    it('should store verifier in Redis with TTL', async () => {
      const pkceId = 'test-pkce-id';
      const verifier = generateCodeVerifier();

      const result = await storeCodeVerifier(pkceId, verifier);

      expect(result).toBe(true);
      expect(mockSetex).toHaveBeenCalledWith(
        `pkce:${pkceId}`,
        600, // 10 minutes TTL
        verifier
      );
    });
  });

  describe('consumeCodeVerifier', () => {
    it('should consume verifier atomically via Lua script', async () => {
      const pkceId = 'test-pkce-id';
      const verifier = 'test-verifier';

      // Mock Lua script execution returning the verifier
      mockEval.mockResolvedValue(verifier);

      const result = await consumeCodeVerifier(pkceId);

      expect(result).toBe(verifier);
      expect(mockEval).toHaveBeenCalled();
    });

    it('should return null if verifier not found', async () => {
      const pkceId = 'nonexistent-pkce-id';

      // Mock Lua script execution returning null
      mockEval.mockResolvedValue(null);

      const result = await consumeCodeVerifier(pkceId);

      expect(result).toBeNull();
    });

    it('should use correct Lua syntax (redis.call)', async () => {
      const pkceId = 'test-pkce-id';

      mockEval.mockResolvedValue('verifier');

      await consumeCodeVerifier(pkceId);

      // Verify Lua script uses redis.call('GET', KEYS[1]) syntax
      const luaScript = mockEval.mock.calls[0][0];
      expect(luaScript).toContain("redis.call('GET', KEYS[1])");
    });
  });

  describe('generatePkce', () => {
    it('should generate complete PKCE pair', async () => {
      const result = await generatePkce();

      expect(result).toHaveProperty('codeVerifier');
      expect(result).toHaveProperty('codeChallenge');
      expect(result).toHaveProperty('pkceId');
    });

    it('should generate 43-char verifier and challenge', async () => {
      const result = await generatePkce();

      expect(result.codeVerifier.length).toBe(43);
      expect(result.codeChallenge.length).toBe(43);
    });

    it('should generate independent pkceId', async () => {
      const result = await generatePkce();

      // pkceId is 64 hex chars (32 bytes)
      expect(result.pkceId.length).toBe(64);
      expect(/^[a-f0-9]+$/.test(result.pkceId)).toBe(true);
    });

    it('should store verifier in Redis', async () => {
      await generatePkce();

      expect(mockSetex).toHaveBeenCalled();
    });
  });

  describe('isValidVerifierFormat', () => {
    it('should validate correct verifier format', () => {
      const verifier = generateCodeVerifier();

      expect(isValidVerifierFormat(verifier)).toBe(true);
    });

    it('should reject wrong length', () => {
      expect(isValidVerifierFormat('tooshort')).toBe(false);
      expect(isValidVerifierFormat('a'.repeat(50))).toBe(false);
    });

    it('should reject invalid characters', () => {
      expect(isValidVerifierFormat('abc+/12345678901234567890123456789012345678901')).toBe(false);
    });

    it('should reject empty input', () => {
      expect(isValidVerifierFormat('')).toBe(false);
      expect(isValidVerifierFormat(undefined as unknown as string)).toBe(false);
    });
  });

  describe('isValidChallengeFormat', () => {
    it('should validate correct challenge format', () => {
      const verifier = generateCodeVerifier();
      const challenge = deriveCodeChallenge(verifier);

      expect(isValidChallengeFormat(challenge)).toBe(true);
    });

    it('should reject wrong length', () => {
      expect(isValidChallengeFormat('tooshort')).toBe(false);
      expect(isValidChallengeFormat('a'.repeat(50))).toBe(false);
    });

    it('should reject invalid characters', () => {
      expect(isValidChallengeFormat('abc+/12345678901234567890123456789012345678901')).toBe(false);
    });

    it('should reject empty input', () => {
      expect(isValidChallengeFormat('')).toBe(false);
      expect(isValidChallengeFormat(undefined as unknown as string)).toBe(false);
    });
  });

  describe('race condition prevention', () => {
    it('should delete verifier before returning (atomic consume)', async () => {
      const pkceId = 'test-pkce-id';
      const verifier = 'test-verifier';

      mockEval.mockResolvedValue(verifier);

      await consumeCodeVerifier(pkceId);

      // Verify Lua script contains both GET and DEL
      const luaScript = mockEval.mock.calls[0][0];
      expect(luaScript).toContain("redis.call('GET', KEYS[1])");
      expect(luaScript).toContain("redis.call('DEL', KEYS[1])");
    });
  });

  describe('TTL enforcement', () => {
    it('should set 600 second TTL on store', async () => {
      const pkceId = 'test-pkce-id';
      const verifier = generateCodeVerifier();

      await storeCodeVerifier(pkceId, verifier);

      // Verify TTL is 600 seconds (10 minutes)
      expect(mockSetex).toHaveBeenCalledWith(
        expect.any(String),
        600,
        expect.any(String)
      );
    });
  });
});