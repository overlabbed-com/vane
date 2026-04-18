/**
 * Unit tests for password hashing.
 */

import { describe, it, expect } from 'vitest';
import { hashPassword, verifyPassword, needsRehash } from './password';

describe('password hashing', () => {
  it('should hash a password', async () => {
    const password = 'testPassword123!';
    const hash = await hashPassword(password);

    expect(hash).toBeDefined();
    expect(hash.length).toBeGreaterThan(0);
    // Argon2id hashes start with $argon2id$
    expect(hash.startsWith('$argon2id$')).toBe(true);
  });

  it('should verify a correct password', async () => {
    const password = 'testPassword123!';
    const hash = await hashPassword(password);

    const isValid = await verifyPassword(password, hash);
    expect(isValid).toBe(true);
  });

  it('should reject an incorrect password', async () => {
    const password = 'testPassword123!';
    const hash = await hashPassword(password);

    const isValid = await verifyPassword('wrongPassword', hash);
    expect(isValid).toBe(false);
  });

  it('should reject empty password', async () => {
    const isValid = await verifyPassword('', 'somehash');
    expect(isValid).toBe(false);
  });

  it('should reject null hash', async () => {
    const isValid = await verifyPassword('password', '');
    expect(isValid).toBe(false);
  });

  it('should reject password exceeding max length', async () => {
    const longPassword = 'a'.repeat(1025);

    await expect(hashPassword(longPassword)).rejects.toThrow();
  });

  it('should produce different hashes for same password', async () => {
    const password = 'testPassword123!';
    const hash1 = await hashPassword(password);
    const hash2 = await hashPassword(password);

    // Salts should be different
    expect(hash1).not.toBe(hash2);

    // But both should verify
    expect(await verifyPassword(password, hash1)).toBe(true);
    expect(await verifyPassword(password, hash2)).toBe(true);
  });

  it('should detect when rehash is needed', async () => {
    const password = 'testPassword123!';
    const hash = await hashPassword(password);

    // Fresh hash from current config should not need rehash
    const needs = await needsRehash(hash);
    expect(needs).toBe(false);
  });
});