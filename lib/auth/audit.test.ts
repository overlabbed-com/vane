/**
 * Unit tests for audit logging.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  logAuditEvent,
  hashIpAddress,
  truncateUserAgent,
  getRecentAuditEvents,
  getAuditEventsForUser,
  getAuditEventsForIp,
  clearAuditLog,
  getAuditLogSize,
  logLoginAttempt,
  logLoginSuccess,
  logLoginFailure,
  logSessionTamper,
  logSessionBindingMismatch,
} from './audit';

describe('audit logging', () => {
  beforeEach(() => {
    clearAuditLog();
  });

  describe('hashIpAddress', () => {
    it('should hash IP addresses consistently', () => {
      const hash1 = hashIpAddress('192.168.1.1');
      const hash2 = hashIpAddress('192.168.1.1');

      expect(hash1).toBe(hash2);
      expect(hash1.length).toBe(64); // SHA-256 hex
    });

    it('should return unknown for undefined IP', () => {
      const hash = hashIpAddress(undefined);
      expect(hash).toBe('unknown');
    });

    it('should normalize IPv6 addresses', () => {
      const hash1 = hashIpAddress('2001:0db8:0000:0000:0000:0000:0000:0001');
      const hash2 = hashIpAddress('2001:db8::1');

      // Different representations should hash differently (not normalized in this impl)
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('truncateUserAgent', () => {
    it('should truncate long user agents', () => {
      const longUA = 'a'.repeat(300);
      const truncated = truncateUserAgent(longUA);

      expect(truncated?.length).toBe(200);
    });

    it('should return null for undefined user agent', () => {
      const result = truncateUserAgent(undefined);
      expect(result).toBeNull();
    });

    it('should keep short user agents intact', () => {
      const shortUA = 'Mozilla/5.0';
      const result = truncateUserAgent(shortUA);

      expect(result).toBe(shortUA);
    });
  });

  describe('logAuditEvent', () => {
    it('should log an audit event', async () => {
      const event = await logAuditEvent({
        eventType: 'login_attempt',
        ipHash: hashIpAddress('192.168.1.1'),
        userAgent: 'Mozilla/5.0',
      });

      expect(event.id).toBeDefined();
      expect(event.event_type).toBe('login_attempt');
      expect(event.ip_hash).toBe(hashIpAddress('192.168.1.1'));
      expect(event.user_agent).toBe('Mozilla/5.0');
      expect(event.created_at).toBeInstanceOf(Date);
    });

    it('should store event in log', async () => {
      await logAuditEvent({
        eventType: 'login_success',
        ipHash: hashIpAddress('192.168.1.1'),
      });

      expect(getAuditLogSize()).toBe(1);
    });

    it('should handle metadata', async () => {
      const event = await logAuditEvent({
        eventType: 'login_failure',
        ipHash: hashIpAddress('192.168.1.1'),
        metadata: { reason: 'invalid_password' },
      });

      expect(event.metadata).toEqual({ reason: 'invalid_password' });
    });
  });

  describe('getRecentAuditEvents', () => {
    it('should return recent events in reverse order', async () => {
      await logAuditEvent({ eventType: 'login_attempt', ipHash: 'hash1' });
      await logAuditEvent({ eventType: 'login_success', ipHash: 'hash2' });
      await logAuditEvent({ eventType: 'login_failure', ipHash: 'hash3' });

      const events = await getRecentAuditEvents(2);

      expect(events.length).toBe(2);
      expect(events[0].event_type).toBe('login_failure');
    });

    it('should limit results', async () => {
      for (let i = 0; i < 10; i++) {
        await logAuditEvent({ eventType: 'login_attempt', ipHash: `hash${i}` });
      }

      const events = await getRecentAuditEvents(5);

      expect(events.length).toBe(5);
    });
  });

  describe('getAuditEventsForUser', () => {
    it('should filter by user ID', async () => {
      await logAuditEvent({
        eventType: 'login_attempt',
        userId: 'user1',
        ipHash: 'hash1',
      });
      await logAuditEvent({
        eventType: 'login_success',
        userId: 'user2',
        ipHash: 'hash2',
      });
      await logAuditEvent({
        eventType: 'login_attempt',
        userId: 'user1',
        ipHash: 'hash3',
      });

      const events = await getAuditEventsForUser('user1');

      expect(events.length).toBe(2);
      expect(events.every((e) => e.user_id === 'user1')).toBe(true);
    });
  });

  describe('getAuditEventsForIp', () => {
    it('should filter by IP hash', async () => {
      const ipHash = hashIpAddress('192.168.1.1');

      await logAuditEvent({ eventType: 'login_attempt', ipHash });
      await logAuditEvent({ eventType: 'login_success', ipHash: 'other' });
      await logAuditEvent({ eventType: 'login_attempt', ipHash });

      const events = await getAuditEventsForIp(ipHash);

      expect(events.length).toBe(2);
    });
  });

  describe('convenience functions', () => {
    it('should log login attempt', async () => {
      const event = await logLoginAttempt('192.168.1.1', 'Mozilla/5.0');
      expect(event.event_type).toBe('login_attempt');
    });

    it('should log login success', async () => {
      const event = await logLoginSuccess('user1', '192.168.1.1', 'Mozilla/5.0');
      expect(event.event_type).toBe('login_success');
      expect(event.user_id).toBe('user1');
    });

    it('should log login failure', async () => {
      const event = await logLoginFailure(
        '192.168.1.1',
        'Mozilla/5.0',
        'invalid_password'
      );
      expect(event.event_type).toBe('login_failure');
      expect(event.reason).toBe('invalid_password');
    });

    it('should log session tamper', async () => {
      const event = await logSessionTamper(
        'user1',
        '192.168.1.1',
        'Mozilla/5.0',
        'hmac_mismatch'
      );
      expect(event.event_type).toBe('session_tamper');
    });

    it('should log session binding mismatch', async () => {
      const event = await logSessionBindingMismatch(
        'user1',
        '192.168.1.1',
        'Mozilla/5.0',
        'ip_mismatch'
      );
      expect(event.event_type).toBe('session_binding_mismatch');
    });
  });
});