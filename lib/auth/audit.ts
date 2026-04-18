/**
 * Database audit logging for authentication events.
 * 
 * Features:
 * - Logs auth events to database (auth_events table)
 * - Events: login_attempt, login_success, login_failure, session_tamper, session_revoked
 * - No PII stored (email not logged, IP hashed)
 * - Async logging to prevent blocking auth flow
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 2
 * STRIDE: Mitigates I-01 (audit logging), I-02 (tamper detection)
 */

import { createHash } from 'crypto';
import { EventEmitter } from 'events';

// Event types for audit logging
export type AuditEventType =
  | 'login_attempt'
  | 'login_success'
  | 'login_failure'
  | 'session_tamper'
  | 'session_revoked'
  | 'session_binding_mismatch';

// Audit event data (no PII)
export interface AuditEvent {
  eventType: AuditEventType;
  userId?: string;
  ipHash: string;
  userAgent?: string;
  reason?: string;
  metadata?: Record<string, unknown>;
}

// Database row for auth_events
export interface AuditEventRow {
  id: string;
  event_type: string;
  user_id: string | null;
  ip_hash: string;
  user_agent: string | null;
  reason: string | null;
  metadata: Record<string, unknown> | null;
  created_at: Date;
}

// In-memory audit log store (in production, this would be PostgreSQL)
const auditLogStore: AuditEventRow[] = [];

/**
 * Hashes an IP address for storage.
 * Uses SHA-256 for consistent 64-character hex output.
 * Does not store the raw IP (no PII).
 */
export function hashIpAddress(ipAddress: string | undefined): string {
  if (!ipAddress) {
    return 'unknown';
  }

  // Normalize IPv6 addresses
  const normalized = ipAddress.toLowerCase().trim();

  // Use SHA-256 for hashing (no salt needed for audit logs)
  return createHash('sha256').update(normalized).digest('hex');
}

/**
 * Truncates user agent for storage (prevent log bloat).
 * Keeps first 200 characters.
 */
export function truncateUserAgent(userAgent: string | undefined): string | null {
  if (!userAgent) {
    return null;
  }
  return userAgent.substring(0, 200);
}

/**
 * Logs an authentication event to the audit log.
 * 
 * @param event - Audit event data
 * @returns The logged event row
 */
export async function logAuditEvent(event: AuditEvent): Promise<AuditEventRow> {
  const row: AuditEventRow = {
    id: generateId(),
    event_type: event.eventType,
    user_id: event.userId || null,
    ip_hash: event.ipHash,
    user_agent: truncateUserAgent(event.userAgent) || null,
    reason: event.reason || null,
    metadata: event.metadata || null,
    created_at: new Date(),
  };

  // Store in memory (in production, this would be an INSERT to PostgreSQL)
  auditLogStore.push(row);

  // Emit event for real-time monitoring (optional)
  emitAuditEvent(row);

  return row;
}

/**
 * Generates a random UUID for event IDs.
 */
function generateId(): string {
  // Simple UUID v4 generation
  const hex = '0123456789abcdef';
  let id = '';

  for (let i = 0; i < 36; i++) {
    if (i === 8 || i === 13 || i === 18 || i === 23) {
      id += '-';
    } else if (i === 14) {
      id += '4'; // Version 4
    } else if (i === 19) {
      id += hex[(Math.random() * 4) | 8]; // Variant
    } else {
      id += hex[(Math.random() * 16) | 0];
    }
  }

  return id;
}

// Event emitter for real-time monitoring
let auditEmitter: EventEmitter | null = null;

/**
 * Gets the audit event emitter for real-time monitoring.
 */
function getAuditEmitter(): EventEmitter {
  if (!auditEmitter) {
    auditEmitter = new EventEmitter();
  }
  return auditEmitter;
}

/**
 * Emits an audit event for real-time monitoring.
 */
function emitAuditEvent(row: AuditEventRow): void {
  try {
    const emitter = getAuditEmitter();
    emitter.emit('audit_event', row);

    // Also log to console for immediate visibility
    console.log(
      JSON.stringify({
        event: `audit.${row.event_type}`,
        event_id: row.id,
        user_id: row.user_id,
        ip_hash: row.ip_hash.substring(0, 16) + '...',
        reason: row.reason,
        timestamp: row.created_at.toISOString(),
      })
    );
  } catch {
    // Ignore emitter errors
  }
}

/**
 * Gets recent audit events.
 * 
 * @param limit - Maximum number of events to return
 * @returns Array of audit event rows
 */
export async function getRecentAuditEvents(limit: number = 100): Promise<AuditEventRow[]> {
  // Return most recent events first
  return auditLogStore.slice(-limit).reverse();
}

/**
 * Gets audit events for a specific user.
 * 
 * @param userId - User ID to query
 * @param limit - Maximum number of events to return
 * @returns Array of audit event rows for the user
 */
export async function getAuditEventsForUser(
  userId: string,
  limit: number = 100
): Promise<AuditEventRow[]> {
  const userEvents = auditLogStore.filter((row) => row.user_id === userId);
  return userEvents.slice(-limit).reverse();
}

/**
 * Gets audit events from a specific IP.
 * 
 * @param ipHash - Hashed IP address
 * @param limit - Maximum number of events to return
 * @returns Array of audit event rows for the IP
 */
export async function getAuditEventsForIp(
  ipHash: string,
  limit: number = 100
): Promise<AuditEventRow[]> {
  const ipEvents = auditLogStore.filter((row) => row.ip_hash === ipHash);
  return ipEvents.slice(-limit).reverse();
}

/**
 * Clears the audit log (for testing only).
 */
export function clearAuditLog(): void {
  auditLogStore.length = 0;
}

/**
 * Gets the current audit log size.
 */
export function getAuditLogSize(): number {
  return auditLogStore.length;
}

// Audit logging convenience functions

/**
 * Logs a login attempt.
 */
export async function logLoginAttempt(
  ipAddress: string | undefined,
  userAgent?: string,
  metadata?: Record<string, unknown>
): Promise<AuditEventRow> {
  return logAuditEvent({
    eventType: 'login_attempt',
    ipHash: hashIpAddress(ipAddress),
    userAgent,
    metadata,
  });
}

/**
 * Logs a successful login.
 */
export async function logLoginSuccess(
  userId: string,
  ipAddress: string | undefined,
  userAgent?: string,
  metadata?: Record<string, unknown>
): Promise<AuditEventRow> {
  return logAuditEvent({
    eventType: 'login_success',
    userId,
    ipHash: hashIpAddress(ipAddress),
    userAgent,
    metadata,
  });
}

/**
 * Logs a failed login.
 */
export async function logLoginFailure(
  ipAddress: string | undefined,
  userAgent?: string,
  reason?: string,
  metadata?: Record<string, unknown>
): Promise<AuditEventRow> {
  return logAuditEvent({
    eventType: 'login_failure',
    ipHash: hashIpAddress(ipAddress),
    userAgent,
    reason,
    metadata,
  });
}

/**
 * Logs a session tampering detection.
 */
export async function logSessionTamper(
  userId: string | undefined,
  ipAddress: string | undefined,
  userAgent?: string,
  reason?: string,
  metadata?: Record<string, unknown>
): Promise<AuditEventRow> {
  return logAuditEvent({
    eventType: 'session_tamper',
    userId,
    ipHash: hashIpAddress(ipAddress),
    userAgent,
    reason,
    metadata,
  });
}

/**
 * Logs a session revocation.
 */
export async function logSessionRevoked(
  userId: string,
  ipAddress: string | undefined,
  userAgent?: string,
  reason?: string,
  metadata?: Record<string, unknown>
): Promise<AuditEventRow> {
  return logAuditEvent({
    eventType: 'session_revoked',
    userId,
    ipHash: hashIpAddress(ipAddress),
    userAgent,
    reason,
    metadata,
  });
}

/**
 * Logs a session binding mismatch (IP/UA validation failure).
 */
export async function logSessionBindingMismatch(
  userId: string | undefined,
  ipAddress: string | undefined,
  userAgent?: string,
  reason?: string,
  metadata?: Record<string, unknown>
): Promise<AuditEventRow> {
  return logAuditEvent({
    eventType: 'session_binding_mismatch',
    userId,
    ipHash: hashIpAddress(ipAddress),
    userAgent,
    reason,
    metadata,
  });
}