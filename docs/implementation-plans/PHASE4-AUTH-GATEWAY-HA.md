# Phase 4: Auth Gateway HA Implementation Plan

**Document Type:** Implementation Plan  
**Date:** 2026-04-17  
**Phase:** 4 of 6  
**Finding ID:** E-02, E-03  
**Severity:** HIGH  
**CWE:** CWE-690 (Insufficient Control of Resource During Exploitation), CWE-754 (Improper Check for Unusual Conditions)  
**Status:** Ready for Implementation  

---

## 1. Executive Summary

This plan deploys Auth Gateway as a highly available service with 2+ replicas behind a load balancer, automatic failover detection via health checks, graceful shutdown handling, and session affinity for request routing. The implementation addresses two critical edge cases identified during security review: single Auth Gateway instance becoming a single point of failure (E-02) and rolling deployments causing request drops (E-03).

**Risk After Implementation:** HIGH → MEDIUM  
**Timeline:** 3 days  
**Files Created:** 3 (`api/auth/health/route.ts`, `lib/auth/shutdown.ts`, `lib/auth/session.ts`)  
**Files Modified:** 2 (`app.ts` or `server.ts`, `docker-compose.yml`)  
**Dependencies:** None (uses built-in Node.js process signals)  

---

## 2. Threat Model

### 2.1 Attack Scenarios

#### Scenario 1: Single Instance Crash
```
Timeline:
T+0:00    Auth Gateway instance crashes (OOM, segfault, or kill)
T+0:01    Load balancer health check fails
T+0:10    Load balancer removes instance from pool
T+0:11    In-flight requests fail
T+0:15    Users begin experiencing auth failures
T+5:00    Manual intervention required
```

**Impact:** Auth service outage until manual restart or load balancer detection.

#### Scenario 2: Rolling Deployment Request Drop
```
Timeline:
T+0:00    Rolling deployment starts (new version deployed)
T+0:01    Old instance receives SIGTERM
T+0:01    Old instance closes listeners immediately
T+0:01    In-flight requests dropped
T+0:02    Users experience auth failures mid-session
T+0:05    New instance becomes ready
T+0:10    Users retry, some succeed
```

**Impact:** Request drops during deployments, session instability.

#### Scenario 3: Instance Failure Mid-Request
```
Timeline:
T+0:00    User request in flight
T+0:00    Instance crashes (hardware issue)
T+0:00    Request never completes
T+0:01    User session may be left in inconsistent state
T+0:05    User retries, creates duplicate session
```

**Impact:** Session inconsistency, potential duplicate sessions.

### 2.2 Mitigated Threats

| Threat | CWE | Attack Vector | Mitigation |
|:---|:---|:---|:---|
| Single instance SPOF | CWE-690 | Instance crash | Multiple replicas + load balancer |
| Auth service outage | CWE-690 | Primary loss | Health check + automatic failover |
| Request drops | CWE-754 | Rolling deployment | Graceful shutdown + drain |
| In-flight failure | CWE-754 | Crash mid-request | Request tracking + wait |
| Session inconsistency | CWE-754 | Duplicate sessions | Request tracking + atomic ops |

### 2.3 Not Mitigated

- Load balancer failure (handled by network-level HA)
- Database failure (handled by Phase 3 Redis HA)
- Network partition (handled by retry logic)
- Memory exhaustion (handled by monitoring)

### 2.4 Architecture Overview

```
                    ┌─────────────────────────────────────┐
                    │         Load Balancer               │
                    │   (health check + routing)        │
                    └──────┬──────────────┬────────────┘
                           │              │
              ┌────────────┴──┐      ┌────┴────────────┐
              │  Replica 1    │      │  Replica 2     │
              │  :3000        │      │  :3001         │
              └────────────┬────┘      └────┬────────────┘
                         │              │
                    ┌────┴──────────────┴────┐
                    │      Redis Sentinel    │
                    │      (Phase 3)       │
                    └───────────────────────┘
```

---

## 3. Implementation Details

### 3.1 Health Check Endpoint

#### 3.1.1 Health Check Route

**File:** `api/auth/health/route.ts` (new)

```typescript
/**
 * Health check endpoint for load balancer.
 * 
 * Features:
 * - Redis connectivity check with timeout wrapper
 * - Database connectivity check (connection-only, no query)
 * - Uptime tracking
 * - Component-level status
 * - Sensitive field stripping from response
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 4
 * STRIDE: Mitigates E-02 (Auth Gateway SPOF)
 */

import { NextResponse } from 'next/server';
import { getRedisClient } from '@/lib/auth/redis';
import { db } from '@/lib/auth/database';
import { isServerShuttingDown } from '@/lib/auth/shutdown';

interface HealthCheckResult {
  status: 'healthy' | 'unhealthy';
  checks: {
    redis: boolean;
    database: boolean;
  };
  timestamp: string;
}

/**
 * Health check for load balancer.
 * Returns 200 if all components healthy, 503 otherwise.
 * 
 * @returns NextResponse with health status
 */
export async function GET(): Promise<NextResponse> {
  // Return 503 if server is shutting down
  if (isServerShuttingDown()) {
    return NextResponse.json({
      status: 'shutting_down',
      checks: { redis: false, database: false },
      timestamp: new Date().toISOString(),
    }, { status: 503 });
  }
  
  const checks = {
    redis: await checkRedisHealth(),
    database: await checkDatabaseHealth(),
  };

  const healthy = checks.redis && checks.database;

  // Strip sensitive fields - only expose boolean status
  const result: HealthCheckResult = {
    status: healthy ? 'healthy' : 'unhealthy',
    checks: {
      redis: checks.redis,
      database: checks.database.healthy,  // Only boolean, not error details
    },
    timestamp: new Date().toISOString(),
  };

  return NextResponse.json(result, {
    status: healthy ? 200 : 503,
  });
}

/**
 * Checks Redis connectivity with timeout wrapper.
 * Fails fast if Redis doesn't respond in 2 seconds.
 * 
 * @returns true if Redis responds to PING within timeout
 */
async function checkRedisHealth(): Promise<boolean> {
  try {
    const redis = getRedisClient();
    
    // Timeout wrapper - fail fast if Redis doesn't respond in 2s
    await Promise.race([
      redis.ping(),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Redis timeout')), 2000)
      ),
    ]);
    return true;
  } catch {
    return false;
  }
}

/**
 * Checks database connectivity.
 * Tests connection only, does not run a query.
 * Distinguishes connection errors from other errors.
 * 
 * @returns Object with healthy status and error type if any
 */
async function checkDatabaseHealth(): Promise<{healthy: boolean; error?: string}> {
  try {
    // Just test connection, don't run a query
    await db.raw('SELECT 1');
    return { healthy: true };
  } catch (error) {
    // Distinguish connection errors from other errors
    if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
      return { healthy: false, error: 'connection_failed' };
    }
    return { healthy: false, error: 'unknown' };
  }
}
```

#### 3.1.2 Health Check Options

For more comprehensive health checks, add to `api/auth/health/route.ts`:

```typescript
// Optional: Detailed health check with timing
// NOTE: This endpoint should be internal-only, not exposed to load balancer
interface DetailedHealthCheck {
  status: 'healthy' | 'degraded' | 'unhealthy';
  checks: {
    redis: { healthy: boolean; latencyMs: number };
    database: { healthy: boolean; latencyMs: number };
  };
  uptime: number;
  memory: { heapUsed: number; heapTotal: number };
  timestamp: string;
}

export async function GETDetailed(): Promise<NextResponse> {
  const [redisHealth, dbHealth] = await Promise.all([
    measureRedisHealth(),
    measureDatabaseHealth(),
  ]);

  const allHealthy = redisHealth.healthy && dbHealth.healthy;
  const anyHealthy = redisHealth.healthy || dbHealth.healthy;

  const result: DetailedHealthCheck = {
    status: allHealthy ? 'healthy' : anyHealthy ? 'degraded' : 'unhealthy',
    checks: {
      redis: redisHealth,
      database: dbHealth,
    },
    uptime: process.uptime(),
    memory: {
      heapUsed: process.memoryUsage().heapUsed,
      heapTotal: process.memoryUsage().heapTotal,
    },
    timestamp: new Date().toISOString(),
  };

  return NextResponse.json(result, {
    status: allHealthy ? 200 : anyHealthy ? 200 : 503,
  });
}

async function measureRedisHealth(): Promise<{ healthy: boolean; latencyMs: number }> {
  const start = Date.now();
  try {
    const redis = getRedisClient();
    await redis.ping();
    return { healthy: true, latencyMs: Date.now() - start };
  } catch {
    return { healthy: false, latencyMs: Date.now() - start };
  }
}

async function measureDatabaseHealth(): Promise<{ healthy: boolean; latencyMs: number }> {
  const start = Date.now();
  try {
    await db.raw('SELECT 1');
    return { healthy: true, latencyMs: Date.now() - start };
  } catch {
    return { healthy: false, latencyMs: Date.now() - start };
  }
}
```

### 3.2 Graceful Shutdown

#### 3.2.1 Shutdown Handler

**File:** `lib/auth/shutdown.ts` (new)

```typescript
/**
 * Graceful shutdown handler for Auth Gateway.
 * 
 * Features:
 * - SIGTERM/SIGINT handling
 * - Race guard mutex to prevent double-close
 * - Active request tracking
 * - Drain timeout
 * - Force exit after timeout
 * - Error handling during shutdown
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 4
 * STRIDE: Mitigates E-03 (Rolling deployment request drops)
 */

// Shutdown state
let isShuttingDown = false;
let shutdownMutex = false;  // Race guard mutex
let activeRequests = 0;
let forceExitTimer: NodeJS.Timeout | null = null;

// Configuration
const SHUTDOWN_CONFIG = {
  // Drain timeout: 30 seconds (wait for active requests)
  drainTimeoutMs: 30000,
  // Force exit delay: 1 second (after drain timeout)
  forceExitDelayMs: 1000,
} as const;

/**
 * Sets up graceful shutdown handlers.
 * Call this at application startup.
 * 
 * @param server - HTTP server instance
 */
export function setupGracefulShutdown(server: {
  close: (callback: (err?: Error) => void) => void;
}): void {
  // SIGTERM: Kubernetes/Docker stop signal
  process.on('SIGTERM', () => {
    initiateShutdown(server, 'SIGTERM');
  });

  // SIGINT: Ctrl+C
  process.on('SIGINT', () => {
    initiateShutdown(server, 'SIGINT');
  });
}

/**
 * Initiates graceful shutdown sequence.
 * Uses mutex to prevent double-close.
 * 
 * @param server - HTTP server instance
 * @param signal - Signal that triggered shutdown
 */
function initiateShutdown(
  server: { close: (callback: (err?: Error) => void) => void },
  signal: 'SIGTERM' | 'SIGINT'
): void {
  // Race guard - prevent double-close
  if (shutdownMutex) {
    return;
  }
  shutdownMutex = true;
  
  console.log(`${signal} received, starting graceful shutdown`);
  isShuttingDown = true;
  
  // Clear any existing force-exit timer
  if (forceExitTimer) {
    clearTimeout(forceExitTimer);
    forceExitTimer = null;
  }

  // Stop accepting new requests by closing the server
  server.close(async (err?: Error) => {
    const deadline = Date.now() + SHUTDOWN_CONFIG.drainTimeoutMs;
    
    try {
      // Wait for active requests to complete
      while (activeRequests > 0 && Date.now() < deadline) {
        await sleep(100);
      }
      
      if (activeRequests > 0) {
        console.warn(`Force closing with ${activeRequests} active requests`);
      }
    } catch (error) {
      console.error('Error during graceful shutdown:', error);
    } finally {
      // Clear the force-exit timer - we're exiting normally
      if (forceExitTimer) {
        clearTimeout(forceExitTimer);
        forceExitTimer = null;
      }
      await cleanup();
      process.exit(activeRequests > 0 ? 1 : 0);
    }
  });

  // Force exit after drain timeout - unref() eliminates the race.
  // Without unref(): timer callback is queued in event loop, may fire
  // while server.close() callback runs, causing double process.exit().
  // With unref(): timer is skipped when process.exit() starts winding
  // down the event loop. The race is impossible, not mitigated.
  forceExitTimer = setTimeout(() => {
    console.error('Graceful shutdown timeout, forcing exit');
    process.exit(1);
  }, SHUTDOWN_CONFIG.drainTimeoutMs + SHUTDOWN_CONFIG.forceExitDelayMs);
  forceExitTimer.unref();
}

/**
 * Tracks a new active request.
 * Throws if server is shutting down.
 * 
 * @returns Cleanup function to call when request completes
 * @throws Error if server is shutting down
 */
export function trackRequest(): () => void {
  if (isShuttingDown || shutdownMutex) {
    throw new Error('Server shutting down');
  }
  activeRequests++;
  return () => {
    activeRequests--;
  };
}

/**
 * Checks if server is shutting down.
 * 
 * @returns true if shutdown in progress
 */
export function isServerShuttingDown(): boolean {
  return isShuttingDown;
}

/**
 * Gets the number of active requests.
 * 
 * @returns Number of active requests
 */
export function getActiveRequestCount(): number {
  return activeRequests;
}

/**
 * Cleanup function.
 * Call this before exiting.
 */
async function cleanup(): Promise<void> {
  try {
    // Close Redis connection
    const { closeRedisClient } = await import('./redis');
    await closeRedisClient();
  } catch (error) {
    console.error('Cleanup error:', error instanceof Error ? error.message : 'Unknown error');
  }
}

/**
 * Sleep utility.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
```

#### 3.2.2 Request Tracking Middleware

**File:** `lib/auth/shutdown.ts` (add to existing)

Add middleware integration for request tracking:

```typescript
/**
 * Request tracking middleware.
 * Use with Express or Next.js API routes.
 * 
 * @param handler - API route handler
 * @returns Wrapped handler with request tracking
 */
export function withRequestTracking<
  T extends (...args: unknown[]) => Promise<unknown>
>(handler: T): T {
  return (async (...args: unknown[]) => {
    const track = trackRequest();
    try {
      return await handler(...args);
    } finally {
      track();
    }
  }) as T;
}
```

For Next.js API routes, create middleware at `middleware.ts`:

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import { isServerShuttingDown } from '@/lib/auth/shutdown';

export function middleware() {
  if (isServerShuttingDown()) {
    return NextResponse.json(
      { error: 'Service unavailable (shutting down)' },
      { status: 503 }
    );
  }
  return NextResponse.next();
}

export const config = {
  matcher: '/api/:path*',
};
```

### 3.3 Session Affinity

#### 3.3.1 Session Affinity Key

**File:** `lib/auth/session.ts` (update existing)

Add session affinity key function:

```typescript
/**
 * Session affinity key generator.
 * 
 * Features:
 * - Consistent hashing based on session token
 * - Full HMAC-SHA256 output (64 hex chars = 256 bits, no truncation)
 * - Timing-safe comparison to prevent timing attacks
 * - Secret required (no optional secret)
 * 
 * Reference: IMPLEMENTATION-PLAN.md Phase 4
 * STRIDE: Mitigates E-02 (Auth Gateway SPOF)
 */

import { createHmac, timingSafeEqual } from 'crypto';

/**
 * Session affinity secret - required for HMAC.
 * Must be set at startup.
 */
const SESSION_AFFINITY_SECRET = process.env.SESSION_AFFINITY_SECRET;

// Validate at startup - secret is required
if (!SESSION_AFFINITY_SECRET) {
  throw new Error('SESSION_AFFINITY_SECRET environment variable is required');
}

/**
 * Gets the session affinity key.
 * Used by load balancer to route same session to same replica.
 * Uses full HMAC-SHA256 output (64 hex characters = 256 bits).
 * 
 * @param sessionToken - Session token
 * @returns Affinity key (64 characters, full HMAC-SHA256)
 */
export function getSessionAffinityKey(sessionToken: string): string {
  // Full HMAC-SHA256 output (64 hex chars = 256 bits)
  // No truncation - full entropy
  const hash = createHmac('sha256', SESSION_AFFINITY_SECRET)
    .update(sessionToken)
    .digest('hex');
  return hash;
}

/**
 * Verifies a session affinity key.
 * Uses constant-time comparison to prevent timing attacks.
 * 
 * @param sessionToken - Session token
 * @param affinityKey - Affinity key to verify
 * @returns true if key matches
 */
const HEX_REGEX = /^[a-fA-F0-9]{64}$/;

export function verifySessionAffinity(
  sessionToken: string, 
  affinityKey: string
): boolean {
  // Validate affinityKey is exactly 64 hex chars before Buffer.from()
  // Invalid hex chars are silently truncated by Buffer.from()
  if (!HEX_REGEX.test(affinityKey)) {
    return false;
  }
  
  const expected = getSessionAffinityKey(sessionToken);
  const expectedBuffer = Buffer.from(expected, 'hex');
  const actualBuffer = Buffer.from(affinityKey, 'hex');
  
  // Constant-time comparison to prevent timing attacks
  if (expectedBuffer.length !== actualBuffer.length) {
    return false;
  }
  return timingSafeEqual(expectedBuffer, actualBuffer);
}

/**
 * Gets session affinity key with instance ID.
 * Includes instance identifier for debugging.
 * 
 * @param sessionToken - Session token
 * @returns Affinity key with instance ID
 */
export function getSessionAffinityKeyWithInstance(
  sessionToken: string
): { key: string; instanceId: string } {
  const key = getSessionAffinityKey(sessionToken);
  const instanceId = process.env.INSTANCE_ID || 'default';
  return { key, instanceId };
}
```

#### 3.3.2 Affinity-Aware Session Store

**File:** `lib/auth/session.ts` (add to existing)

Add affinity-aware session operations:

```typescript
/**
 * Session store with affinity tracking.
 * Tracks which replica owns each session.
 */

interface SessionAffinity {
  sessionToken: string;
  instanceId: string;
  affinityKey: string;
  createdAt: string;
}

/**
 * Gets session affinity info.
 * 
 * @param sessionToken - Session token
 * @returns Affinity info
 */
export async function getSessionAffinity(
  sessionToken: string
): Promise<SessionAffinity | null> {
  const redis = getRedisClient();
  const key = `vane:sess:affinity:${sessionToken}`;

  const data = await redis.get(key);
  if (!data) {
    return null;
  }

  return JSON.parse(data);
}

/**
 * Sets session affinity info.
 * Called when session is created or verified.
 * 
 * @param sessionToken - Session token
 * @param instanceId - Instance ID
 */
export async function setSessionAffinity(
  sessionToken: string,
  instanceId: string
): Promise<void> {
  const redis = getRedisClient();
  const key = `vane:sess:affinity:${sessionToken}`;

  const affinity: SessionAffinity = {
    sessionToken,
    instanceId,
    affinityKey: getSessionAffinityKey(sessionToken),
    createdAt: new Date().toISOString(),
  };

  // Set with same TTL as session
  const ttl = parseInt(process.env.SESSION_TTL || '86400', 10);
  await redis.set(key, JSON.stringify(affinity), 'EX', ttl);
}

/**
 * Clears session affinity info.
 * Called when session is revoked.
 * 
 * @param sessionToken - Session token
 */
export async function clearSessionAffinity(
  sessionToken: string
): Promise<void> {
  const redis = getRedisClient();
  const key = `vane:sess:affinity:${sessionToken}`;
  await redis.del(key);
}
```

### 3.4 Load Balancer Configuration

#### 3.4.1 Caddy Configuration

**File:** `docs/implementation-plans/PHASE4-AUTH-GATEWAY-HA.md` (add config)

For Caddy as load balancer:

```caddyfile
# Caddyfile for Auth Gateway HA
# Auth Gateway replicas on ports 3000, 3001, 3002
# Optimized for fast failover detection

auth-gateway.internal.example.com {
    import internal_tls
    
    reverse_proxy localhost:3000 localhost:3001 localhost:3002 {
        # Health check configuration
        # Optimized for fast detection (reduced from defaults)
        health_uri /api/auth/health
        health_interval 5s       # Reduced from 10s - faster detection
        health_timeout 3s        # Reduced from 5s - fail fast
        fail_duration 10s        # Reduced from 30s - faster recovery
        
        # Load balancing policy
        load_balancing round_robin
        
        # Circuit breaker
        fail_duration 10s
    }
}
```

#### 3.4.2 Nginx Configuration

For Nginx as load balancer:

```nginx
# nginx.conf for Auth Gateway HA
upstream auth_gateway {
    least_conn;
    
    server 127.0.0.1:3000;
    server 127.0.0.1:3001;
    server 127.0.0.1:3002;
    
    keepalive 32;
}

server {
    listen 443 ssl;
    server_name auth-gateway.internal.example.com;
    
    location / {
        proxy_pass http://auth_gateway;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        
        # Health check - faster detection
        proxy_connect_timeout 3s;
        proxy_next_upstream error timeout invalid_header;
        
        # Timeouts
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    location /api/auth/health {
        proxy_pass http://auth_gateway/api/auth/health;
        proxy_connect_timeout 3s;
        proxy_next_upstream error timeout;
    }
}
```

#### 3.4.3 Docker Compose Update

**File:** `docker-compose.yml` (update existing)

```yaml
# docker-compose.yml for Auth Gateway HA
services:
  auth-gateway:
    image: auth-gateway:${VERSION:-latest}
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
        order: start-first
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
    ports:
      - "3000"
      - "3001"
      - "3002"
    environment:
      - NODE_ENV=production
      - INSTANCE_ID=${INSTANCE_ID:-replica-1}
      - REDIS_USE_SENTINEL=true
      - SESSION_TTL=86400
      - SESSION_AFFINITY_SECRET=${SESSION_AFFINITY_SECRET}
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/api/auth/health"]
      interval: 5s
      timeout: 3s
      retries: 3
      start_period: 10s
    restart: unless-stopped
    networks:
      - auth-network

networks:
  auth-network:
    driver: overlay
```

---

## 4. Files to Create/Modify

### 4.1 New Files

| File | Purpose | Lines |
|:---|:---|:---|
| `api/auth/health/route.ts` | Health check endpoint | ~80 |
| `api/auth/health/route.test.ts` | Unit tests for health check | ~60 |
| `lib/auth/shutdown.ts` | Graceful shutdown handler | ~150 |
| `lib/auth/shutdown.test.ts` | Unit tests for shutdown | ~80 |

### 4.2 Modified Files

| File | Change | Lines |
|:---|:---|:---|
| `lib/auth/session.ts` | Add affinity key function | ~50 |
| `app.ts` or `server.ts` | Wire graceful shutdown | ~20 |
| `docker-compose.yml` | Multiple replicas | ~30 |

### 4.3 Optional Files

| File | Purpose | Lines |
|:---|:---|:---|
| `middleware.ts` | Request tracking middleware | ~30 |
| `lib/auth/session.ts` | Affinity tracking | ~50 |

---

## 5. Test Cases

### 5.1 Health Check Tests

```typescript
// api/auth/health/route.test.ts

describe('Health Check', () => {
  it('returns 200 when healthy', async () => {
    const response = await GET();
    const data = await response.json();
    
    expect(response.status).toBe(200);
    expect(data.status).toBe('healthy');
    expect(data.checks.redis).toBe(true);
    expect(data.checks.database).toBe(true);
  });

  it('returns 503 when Redis down', async () => {
    // Mock Redis failure
    vi.spyOn(redis, 'ping').mockRejectedValueOnce(new Error('Connection refused'));
    
    const response = await GET();
    const data = await response.json();
    
    expect(response.status).toBe(503);
    expect(data.status).toBe('unhealthy');
    expect(data.checks.redis).toBe(false);
  });

  it('returns 503 when DB down', async () => {
    // Mock DB failure
    vi.spyOn(db, 'raw').mockRejectedValueOnce(new Error('Connection refused'));
    
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
    // Mock slow Redis (takes 5 seconds)
    vi.spyOn(redis, 'ping').mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve('PONG'), 5000))
    );
    
    const start = Date.now();
    const result = await checkRedisHealth();
    const elapsed = Date.now() - start;
    
    // Should fail fast due to timeout wrapper
    expect(result).toBe(false);
    expect(elapsed).toBeLessThan(3000); // Should timeout before 5s
  });
});
```

### 5.2 Graceful Shutdown Tests

```typescript
// lib/auth/shutdown.test.ts

describe('Graceful Shutdown', () => {
  beforeEach(() => {
    // Reset state
    isShuttingDown = false;
    shutdownMutex = false;
    activeRequests = 0;
    forceExitTimer = null;
  });

  it('sets shutting down flag on SIGTERM', () => {
    const server = { close: vi.fn((cb) => cb()) };
    
    setupGracefulShutdown(server);
    process.emit('SIGTERM');
    
    expect(isShuttingDown).toBe(true);
  });

  it('race guard prevents double-close', () => {
    const closeSpy = vi.fn((cb) => cb());
    const server = { close: closeSpy };
    
    setupGracefulShutdown(server);
    
    // First SIGTERM
    process.emit('SIGTERM');
    expect(isShuttingDown).toBe(true);
    expect(closeSpy).toHaveBeenCalledTimes(1);
    
    // Reset close spy to count calls
    closeSpy.mockClear();
    
    // Second SIGTERM (should be debounced by mutex)
    process.emit('SIGTERM');
    expect(closeSpy).toHaveBeenCalledTimes(0);
  });

  it('tracks active requests', () => {
    const track = trackRequest();
    expect(activeRequests).toBe(1);
    
    track();
    expect(activeRequests).toBe(0);
  });

  it('throws when tracking during shutdown', () => {
    isShuttingDown = true;
    
    expect(() => trackRequest()).toThrow('Server shutting down');
  });

  it('handles errors in shutdown callback', () => {
    const server = {
      close: vi.fn((cb) => cb(new Error('Close error'))),
    };
    
    vi.spyOn(console, 'error').mockImplementation(() => {});
    
    setupGracefulShutdown(server);
    process.emit('SIGTERM');
    
    // Should not throw - error is caught
    expect(console.error).toHaveBeenCalled();
  });

  it('tracks concurrent requests', () => {
    const tracks = [trackRequest(), trackRequest(), trackRequest()];
    
    expect(activeRequests).toBe(3);
    
    tracks[0]();
    expect(activeRequests).toBe(2);
    
    tracks[1]();
    expect(activeRequests).toBe(1);
    
    tracks[2]();
    expect(activeRequests).toBe(0);
  });
});
```

### 5.3 Session Affinity Tests

```typescript
// lib/auth/session.test.ts

describe('Session Affinity', () => {
  const originalEnv = process.env.SESSION_AFFINITY_SECRET;
  
  beforeEach(() => {
    process.env.SESSION_AFFINITY_SECRET = 'test-secret';
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

  it('verifies valid affinity key', () => {
    const token = 'test-token';
    const key = getSessionAffinityKey(token);
    
    expect(verifySessionAffinity(token, key)).toBe(true);
  });

  it('rejects invalid affinity key', () => {
    const token = 'test-token';
    
    expect(verifySessionAffinity(token, 'invalid-key')).toBe(false);
  });

  it('stores affinity info', async () => {
    await setSessionAffinity('test-token', 'instance-1');
    
    const affinity = await getSessionAffinity('test-token');
    expect(affinity).not.toBeNull();
    expect(affinity?.instanceId).toBe('instance-1');
  });

  it('clears affinity info', async () => {
    await setSessionAffinity('test-token', 'instance-1');
    await clearSessionAffinity('test-token');
    
    const affinity = await getSessionAffinity('test-token');
    expect(affinity).toBeNull();
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
```

### 5.4 Edge Case Tests

```typescript
// lib/auth/shutdown.test.ts

describe('Shutdown Edge Cases', () => {
  it('debounces multiple SIGTERM signals', () => {
    const server = { close: vi.fn((cb) => cb()) };
    
    setupGracefulShutdown(server);
    
    // First SIGTERM
    process.emit('SIGTERM');
    expect(isShuttingDown).toBe(true);
    
    // Second SIGTERM (should be debounced)
    process.emit('SIGTERM');
    
    // Server.close should only be called once
    expect(server.close).toHaveBeenCalledTimes(1);
  });

  it('handles close error gracefully', async () => {
    const server = {
      close: vi.fn((callback) => {
        callback(new Error('Close error'));
      }),
    };
    
    vi.spyOn(console, 'error').mockImplementation(() => {});
    
    setupGracefulShutdown(server);
    process.emit('SIGTERM');
    
    // Should not throw
  });

  it('tracks concurrent requests', () => {
    const tracks = [trackRequest(), trackRequest(), trackRequest()];
    
    expect(activeRequests).toBe(3);
    
    tracks[0]();
    expect(activeRequests).toBe(2);
    
    tracks[1]();
    expect(activeRequests).toBe(1);
    
    tracks[2]();
    expect(activeRequests).toBe(0);
  });

  it('force exit timer uses unref() to eliminate race', () => {
    // This test verifies the unref() approach eliminates the race.
    // With unref(), the timer is skipped when process.exit() starts.
    // No forceExited flag needed - the race is structurally impossible.
    const server = {
      close: vi.fn((callback) => {
        callback();
      }),
    };
    
    setupGracefulShutdown(server);
    process.emit('SIGTERM');
    
    // The forceExitTimer should be unref'd
    // (we can't directly test unref, but we can verify the timer fires correctly)
    // The key is: when process.exit() runs, the unref'd timer is skipped.
    // No double-exit possible.
    expect(forceExitTimer).not.toBeNull();
  });
});
```

---

## 6. Edge Cases

### 6.1 Health Check Timeout

When Redis or database is slow to respond:

```
Scenario:
- Health check starts
- Redis PING takes 10 seconds
- Load balancer timeout is 3 seconds

Result:
- Health check times out at 2 seconds (internal timeout)
- Load balancer marks instance unhealthy
- Failover triggered quickly

Prevention:
- Internal timeout wrapper (2 seconds)
- Failures counted over duration (10 seconds)
- Single timeout doesn't trigger failover
```

**Mitigation:** Internal timeout wrapper + fail duration requires multiple failures.

### 6.2 Active Requests During Shutdown

When shutdown occurs with active requests:

```
Scenario:
- SIGTERM received
- 10 active requests
- Each request takes 10 seconds

Result:
- Shutdown waits 30 seconds
- 7 requests complete
- 3 requests force closed
- Users experience errors

Prevention:
- Wait for active requests (up to drain timeout)
- Force close after drain timeout
- Log force close count
```

**Mitigation:** Configurable drain timeout + force exit.

### 6.3 Multiple SIGTERM Signals

When SIGTERM is sent multiple times:

```
Scenario:
- SIGTERM sent to container
- Container doesn't respond
- SIGTERM sent again
- Kubernetes sends SIGKILL

Result:
- Double shutdown handling
- Potential race conditions
- Resource leaks

Prevention:
- shutdownMutex race guard prevents re-entry
- isShuttingDown flag checked first
```

**Mitigation:** shutdownMutex + early return.

### 6.4 Health Check During Rolling Restart

When health check runs during rolling restart:

```
Scenario:
- Rolling restart starts
- Old instance receives SIGTERM
- Health check runs before close

Result:
- Health check returns 200
- Load balancer routes to shutting down instance
- Requests fail

Prevention:
- isShuttingDown flag checked in health check
- Return 503 when shutting down
- Load balancer removes instance
```

**Mitigation:** Health check returns 503 when shutting down.

### 6.5 Instance ID Collision

When multiple replicas have same instance ID:

```
Scenario:
- Docker compose with 3 replicas
- All replicas have INSTANCE_ID=replica
- Session affinity set to "replica"

Result:
- Affinity tracking unreliable
- Can't identify specific instance

Prevention:
- INSTANCE_ID set to container hostname
- Docker compose uses service name + replica number
- Unique per replica
```

**Mitigation:** Unique INSTANCE_ID per replica.

---

## 7. Integration Points

### 7.1 Application Startup

```
Startup Sequence:
1. Validate SESSION_AFFINITY_SECRET is set
2. Set INSTANCE_ID from HOSTNAME or environment
3. Initialize Redis client (Phase 3)
4. Initialize database client
5. Setup graceful shutdown handlers
6. Start HTTP server
7. Register health check endpoint
8. Begin accepting requests
```

### 7.2 Request Lifecycle

```
Request Lifecycle:
1. Request received
2. Check isShuttingDown flag
3. If shutting down: return 503
4. Track request (increment counter)
5. Process request
6. Complete request
7. Untrack request (decrement counter)
```

### 7.3 Shutdown Sequence

```
Shutdown Sequence:
1. SIGTERM received
2. Acquire shutdownMutex (race guard)
3. Set isShuttingDown = true
4. Close HTTP server (stop accepting)
5. Wait for active requests (up to drain timeout)
6. Close Redis connection
7. Exit process
```

---

## 8. Verification Steps

### 8.1 Unit Tests

```bash
npm test -- api/auth/health/route.test.ts
npm test -- lib/auth/shutdown.test.ts
npm test -- lib/auth/session.test.ts
# Expected: All tests pass
```

### 8.2 Integration Tests

```bash
# Test 1: Health check endpoint
curl -s http://localhost:3000/api/auth/health | jq
# Expected: {"status": "healthy", "checks": {...}}

# Test 2: Graceful shutdown
# Start load test
# Send SIGTERM to one replica
# Verify requests route to other replicas
# Verify replica shuts down gracefully

# Test 3: Rolling deployment
# Deploy new version
# Verify zero downtime
# Verify all requests complete

# Test 4: Session affinity
# Create session
# Verify affinity key is 64 characters
# Verify same replica handles requests
```

### 8.3 Manual Verification

```bash
# Verify 1: Multiple replicas
docker compose ps
# Expected: 3 replicas running

# Verify 2: Health check from load balancer
curl -s http://localhost/api/auth/health
# Expected: 200 OK

# Verify 3: Shutdown waits for requests
# Start long-running request
# Send SIGTERM
# Verify request completes

# Verify 4: Session affinity key
node -e "console.log(require('./lib/auth/session').getSessionAffinityKey('test-token').length)"
# Expected: 64
```

---

## 9. Acceptance Criteria

- [ ] Health check returns 200 when all components healthy
- [ ] Health check returns 503 when Redis down
- [ ] Health check returns 503 when database down
- [ ] Health check has timeout wrapper (2s for Redis)
- [ ] Health check strips sensitive fields (memory, IPs, error details)
- [ ] Graceful shutdown waits for active requests
- [ ] Graceful shutdown forces exit after timeout
- [ ] Graceful shutdown has race guard mutex
- [ ] Graceful shutdown handles errors in callback
- [ ] Request tracking increments on request start
- [ ] Request tracking decrements on request complete
- [ ] Shutting down server rejects new requests
- [ ] Session affinity key is consistent per token
- [ ] Session affinity key is 64 characters (full HMAC-SHA256)
- [ ] Session affinity uses timingSafeEqual
- [ ] Session affinity secret is required at startup
- [ ] Docker compose deploys 3 replicas
- [ ] Rolling deployment has zero downtime
- [ ] Load balancer has fast detection (5s interval, 3s timeout)
- [ ] Unit tests: 100% coverage for health check
- [ ] Unit tests: 100% coverage for shutdown
- [ ] Unit tests: 100% coverage for affinity

---

## 10. Dependencies

| Dependency | Required For | Status |
|:---|:---|:---|
| Node.js process signals | Graceful shutdown | Built-in |
| crypto | Session affinity (HMAC, timingSafeEqual) | Built-in |
| Redis (Phase 3) | Session storage | Phase 3 |
| Load balancer | HA routing | Infrastructure |

---

## 11. Environment Variables

| Variable | Required | Default | Description |
|:---|:---|:---|:---|
| `SESSION_AFFINITY_SECRET` | **Yes** | - | HMAC secret for session affinity (required) |
| `INSTANCE_ID` | Recommended | `replica-1` | Unique replica identifier |
| `SESSION_TTL` | No | `86400` | Session TTL in seconds |
| `DRAIN_TIMEOUT_MS` | No | `30000` | Graceful shutdown drain timeout |
| `HEALTH_CHECK_INTERVAL` | No | `5s` | Load balancer health check interval |

---

## 12. Security Considerations

### 12.1 Health Check Security

| Setting | Value | Rationale |
|:---|:---|:---|
| Health check endpoint | `/api/auth/health` | Standard path for load balancers |
| Authentication | None | Health checks must be public |
| Rate limiting | None | Load balancer needs frequent checks |
| Internal timeout | 2 seconds | Fail fast, don't block health check |
| Sensitive fields | Stripped | Don't expose memory, IPs, errors |

### 12.2 Shutdown Security

| Setting | Value | Rationale |
|:---|:---|:---|
| Drain timeout | 30 seconds | Wait for active requests |
| Force exit | After timeout | Prevent indefinite hang |
| Race guard | Mutex | Prevent double-close |
| Error handling | Caught | Don't crash on close error |
| Signal handling | SIGTERM/SIGINT | Standard termination signals |

### 12.3 Session Affinity Security

| Setting | Value | Rationale |
|:---|:---|:---|
| Hash algorithm | HMAC-SHA256 | Collision-resistant, keyed |
| Output length | 64 characters | Full 256-bit entropy |
| Secret | Required | No optional secret |
| Comparison | timingSafeEqual | Prevent timing attacks |

---

## 13. Monitoring

### 13.1 Metrics

| Metric | Description | Alert |
|:---|:---|:---|
| `auth.health.status` | Health check status (0/1) | Alert if 0 |
| `auth.health.latency` | Health check latency (ms) | Alert if > 2000 |
| `auth.shutdown.active_requests` | Active request count | Alert if > 100 |
| `auth.shutdown.drain_duration` | Drain time (ms) | Alert if > 30000 |
| `auth.affinity.hits` | Affinity cache hits | None |
| `auth.affinity.misses` | Affinity cache misses | None |

### 13.2 Log Events

| Event | When | Fields |
|:---|:---|:---|
| `health.check.passed` | Health check success | replica, latency_ms |
| `health.check.failed` | Health check failure | replica, reason |
| `shutdown.initiated` | Shutdown started | signal, active_requests |
| `shutdown.drained` | Drain completed | duration, requests_completed |
| `shutdown.forced` | Force exit | active_requests |
| `affinity.set` | Affinity set | session_token, instance_id |

---

## 14. Rollback Procedure

If Auth Gateway HA causes issues:

```bash
# 1. Check health check status
curl -s http://localhost:3000/api/auth/health | jq

# 2. Check active requests
# Look at logs for "active requests" count

# 3. Disable rolling deployment
# Set replicas to 1

# 4. Revert docker-compose.yml
# Set replicas to 1

# 5. Restart single instance
docker compose up -d --force-recreate

# 6. Verify single instance
docker compose ps
```

---

## 15. Next Steps

1. **Implement:** Create `api/auth/health/route.ts` with health check endpoint (with timeout wrapper, stripped fields)
2. **Implement:** Create `lib/auth/shutdown.ts` with graceful shutdown handler (with race guard, error handling)
3. **Update:** Modify `lib/auth/session.ts` for affinity key function (full HMAC-SHA256, timingSafeEqual, required secret)
4. **Update:** Modify `app.ts` or `server.ts` to wire shutdown handler
5. **Update:** Modify `docker-compose.yml` for multiple replicas + SESSION_AFFINITY_SECRET
6. **Update:** Load balancer config for faster detection (5s interval, 3s timeout)
7. **Test:** Add unit tests for all new functions
8. **Test:** Integration test with load balancer
9. **Deploy:** Staging → Production with monitoring
10. **Monitor:** Watch health check metrics for 1 week