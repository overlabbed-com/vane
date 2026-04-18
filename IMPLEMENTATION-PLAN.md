# Vane Authentication Security Implementation Plan

**Document Type:** Unified Implementation Plan  
**Date:** 2026-04-17  
**Synthesizes:** Worker (Round 1), Architect (Round 2), Reviewer (Round 2)  
**Status:** FINAL — Ready for Implementation  

---

## 1. Executive Summary

This plan synthesizes three independent security reviews into a unified implementation roadmap for the Vane authentication layer. The plan addresses four critical vulnerabilities (F-01 through F-04) plus five edge-case mitigations identified by the critical reviewer.

**Overall Risk:** CRITICAL → MEDIUM (after implementation)  
**Timeline:** 6 weeks (phased, with 2-week shadow period)  
**Implementation Scope:** 3 files, ~400 lines  

---

## 2. Agreed Findings (All 3 Agents)

### 2.1 Critical Vulnerabilities

| ID | Finding | Severity | CVSS | CWE | Agent Agreement |
|:---|:---|:---|:---|:---|:---|
| **F-01** | Authentication Bypass (email-only login) | CRITICAL | 10.0 | CWE-306 | ✅ Worker ✅ Architect ✅ Reviewer |
| **F-02** | Plaintext Token Storage | CRITICAL | 9.8 | CWE-916 | ✅ Worker ✅ Architect ✅ Reviewer |
| **F-03** | User Enumeration | HIGH | 7.5 | CWE-204 | ✅ Worker ✅ Architect ✅ Reviewer |
| **F-04** | Log-based Enumeration Leak | MEDIUM | 6.5 | CWE-532 | ✅ Worker ✅ Architect ✅ Reviewer |

### 2.2 Edge Cases (Reviewer-Only)

| ID | Finding | Risk | Mitigation Required |
|:---|:---|:---|:---|
| **E-01** | Race condition in Redis migration (split-brain) | HIGH | Distributed lock + dual-write period |
| **E-02** | Argon2id DoS vector (memory exhaustion) | HIGH | Cost parameters bounded + monitoring |
| **E-03** | Account lockout enumeration side-channel | MEDIUM | Constant-time lockout response |
| **E-04** | Auth Gateway SPOF | HIGH | HA deployment + failover |
| **E-05** | Session fixation on auth | MEDIUM | Session regeneration post-auth |
| **E-06** | Rate limit too aggressive (1 req/min/IP) | MEDIUM | 5 req/min/IP with burst allowance |

---

## 3. Technology Decisions with Rationale

### 3.1 Cryptographic Choices

| Component | Decision | Rationale | Alternative Considered |
|:---|:---|:---|:---|
| **Password Hashing** | Argon2id (t=3, m=64MB, p=4) | Memory-hard, side-channel resistant, NIST recommended | bcrypt (weaker), scrypt (higher memory) |
| **Token Derivation** | HMAC-SHA256 | Fast, deterministic, key-extractable | BLAKE3 (not key-extractable) |
| **Session Token** | 256-bit random + HMAC verification | Token never stored, only verified | Raw token storage (F-02) |

**Argon2id Cost Bounding (E-02 Mitigation):**
- Time parameter: 3 iterations (fixed, not configurable by user)
- Memory: 64MB (hard cap prevents exhaustion)
- Parallelism: 4 (bounded)
- No user-controlled cost parameters in API

### 3.2 Storage Choices

| Component | Decision | Rationale | Alternative Considered |
|:---|:---|:---|:---|
| **Session Store** | Redis with Sentinel failover | Sub-ms latency, TTL support, HA | PostgreSQL (slower), in-memory (no HA) |
| **User Database** | PostgreSQL (existing) | Existing infrastructure | Unchanged |
| **Audit Log** | Structured JSON to Splunk | Compliance, correlation | File-based (insufficient) |

### 3.3 Architecture Choices

| Component | Decision | Rationale | Alternative Considered |
|:---|:---|:---|:---|
| **Auth Gateway** | Dedicated microservice | Single responsibility, independent scaling | Monolith (coupled) |
| **Rate Limiting** | Sliding window (Redis) | Smooth, memory-efficient | Fixed window (bursty) |
| **HA Strategy** | Active-passive Redis Sentinel | Automatic failover, simple | Multi-master (complex) |

---

## 4. Implementation Phases

### Phase 0: Emergency Stop-Gap (0-24 Hours)
**Goal:** Stop active exploitation immediately.

```
Steps:
1. [ ] Add feature flag AUTH_EMAIL_ONLY_ENABLED=false
2. [ ] Require password OR API key for all login attempts
3. [ ] Force-rotate all active sessions (delete all Redis keys with prefix "sess:")
4. [ ] Add emergency rate limit: 10 req/min/IP (temporary, will adjust in Phase 2)
5. [ ] Verify: Login without password returns 401, not 500
```

**Verification:**
```bash
curl -X POST https://vane/auth/login -d '{"email":"test@example.com"}'
# Expected: 401 INVALID_REQUEST (not 500, not 200 with session)
```

---

### Phase 1: Core Authentication (24-72 Hours)
**Goal:** Implement secure password and token verification.

```
Files Modified:
- vane/api/auth/login/route.ts
- vane/lib/auth/verify.ts
- vane/lib/database/users.ts

Steps:
1. [ ] Add argon2id password hashing (import argon2, configure bounds)
2. [ ] Add password verification with constant-time comparison
3. [ ] Add HMAC-SHA256 session token derivation
4. [ ] Replace in-memory sessions with Redis client
5. [ ] Add session TTL (15 minutes, sliding refresh)
6. [ ] Standardize error responses (same 401 for user not found + wrong password)
7. [ ] Add PII redaction to console.error logging
8. [ ] Add unit tests for verifySession, createSession
```

**Key Code Changes:**

```typescript
// verify.ts - New session creation with HMAC derivation
import { createHmac } from 'crypto';
import argon2 from 'argon2';

const SESSION_SECRET = process.env.SESSION_SECRET!; // 256-bit key from env
const SESSION_TTL_MS = 15 * 60 * 1000; // 15 minutes

export async function createSession(userId: string): Promise<Session> {
  const rawToken = randomBytes(32).toString('hex');
  const token = createHmac('sha256', SESSION_SECRET).update(rawToken).digest('hex');
  const createdAt = new Date();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);

  const session: Session = {
    token, // Stored token is HMAC, not raw
    userId,
    createdAt,
    expiresAt,
    revoked: false,
  };

  await redis.setex(`sess:${token}`, SESSION_TTL_MS / 1000, JSON.stringify(session));
  return { ...session, token: rawToken }; // Return raw to client once
}

export async function verifySession(rawToken: string): Promise<Session | null> {
  const token = createHmac('sha256', SESSION_SECRET).update(rawToken).digest('hex');
  const data = await redis.get(`sess:${token}`);
  if (!data) return null;

  const session = JSON.parse(data);
  if (session.revoked || new Date() > new Date(session.expiresAt)) {
    await redis.del(`sess:${token}`);
    return null;
  }
  return session;
}
```

**Verification:**
```bash
# Test 1: Login with correct password returns session
curl -X POST https://vane/auth/login \
  -d '{"email":"user@example.com","password":"correct"}'
# Expected: 200 with session token (raw, one-time display)

# Test 2: Login with wrong password returns same error as user not found
curl -X POST https://vane/auth/login \
  -d '{"email":"user@example.com","password":"wrong"}'
# Expected: 401 INVALID_CREDENTIALS (same as non-existent user)

# Test 3: Session token is HMAC-derivable only
# Verify raw token cannot be used directly in Redis
```

---

### Phase 2: Defense in Depth (Week 1-2)
**Goal:** Layered security, rate limiting, audit trail.

```
Steps:
1. [ ] Implement sliding window rate limiting (Redis)
   - 5 req/min/IP baseline
   - Burst allowance: 3x for 10 seconds after idle
   - NAT exemption: Allow 3 concurrent sessions per IP

2. [ ] Add account lockout (mitigates E-03)
   - Track failed attempts in Redis (key: "fail:{email}")
   - After 5 failed: 15-minute lockout
   - Response: Same 401 for lockout + wrong password (no enumeration)
   - Lockout releases automatically after TTL

3. [ ] Add session regeneration post-auth (mitigates E-05)
   - On successful login: Create new session, revoke old if exists
   - Include X-Session-Token header (raw token, one-time)

4. [ ] Add audit trail to Splunk
   - Event: auth.login.attempt, auth.login.success, auth.login.failure
   - Fields: timestamp, email_hash (not email), ip, user_agent, reason
   - No PII in logs

5. [ ] Redis Sentinel failover (mitigates E-04)
   - Primary + 2 replicas
   - Automatic failover on primary loss
   - Client-side redirect to new primary

6. [ ] Add Argon2id monitoring (mitigates E-02)
   - Alert if hash time > 2 seconds
   - Metrics: auth.password.hash_time_ms
```

**Rate Limit Configuration (E-06 Resolution):**
```typescript
const RATE_LIMIT = {
  baseline: '5 req/min/IP',
  burst: {
    requests: 15,
    window: '10 seconds',
    afterIdle: true
  },
  natExemption: {
    maxSessions: 3,
    window: '1 hour'
  }
};
```

**Verification:**
```bash
# Test 1: Rate limit enforced
for i in {1..6}; do curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST https://vane/auth/login \
  -d '{"email":"user@example.com","password":"wrong"}'; done
# Expected: 200,200,200,200,200,429 (5 allowed, 6th rejected)

# Test 2: Lockout after 5 failures
# After 5 failures, same 401 response (no lockout indication)
curl -X POST https://vane/auth/login \
  -d '{"email":"user@example.com","password":"wrong"}'
# Expected: 401 INVALID_CREDENTIALS (no indication of lockout)

# Test 3: Session regeneration
# Login twice, first token should be revoked
curl -X POST https://vane/auth/login \
  -d '{"email":"user@example.com","password":"correct"}'
# First token should not work after second login
```

---

### Phase 3: Redis Migration with Split-Brain Protection (Week 2-3)
**Goal:** Migrate from in-memory to Redis without consistency gaps.

```
Steps (Mitigates E-01):
1. [ ] Deploy Redis Sentinel cluster (3 nodes)
2. [ ] Run dual-write period: Write to both in-memory + Redis
3. [ ] Verify data consistency between stores
4. [ ] Cutover: Read from Redis only
5. [ ] Remove in-memory store code
6. [ ] Run 2-week shadow period (Architect recommendation)
```

**Distributed Lock Implementation:**
```typescript
// Prevent split-brain during migration
const MIGRATION_LOCK = 'migration:in-progress';
const LOCK_TTL = '30 seconds';

async function acquireMigrationLock(): Promise<boolean> {
  const result = await redis.set(MIGRATION_LOCK, process.env.HOSTNAME, {
    nx: true,
    ex: 30
  });
  return result === 'OK';
}

async function releaseMigrationLock(): Promise<void> {
  await redis.del(MIGRATION_LOCK);
}
```

**Verification:**
```bash
# Test 1: Dual-write consistency
# During migration, verify session exists in both stores

# Test 2: Failover handling
# Kill primary Redis, verify automatic reconnect

# Test 3: Lock acquisition
# Verify only one instance can run migration
```

---

### Phase 4: Auth Gateway HA (Week 3-4)
**Goal:** Eliminate Auth Gateway single point of failure.

```
Steps (Mitigates E-04):
1. [ ] Deploy Auth Gateway as 2+ replicas behind load balancer
2. [ ] Health check endpoint: GET /health
3. [ ] Session affinity: Same session routes to same gateway
4. [ ] Graceful shutdown: Drain connections before exit
5. [ ] Deploy Redis Sentinel with automatic failover
```

**Verification:**
```bash
# Test 1: Gateway failover
# Kill one gateway, verify requests continue
# Session should remain valid (Redis-backed)

# Test 2: Health check
curl https://auth-gateway/health
# Expected: 200 OK

# Test 3: Load distribution
# Verify requests distribute across replicas
```

---

### Phase 5: Production Hardening (Week 4-6)
**Goal:** Validation and compliance.

```
Steps:
1. [ ] Third-party penetration test
2. [ ] High-concurrency load test (1000 req/s for 10 minutes)
3. [ ] Disaster recovery test (Redis primary failure)
4. [ ] Security compliance audit
5. [ ] Documentation review
6. [ ] Runbook creation for common auth failures
```

---

## 5. Edge Case Mitigations Summary

| Edge Case | Mitigation | Implementation | Verification |
|:---|:---|:---|:---|
| **E-01** Race condition | Distributed lock + dual-write | `MIGRATION_LOCK` key in Redis | Only one instance migrates |
| **E-02** Argon2id DoS | Bounded cost params | t=3, m=64MB, p=4 (hardcoded) | Monitor hash_time_ms < 2s |
| **E-03** Lockout enumeration | Constant-time response | Same 401 for all failures | No timing difference |
| **E-04** Auth Gateway SPOF | HA deployment | 2+ replicas + Sentinel | Failover test passes |
| **E-05** Session fixation | Regeneration post-auth | New session on login | Old token revoked |
| **E-06** Rate limit NAT | Burst + NAT exemption | 5 req/min + 3 sessions/IP | Multiple clients work |

---

## 6. Residual Risk Assessment

After full implementation, residual risks:

| Risk | Severity | Mitigation | Acceptable? |
|:---|:---|:---|:---|
| Redis Sentinel failover delay | LOW | 30s automatic failover | ✅ Yes |
| Argon2id timing variance | LOW | Monitoring + alerting | ✅ Yes |
| Rate limit false positives | LOW | NAT exemption + burst | ✅ Yes |
| Session token derivation key compromise | CRITICAL | Key rotation procedure | ⚠️ Requires procedure |
| Distributed denial of service | MEDIUM | Cloudflare rate limiting | ✅ Yes (external) |
| Zero-day in argon2id library | MEDIUM | Dependency monitoring | ⚠️ Requires vigilance |

**Unavoidable Residual Risks:**
1. **Key Management:** Session derivation key must be stored securely. If compromised, all sessions vulnerable.
   - Mitigation: Key rotation procedure, 90-day rotation schedule
   - Acceptable: Standard key management practice

2. **Library Vulnerabilities:** Argon2id implementation bugs could compromise password hashing.
   - Mitigation: Monitor for CVEs, update dependencies
   - Acceptable: All cryptographic libraries have this risk

---

## 7. Acceptance Criteria

### Phase 1 (Must Pass Before Deploy)

- [ ] Login without password returns 401
- [ ] Login with wrong password returns 401 (same error as non-existent user)
- [ ] Login with correct password returns session token
- [ ] Session token is HMAC-derived (not stored raw)
- [ ] Session expires after 15 minutes of inactivity
- [ ] Password hashing uses argon2id with bounded costs
- [ ] No PII in console logs
- [ ] Unit tests: 95% coverage for auth functions

### Phase 2 (Must Pass Before Production)

- [ ] Rate limiting: 5 req/min/IP enforced
- [ ] Account lockout: 5 failures → 15-minute lockout
- [ ] Lockout response: Same 401 as wrong password (no enumeration)
- [ ] Session regeneration: Old session revoked on new login
- [ ] Audit trail: Login events in Splunk (no PII)
- [ ] Redis Sentinel: Automatic failover verified

### Phase 3 (Must Pass Before Production)

- [ ] Migration: Zero session loss during cutover
- [ ] Split-brain prevention: Distributed lock verified
- [ ] Shadow period: 2 weeks with monitoring
- [ ] Auth Gateway HA: 2+ replicas, failover tested

### Phase 4 (Must Pass Before Production)

- [ ] Penetration test: No critical findings
- [ ] Load test: 1000 req/s sustained, < 100ms p99
- [ ] DR test: Session recovery after Redis failure
- [ ] Compliance audit: No high findings

---

## 8. Timeline Summary

| Phase | Duration | Key Deliverable | Dependencies |
|:---|:---|:---|:---|
| Phase 0 | 0-24 hours | Exploit stopped | None |
| Phase 1 | 24-72 hours | Secure auth baseline | Phase 0 |
| Phase 2 | Week 1-2 | Defense in depth | Phase 1 |
| Phase 3 | Week 2-3 | Redis migration | Phase 2 |
| Phase 4 | Week 3-4 | Auth Gateway HA | Phase 3 |
| Phase 5 | Week 4-6 | Production hardening | Phase 4 |

**Total Timeline:** 6 weeks  
**Shadow Period:** 2 weeks (included in Phase 3-4)  
**Cost Projection:** $100-$1,500/month (Redis Sentinel + monitoring)

---

## 9. Sign-Off

This implementation plan represents consensus among three independent reviews:

| Role | Model | Perspective | Sign-Off |
|:---|:---|:---|:---|
| Worker | MiniMax M2.7 | Implementation feasibility | ✅ |
| Architect | Qwen3.5-122B | Strategic architecture | ✅ |
| Reviewer | Gemma 4 31B | Critical edge cases | ✅ |

**All three agents approve this plan for implementation.**

---

## 10. Next Steps

1. **Immediate:** Execute Phase 0 emergency stop-gap
2. **This Week:** Begin Phase 1 implementation
3. **Next Week:** Complete Phase 1 + begin Phase 2
4. **Week 2:** Complete Phase 2 + begin Phase 3
5. **Week 3-4:** Complete Phases 3-4
6. **Week 5-6:** Phase 5 validation + production deploy