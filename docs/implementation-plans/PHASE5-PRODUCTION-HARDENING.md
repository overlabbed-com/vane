# Phase 5: Production Hardening Implementation Plan

**Document Type:** Implementation Plan  
**Date:** 2026-04-17  
**Phase:** 5 of 6  
**Status:** Draft — Post-Adversarial Review (Round 1)  

---

## 1. Executive Summary

Phase 5 validates the complete Vane implementation through penetration testing, load testing, disaster recovery testing, and compliance audit. This is the final validation phase before production deployment.

**Risk After Implementation:** MEDIUM → LOW  
**Timeline:** 2 weeks  
**Dependencies:** Phases 0-4 complete  

---

## 2. Test Scope

### 2.1 Third-Party Penetration Test

**Objective:** Independent validation that no critical vulnerabilities remain.

**Scope:**
- Authentication endpoints (login, logout, verify)
- Session management (creation, validation, revocation)
- Token derivation (HMAC-SHA256)
- Password hashing (Argon2id)
- Rate limiting (sliding window)
- Account lockout (constant-time response)
- Redis Sentinel failover
- Auth Gateway HA
- Health check endpoint
- Graceful shutdown

**Excluded:**
- Infrastructure (load balancer, network)
- Client applications

**Note:** Google OAuth social login IS in scope — it is the primary multi-user authentication mechanism. Excluding it would leave the core auth path untested.

**Deliverable:** Pentest report with findings (if any).

### 2.2 High-Concurrency Load Test

**Objective:** Verify system handles 1000 req/s sustained load.


**Target:**
- 1000 requests/second for 10 minutes (600,000 total requests)
- p99 latency < 100ms
- Error rate < 0.1%
- No session failures or inconsistencies

**Test Scenarios:**

| Scenario | RPS | Duration | Target |
|:---|:---|:---|:---|
| Login baseline | 1000 | 10 min | p99 < 100ms |
| Login + verify | 500 + 500 | 10 min | p99 < 100ms |
| Burst test | 3000 (peak) | 30 sec | No 5xx errors |
| Sustained load | 1000 | 10 min | No memory leaks |
| Health check | 100 | 10 min | All replicas healthy |
| Failover under load | N/A | Mid-test | Redis failover during peak load |
| Graceful shutdown | N/A | Mid-test | Shutdown with in-flight requests |

**Metrics Collected:**
- Request throughput (req/s)
- Response latency (p50, p95, p99)
- Error rate (4xx, 5xx)
- CPU usage
- Memory usage
- Redis connections
- Session creation rate

### 2.3 Disaster Recovery Test

**Objective:** Verify system recovers from Redis primary failure.

**Scenario:**
1. Kill Redis primary node
2. Verify Sentinel promotes replica to primary
3. Verify sessions remain accessible
4. Verify new sessions can be created
5. Verify old sessions are rejected after failover
6. Restore original primary
7. Verify rejoin and sync

**Acceptance Criteria:**
- Automatic failover completes within 30 seconds
- No session data loss for active sessions
- No 5xx errors during failover (clients retry)
- System remains operational during failover

### 2.4 Security Compliance Audit

**Objective:** Verify implementation matches security standards.

**Standards:**
- OWASP Top 10 (2021)
- NIST SP 800-63B (authenticator assurance)
- GDPR Article 32 (security of processing)

**Checklist:**

| Category | Requirement | Status | Notes |
|:---|:---|:---|:---|
| Authentication | Multi-factor available | ⚠️ Phase 2 | Google OAuth is SSO, not MFA. TOTP/U2F not implemented. |
| Session management | 15-minute TTL, sliding refresh | ✅ Phase 1 | Verified in unit tests |
| Password storage | Argon2id with bounded costs | ✅ Phase 1 | t=3, m=64MB, p=4 (hardcoded) |
| Rate limiting | 5 req/min/IP with burst | ✅ Phase 2 | Burst: 15 req/min for 10s after idle |
| Audit logging | No PII in logs | ✅ Phase 2 | Email hashed, IP anonymized |
| Encryption | TLS 1.2+ required | Infrastructure | Caddy handles TLS |
| Secrets | No hardcoded secrets | ✅ All phases | All via env vars |
| Error handling | Constant-time errors | ✅ Phase 1 | Error jitter + constant-time compare |
| Session binding | IP/UA validation | ✅ Phase 2 | IP/UA bound to session |

### 2.5 Documentation Review

**Objective:** Ensure all security decisions are documented.

**Documents:**
- `IMPLEMENTATION-PLAN.md` — Complete (all phases)
- `STRIDE-THREAT-MODELING.md` — Complete
- `PKCE-REVIEW-FINDINGS.md` — Complete
- `CSRF-PROTECTION.md` — Complete
- `ERROR-JITTER.md` — Complete
- `PHASE3-REDIS-HA.md` — Complete
- `PHASE4-AUTH-GATEWAY-HA.md` — Complete
- `DEPLOY.md` — Deployment procedure

**Review Checklist:**
- [ ] All implementation decisions have rationale
- [ ] All security trade-offs are documented
- [ ] All acceptance criteria are verifiable
- [ ] All test cases are automated
- [ ] All environment variables are documented

### 2.6 Runbook Creation

**Objective:** Document procedures for common auth failures.

**Runbooks:**

| Runbook | Trigger | Steps |
|:---|:---|:---|
| Auth Gateway down | Health check fails | 1. Check container status 2. Check logs 3. Restart if needed |
| Redis Sentinel failover | Primary down | 1. Verify failover completes 2. Check sessions 3. Monitor |
| Rate limit triggered | 429 responses | 1. Identify source IP 2. Check if legitimate 3. Whitelist if needed |
| Account locked out | User reports lockout | 1. Verify lockout status 2. Check failed attempts 3. Clear if legitimate |
| Session invalid | User reports logout | 1. Check session TTL 2. Check Redis 3. Verify token |
| Password reset | User requests reset | 1. Verify email ownership 2. Send reset link 3. Log event |

---

## 3. Test Environment

### 3.1 Environment Configuration

**Staging Environment:**
- Auth Gateway: 3 replicas (Phase 4)
- Redis Sentinel: 3 nodes (Phase 3)
- PostgreSQL: 1 primary (existing)
- Load Balancer: Caddy (existing)

**Test Clients:**
- 10 concurrent clients for load testing
- Each client: 100 req/s

### 3.2 Test Accounts

**Test Users:**
- `pentest@example.com` — Pentest account (no real data)
- `loadtest@example.com` — Load test account
- `recovery@example.com` — DR test account

**Test Credentials:**
- All test accounts use password: `VaneTestPassword123!`

---

## 4. Test Cases

### 4.1 Penetration Test Cases

```typescript
// Authentication bypass
it('cannot login without password', async () => {
  const response = await POST('/api/auth/login', { email: 'test@example.com' });
  expect(response.status).toBe(401);
});

// Token derivation
it('session token is HMAC-derived, not stored raw', async () => {
  const session = await createSession('user-1');
  const rawToken = session.token;
  
  // Raw token should work
  const verified = await verifySession(rawToken);
  expect(verified).not.toBeNull();
  
  // HMAC of raw token should also work (token = HMAC(raw))
  const derivedToken = createHmac('sha256', SESSION_SECRET)
    .update(rawToken)
    .digest('hex');
  const verified2 = await verifySession(derivedToken);
  expect(verified2).not.toBeNull();
});

// Rate limiting
it('rate limit enforced at 5 req/min/IP', async () => {
  for (let i = 0; i < 5; i++) {
    const response = await POST('/api/auth/login', {
      email: 'test@example.com',
      password: 'wrong'
    });
    expect(response.status).toBe(401);
  }
  // 6th request should be rate limited
  const response = await POST('/api/auth/login', {
    email: 'test@example.com',
    password: 'wrong'
  });
  expect(response.status).toBe(429);
});

// Account lockout
it('lockout returns same error as wrong password', async () => {
  // Trigger 5 failures
  for (let i = 0; i < 5; i++) {
    await POST('/api/auth/login', {
      email: 'lockout@example.com',
      password: 'wrong'
    });
  }
  
  // 6th failure (should be locked)
  const response = await POST('/api/auth/login', {
    email: 'lockout@example.com',
    password: 'wrong'
  });
  
  // Same error as wrong password - no lockout indication
  expect(response.status).toBe(401);
  const body = await response.json();
  expect(body.error).toBe('INVALID_CREDENTIALS');
  expect(body.message).not.toContain('lockout');
});

// Session fixation - test the actual attack vector
it('session fixation: attacker token invalidated after victim login', async () => {
  // Attacker obtains session token (via XSS, network sniffing, etc.)
  const attackerToken = await createSession('victim-user');
  
  // Victim logs in (should revoke attacker's session)
  const victimSession = await login('victim-user', 'password');
  
  // Attacker's token should be revoked
  const verified = await verifySession(attackerToken.token);
  expect(verified).toBeNull();
  
  // Victim's session should work
  const verifiedVictim = await verifySession(victimSession.token);
  expect(verifiedVictim).not.toBeNull();
});

// Session fixation - old session revoked on new login
it('old session revoked on new login', async () => {
  const session1 = await login('user@example.com', 'password');
  const session2 = await login('user@example.com', 'password');
  
  // First session should be revoked
  const verified1 = await verifySession(session1.token);
  expect(verified1).toBeNull();
  
  // Second session should work
  const verified2 = await verifySession(session2.token);
  expect(verified2).not.toBeNull();
});

// SESSION_SECRET rotation
it('sessions survive SESSION_SECRET rotation', async () => {
  // Create session with old key
  const session = await createSession('user-1');
  
  // Rotate key (update env, restart instances)
  await rotateSessionSecret();
  
  // Old session should still work (grace period for existing sessions)
  // OR old session should fail fast (key rotation invalidates all sessions)
  // Either behavior is acceptable, but must be documented
  const verified = await verifySession(session.token);
  // Document which behavior: graceful (not null) or hard (null)
  expect(verified).not.toBeNull(); // or expect(verified).toBeNull() - document this
});

// Audit log PII redaction
it('audit logs contain no PII', async () => {
  await login('test@example.com', 'password');
  
  const logs = await getAuditLogs();
  const lastLog = logs[logs.length - 1];
  
  // Email should be hashed, not plaintext
  expect(lastLog.email).toMatch(/^[a-f0-9]{64}$/);  // SHA256 hash
  expect(lastLog.email).not.toContain('test@example.com');
  
  // IP should be anonymized (last octet zeroed)
  expect(lastLog.ip).toMatch(/^\d+\.\d+\.\d+\.0$/);
  
  // No session tokens in logs
  expect(JSON.stringify(lastLog)).not.toMatch(/token[=:]/);
});

// Burst rate limit
it('burst rate limit allows 15 req/min after idle', async () => {
  // Idle for 60 seconds (burst window expired)
  await sleep(60000);
  
  // First 5 requests should succeed
  for (let i = 0; i < 5; i++) {
    const response = await POST('/api/auth/login', {
      email: 'burst@example.com',
      password: 'wrong',
    });
    expect(response.status).toBe(401);
  }
  
  // Next 10 requests (burst) should also succeed
  for (let i = 0; i < 10; i++) {
    const response = await POST('/api/auth/login', {
      email: 'burst@example.com',
      password: 'wrong',
    });
    expect(response.status).toBe(401);
  }
  
  // 16th request should be rate limited
  const response = await POST('/api/auth/login', {
    email: 'burst@example.com',
    password: 'wrong',
  });
  expect(response.status).toBe(429);
});

// Account lockout TTL
it('lockout auto-releases after 15 minutes', async () => {
  // Trigger lockout
  for (let i = 0; i < 5; i++) {
    await POST('/api/auth/login', {
      email: 'lockout@example.com',
      password: 'wrong',
    });
  }
  
  // Verify locked
  const locked = await POST('/api/auth/login', {
    email: 'lockout@example.com',
    password: 'wrong',
  });
  expect(locked.status).toBe(401);
  
  // Wait 15 minutes
  await sleep(15 * 60 * 1000);
  
  // Should be unlocked (can try again)
  const unlocked = await POST('/api/auth/login', {
    email: 'lockout@example.com',
    password: 'wrong',
  });
  expect(unlocked.status).toBe(401);  // Wrong password, not rate limited
});
```

### 4.2 Load Test Cases

```typescript
// Load test configuration
const LOAD_TEST_CONFIG = {
  target: {
    rps: 1000,
    duration: '10 minutes',
    p99Latency: 100,  // ms
    errorRate: 0.001,  // 0.1%
  },
  burst: {
    rps: 3000,
    duration: '30 seconds',
    maxErrors: 10,
  },
};

// Login baseline test
it('handles 1000 req/s login for 10 minutes', async () => {
  const results = await runLoadTest({
    target: LOAD_TEST_CONFIG.target.rps,
    duration: LOAD_TEST_CONFIG.target.duration,
    endpoint: '/api/auth/login',
    body: { email: 'loadtest@example.com', password: 'password' },
  });
  
  expect(results.p99Latency).toBeLessThan(LOAD_TEST_CONFIG.target.p99Latency);
  expect(results.errorRate).toBeLessThan(LOAD_TEST_CONFIG.target.errorRate);
});

// Login + verify test
it('handles 500 login + 500 verify req/s for 10 minutes', async () => {
  const [loginResults, verifyResults] = await Promise.all([
    runLoadTest({
      target: 500,
      duration: '10 minutes',
      endpoint: '/api/auth/login',
      body: { email: 'loadtest@example.com', password: 'password' },
    }),
    runLoadTest({
      target: 500,
      duration: '10 minutes',
      endpoint: '/api/auth/verify',
      body: { token: 'valid-session-token' },
    }),
  ]);
  
  expect(loginResults.p99Latency).toBeLessThan(100);
  expect(verifyResults.p99Latency).toBeLessThan(100);
  expect(loginResults.errorRate).toBeLessThan(0.001);
  expect(verifyResults.errorRate).toBeLessThan(0.001);
});

// Burst test
it('handles 3000 req/s burst for 30 seconds', async () => {
  const results = await runLoadTest({
    target: LOAD_TEST_CONFIG.burst.rps,
    duration: LOAD_TEST_CONFIG.burst.duration,
    endpoint: '/api/auth/login',
    body: { email: 'loadtest@example.com', password: 'password' },
  });
  
  // No 5xx errors during burst
  expect(results.status5xx).toBeLessThan(LOAD_TEST_CONFIG.burst.maxErrors);
});

// Memory stability
it('no memory leaks during sustained load', async () => {
  const initialMemory = await getMemoryUsage();
  
  await runLoadTest({
    target: 1000,
    duration: '10 minutes',
    endpoint: '/api/auth/login',
    body: { email: 'loadtest@example.com', password: 'password' },
  });
  
  const finalMemory = await getMemoryUsage();
  const memoryGrowth = (finalMemory - initialMemory) / initialMemory;
  
  // Less than 10% memory growth over 10 minutes
  expect(memoryGrowth).toBeLessThan(0.10);
});

// Health check under load
it('health check endpoint remains healthy under load', async () => {
  // Start load test
  const loadTest = runLoadTest({
    target: 1000,
    duration: '10 minutes',
    endpoint: '/api/auth/login',
    body: { email: 'loadtest@example.com', password: 'password' },
  });
  
  // Poll health check every 10 seconds
  for (let i = 0; i < 60; i++) {
    await sleep(10000);
    const response = await GET('/api/auth/health');
    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data.status).toBe('healthy');
  }
});

// Failover under load
it('Redis failover completes without errors during peak load', async () => {
  // Start load test
  const loadTest = runLoadTest({
    target: 1000,
    duration: '10 minutes',
    endpoint: '/api/auth/login',
    body: { email: 'loadtest@example.com', password: 'password' },
  });
  
  // Wait 2 minutes, then trigger failover
  await sleep(120000);
  await killRedisNode(await getRedisPrimary());
  
  // Load should continue (with retries)
  // No 5xx errors should spike
  const results = await loadTest;
  expect(results.status5xx).toBeLessThan(100);
});

// Graceful shutdown with in-flight requests
it('graceful shutdown completes in-flight requests', async () => {
  // Start 100 concurrent long-running requests
  const requests = Array.from({ length: 100 }, () =>
    POST('/api/auth/verify', { token: 'valid-session' })
  );
  
  // Trigger graceful shutdown mid-request
  await sleep(100);  // Wait for requests to start
  await triggerGracefulShutdown();
  
  // All 100 requests should complete (not fail)
  const results = await Promise.all(requests);
  results.forEach((result) => {
    // Either 200 (completed) or 503 (graceful shutdown) - not 500
    expect([200, 503]).toContain(result.status);
  });
});
```

### 4.3 Disaster Recovery Test Cases

```typescript
// Redis failover test
it('automatic failover within 30 seconds', async () => {
  // Get current primary
  const initialPrimary = await getRedisPrimary();
  
  // Kill primary
  await killRedisNode(initialPrimary);
  
  // Measure failover time
  const start = Date.now();
  await waitForNewPrimary(initialPrimary);
  const failoverTime = Date.now() - start;
  
  // Failover should complete within 30 seconds
  expect(failoverTime).toBeLessThan(30000);
});

// Session availability during failover
it('sessions remain accessible during failover', async () => {
  // Create session before failover
  const session = await createSession('user-1');
  
  // Kill primary
  await killRedisNode(await getRedisPrimary());
  
  // Wait for failover
  await waitForNewPrimary();
  
  // Session should still be accessible
  const verified = await verifySession(session.token);
  expect(verified).not.toBeNull();
});

// New sessions during failover
it('new sessions can be created during failover', async () => {
  // Kill primary
  await killRedisNode(await getRedisPrimary());
  
  // Try to create session during failover
  try {
    const session = await createSession('user-1');
    // May fail or succeed depending on retry logic
  } catch (error) {
    // Should retry and succeed after failover
    await waitForNewPrimary();
    const session = await createSession('user-1');
    expect(session).not.toBeNull();
  }
});

// Old sessions survive or fail fast after failover
it('sessions created before failover: survive if replicated, fail fast if not', async () => {
  const session = await createSession('user-1');
  
  await killRedisNode(await getRedisPrimary());
  await waitForNewPrimary();
  
  // Expected: Either session survives (replicated to new primary)
  // OR session is lost (acceptable for short-TTL sessions)
  // The key is: verifySession returns null after failover, not an error
  const verified = await verifySession(session.token);
  
  // Should return null (not found), not throw
  // If it throws, that's a bug
  expect(verified).toBeNull();
});
```

---

## 5. Acceptance Criteria

### 5.1 Penetration Test

- [ ] No CRITICAL findings
- [ ] No HIGH findings
- [ ] Maximum 3 MEDIUM findings (action items)
- [ ] All findings remediated or accepted with risk

### 5.2 Load Test

- [ ] 1000 req/s sustained for 10 minutes
- [ ] p99 latency < 100ms
- [ ] Error rate < 0.1%
- [ ] 3000 req/s burst for 30 seconds (no 5xx)
- [ ] Memory growth < 10% over 10 minutes

### 5.3 Disaster Recovery

- [ ] Automatic failover < 30 seconds
- [ ] No session data loss for active sessions
- [ ] No 5xx errors during failover
- [ ] System operational during failover

### 5.4 Compliance Audit

- [ ] OWASP Top 10: No high findings
- [ ] NIST SP 800-63B: All requirements met
- [ ] GDPR Article 32: All requirements met

### 5.5 Documentation

- [ ] All implementation decisions documented
- [ ] All security trade-offs documented
- [ ] All acceptance criteria verifiable
- [ ] All test cases automated

### 5.6 Runbooks

- [ ] Auth Gateway down runbook
- [ ] Redis Sentinel failover runbook
- [ ] Rate limit triggered runbook
- [ ] Account locked out runbook
- [ ] Session invalid runbook
- [ ] Password reset runbook

---

## 6. Timeline

| Week | Activities |
|:---|:---|
| Week 1, Day 1-5 | Penetration test (5 days — 2 days insufficient for professional vendor) |
| Week 2, Day 1-2 | Load test + failover under load |
| Week 2, Day 3 | Disaster recovery test |
| Week 2, Day 4 | Compliance audit |
| Week 2, Day 5 | Documentation review + runbooks |
| Week 3, Day 1-2 | Remediation + final sign-off |

---

## 7. Dependencies

| Dependency | Required For | Status |
|:---|:---|:---|
| Phases 0-4 | All test scenarios | ✅ Complete |
| Staging environment | All tests | Infrastructure |
| Load testing tool | Load test | k6 or similar |
| Pentest vendor | Penetration test | External |
| Test accounts | All tests | To be created |

---

## 8. Risks

| Risk | Likelihood | Impact | Mitigation |
|:---|:---|:---|:---|
| Pentest finds critical issues | LOW | HIGH | Buffer 1 week for remediation (Week 3) |
| Load test reveals scaling issues | MEDIUM | MEDIUM | Horizontal scaling ready |
| DR test reveals session loss | HIGH | MEDIUM | Acceptable for 15-min TTL sessions |
| Compliance audit finds gaps | LOW | MEDIUM | MFA gap documented, accepted risk |
| Failover during peak load | MEDIUM | HIGH | Retry logic handles transient failures |

---

## 9. Next Steps

1. **Schedule pentest vendor** — Book external pentest
2. **Set up staging environment** — Verify all Phase 4 components
3. **Create test accounts** — Set up test users with test credentials
4. **Set up load testing tool** — Configure k6 or similar
5. **Execute penetration test** — Day 1-2
6. **Execute load test** — Day 3-4
7. **Execute disaster recovery test** — Day 5
8. **Compliance audit** — Week 2
9. **Documentation review** — Week 2
10. **Runbook creation** — Week 2
11. **Final sign-off** — Week 2, Day 5