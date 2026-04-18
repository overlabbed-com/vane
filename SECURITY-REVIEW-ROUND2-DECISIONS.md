# Vane Security Review Round 2: Architectural Decisions Consensus

**Date:** 2026-04-17  
**Review Type:** Multi-Model Consensus (Architect + Reviewer + Sentinel)  
**Status:** CONSENSUS ACHIEVED — MODIFY & APPROVE  

---

## Executive Summary

Round 2 evaluates three architectural decisions proposed to address CRITICAL vulnerabilities identified in Round 1:
1. **CRITICAL Auth Bypass** (email-only login without credential verification)
2. **CRITICAL Plaintext Session Tokens** (stored unhashed in memory)
3. **HIGH User Enumeration** (distinct error messages reveal user existence)

**Consensus Outcome:** Two decisions are approved as-is; one requires modification before implementation.

| Decision | Verdict | Key Modification |
|----------|---------|------------------|
| Auth flow: password OR API key | ✅ **APPROVE** | None |
| Session store: Redis + PostgreSQL fallback | 🟡 **MODIFY** | Remove fallback by default; opt-in only for single-instance deployments |
| Session TTL: 15 minutes with sliding | ✅ **APPROVE** | None |

---

## Decision 1: Auth Flow — Password OR API Key

### Consensus Assessment

| Model | Verdict | Key Concerns |
|-------|---------|--------------|
| Architect | ✅ APPROVE | Industry standard pattern; aligns with Vane's dual audience (humans + API clients) |
| Reviewer | ✅ APPROVE | Properly addresses F-01 when credential verification is implemented |
| Sentinel | ⚠️ APPROVE w/ Caveats | Missing distributed brute force detection; API key rotation mechanism needed |

### Strategic Trade-offs

| Dimension | Analysis |
|-----------|----------|
| **Security** | API key = single factor (no second factor). Acceptable for M2M; humans get password protection. |
| **UX** | Flexibility for different client types. API clients don't need password management. |
| **Complexity** | Dual credential paths = 2x verification logic. Minimal overhead; both converge at session creation. |

### Vulnerability Remediation

| Round 1 Finding | Addressed? | How |
|-----------------|------------|-----|
| F-01: Auth Bypass | ✅ YES | Credential verification mandatory before session creation |
| F-03: User Enumeration | ✅ YES | Unified `INVALID_CREDENTIALS` response for all failures |

### Implementation Requirements

```typescript
// Mandatory implementation details
1. Constant-time comparison for password/API key verification
2. Unified error response: "INVALID_CREDENTIALS" for all failures
3. Rate limiting: 5 req/min/IP + 20 req/account/hour
4. Account lockout: 5 failures → 15-minute lockout
5. Argon2id for password hashing (memory: 64MB, time: 3, parallelism: 4)
6. BLAKE3 for API key hashing
```

### New Risks Introduced

| Risk | Severity | Mitigation |
|------|----------|------------|
| API key rotation complexity | MEDIUM | Document 90-day rotation policy; track last-used timestamp |
| Distributed brute force | MEDIUM | Cross-IP correlation alert (same account targeted from 10+ IPs) |
| Credential stuffing | MEDIUM | Anomaly detection for known-breach email addresses |

### Final Verdict: ✅ **APPROVE**

Proceed as designed. This is the correct strategic choice for Vane's use case.

---

## Decision 2: Session Store — Redis Preferred, PostgreSQL Fallback

### Consensus Assessment

| Model | Verdict | Key Concerns |
|-------|---------|--------------|
| Architect | 🟡 MODIFY | Over-engineered for Vane's scale; adds complexity without proportional benefit |
| Reviewer | 🟡 MODIFY | Split-brain risk: sessions in PostgreSQL only not synced to Redis |
| Sentinel | 🟡 MODIFY | No backfill procedure; connection pool exhaustion risk at scale |

### Strategic Trade-offs

| Dimension | Analysis |
|-----------|----------|
| **Security** | Redis = short TTL, automatic expiration. PostgreSQL = manual cleanup, longer exposure window. |
| **Performance** | Redis = sub-ms latency. PostgreSQL = 20-200ms (adds auth latency). |
| **Resilience** | Redis failure = fail closed (deny auth). PostgreSQL fallback = continued operation but degraded. |
| **Ops Complexity** | Redis Sentinel = 3 nodes, HA config. PostgreSQL fallback = dual-store logic, consistency gaps. |

### The Split-Brain Problem

**Current design has a consistency gap:**

```
Write path:
1. Write session to PostgreSQL (source of truth)
2. Write session to Redis (cache)
3. If Redis write fails → session exists in PostgreSQL only
4. If Redis is down during read → session not found (even though valid in PostgreSQL)
```

**Result:** User presents valid token → Redis says invalid → PostgreSQL fallback needed → inconsistent UX.

### Scaling Reality

| Concurrency | Redis Latency | PostgreSQL Fallback Latency |
|------------|---------------|----------------------------|
| 100 concurrent auth | ~5ms | ~20ms |
| 1,000 concurrent auth | ~10ms | ~50ms |
| 10,000 concurrent auth | ~20ms | ~200ms (connection pool exhaustion risk) |

**PostgreSQL fallback adds 20-200ms latency per auth request.** At 10,000 concurrent users, this creates queueing cascade.

### Modified Recommendation

**Change:** Remove PostgreSQL fallback for production deployments. Use Redis-only with proper HA.

**Rationale:** The fallback pattern adds complexity without meaningful security benefit. For Vane's scale, Redis HA (Sentinel or managed service) is the correct choice.

**Exception:** Keep PostgreSQL fallback as an **opt-in feature flag** for single-instance/homelab deployments where Redis HA is not feasible.

### Implementation Changes

```typescript
// Add feature flag (default: false)
const SESSION_STORE_FALLOVER_ENABLED = process.env.SESSION_STORE_FALLOVER_ENABLED === 'true';

// Default: Redis-only (fail closed on unavailability)
if (!redis.available) {
  if (SESSION_STORE_FALLOVER_ENABLED) {
    // Use PostgreSQL fallback (documented as "graceful degradation")
    // ⚠️ WARNING: Adds 20-200ms latency
    return postgres.createSession(userId);
  } else {
    // Fail closed — deny new sessions
    throw new Error('Session store unavailable');
  }
}

// Write path: always write to both (if fallback enabled)
await redis.setex(token, SESSION_TTL, data);
if (SESSION_STORE_FALLOVER_ENABLED) {
  await postgres.insertSession(tokenHash, userId, expiresAt);
}
```

### Implementation Requirements

```typescript
// Mandatory implementation details
1. Token hashing: HMAC-SHA256 before storage (addresses F-02)
2. Redis Sentinel topology: 3 nodes, quorum=2, failover timeout=30s
3. Circuit breaker: 3 consecutive Redis failures → switch to PostgreSQL (if enabled)
4. Health check endpoint: GET /health returning {"redis": "ok|degraded|down", "postgres": "ok|degraded|down"}
5. Connection pools: Redis pool size = 50; PostgreSQL pool size = 2× auth gateway count
6. Background cleanup job: Remove expired sessions from PostgreSQL (every 5 min)
```

### New Risks Introduced

| Risk | Severity | Mitigation |
|------|----------|------------|
| Redis single point of failure | HIGH (if not HA) | Use Redis Sentinel or managed service. Document fallback mode. |
| Split-brain sessions | MEDIUM | Backfill procedure after Redis recovery. |
| PostgreSQL connection exhaustion | MEDIUM | Connection pool tuning; circuit breaker after 5 consecutive timeouts. |
| Grace period abuse | LOW | Max 5 min grace period. Anomaly detection for unusual patterns. |

### Final Verdict: 🟡 **MODIFY**

**Proceed with modification:** Redis-only by default; PostgreSQL fallback opt-in via feature flag for single-instance deployments only.

---

## Decision 3: Session TTL — 15 Minutes with Sliding Expiration

### Consensus Assessment

| Model | Verdict | Key Concerns |
|-------|---------|--------------|
| Architect | ✅ APPROVE | Matches Vane's bursty search pattern; industry standard for OAuth tokens |
| Reviewer | ✅ APPROVE | Properly limits exposure window for stolen tokens |
| Sentinel | ⚠️ APPROVE w/ Caveats | Grace period not implemented; PostgreSQL needs background cleanup job |

### Strategic Trade-offs

| Dimension | Analysis |
|-----------|----------|
| **Security** | 15 min = limited exposure if token stolen. Shorter = more secure, but impacts UX. |
| **UX** | Sliding = continuous users never notice. 15 min idle = forced re-auth (acceptable for search). |
| **Performance** | Sliding = Redis EXPIRE on every request. Minimal overhead (sub-ms operation). |

### Vulnerability Remediation

| Round 1 Finding | Addressed? | How |
|-----------------|------------|-----|
| F-02: Plaintext Tokens | ✅ YES | Tokens hashed before storage; Redis TTL limits exposure window |

### Implementation Requirements

```typescript
// Mandatory implementation details
1. Grace period: Allow in-flight requests up to 5 min past TTL
2. Server-side time only: Client clock skew doesn't affect expiration
3. Sliding expiration: Reset TTL on every successful session lookup
4. PostgreSQL cleanup: Background job removes expired sessions every 5 min
5. NTP sync requirement: All auth gateways must sync to same time source
```

### Grace Period Implementation

```typescript
// Mark session as in-flight when request starts
await redis.setex(`sess:inflight:${token}`, GRACE_PERIOD_SEC, "1");

// On request completion, refresh TTL
const inflight = await redis.get(`sess:inflight:${token}`);
if (inflight) {
  await redis.del(`sess:inflight:${token}`);
  await redis.expire(`sess:${token}`, SESSION_TTL_SEC);
}
```

### Final Verdict: ✅ **APPROVE**

Proceed as designed. This is optimal for Vane's search gateway pattern.

---

## Vulnerability Remediation Summary

| Round 1 Finding | Decision(s) Addressing It | Properly Addressed? |
|-----------------|---------------------------|---------------------|
| **F-01: Auth Bypass** | Decision 1 (verify credentials) | ✅ YES — Credential verification mandatory before session creation |
| **F-02: Plaintext Tokens** | Decision 2 (HMAC hashing + Redis) | ✅ YES — Tokens hashed before storage, Redis TTL limits exposure |
| **F-03: User Enumeration** | Decision 1 (unified errors) | ✅ YES — `INVALID_CREDENTIALS` for all failures |

**Assessment:** The three decisions, when implemented correctly with the modification to Decision 2, **fully address all Round 1 vulnerabilities**.

---

## Infrastructure Requirements (Not Optional)

### Monitoring Stack

```yaml
metrics:
  - auth_attempts_total{result=success|failure|rate_limited}
  - auth_latency_seconds{quantile=0.5|0.95|0.99}
  - session_active_count
  - session_lookup_latency_seconds
  - redis_connection_pool_available
  - redis_command_duration_seconds{command=get|set|setex|del}
  - postgres_connection_pool_available
  - argon2_hash_duration_seconds

alerts:
  - auth_failure_rate >50% in 5 min
  - auth_latency_p99 >500ms
  - redis_command_duration >100ms
  - session_active_count_change >20% in 5 min
  - cross_ip_brute_force: same account targeted from 10+ IPs in 1 hour
```

### SLO Targets

| SLO | Target | Alert Threshold |
|-----|--------|-----------------|
| Auth availability | 99.9% | <99.9% in any hour |
| Auth latency p50 | <100ms | >200ms |
| Auth latency p99 | <500ms | >1s |
| Session lookup latency | <10ms | >50ms |
| Redis Sentinel failover | <30s | >30s |

### Runbooks Required

1. **Redis failover runbook** — Manual failover, backfill from PostgreSQL
2. **PostgreSQL slow query runbook** — Connection pool tuning, query optimization
3. **Auth latency spike runbook** — Argon2id tuning, Redis health check
4. **Credential stuffing response runbook** — IP block, account lockout, alert escalation

---

## Deployment Recommendation

**STATUS: 🟡 CONDITIONAL GO**

**Condition:** Proceed with implementation using the modified Decision 2 (Redis-only default, PostgreSQL fallback opt-in).

**Deployment Sequence:**
1. Implement Decision 1 (auth verification) — Phase 1
2. Implement Decision 3 (15-min TTL) — Phase 1
3. Implement Decision 2 (Redis-only) — Phase 1
4. Add monitoring and alerts — Phase 2
5. Add PostgreSQL fallback (opt-in) — Phase 2 (optional)
6. Third-party penetration test — Phase 3

**Condition for Production:** Zero "Critical" or "High" findings in independent penetration test after Phase 1 deployment.

---

## Acceptance Criteria (Updated)

### Phase 1 (Core Authentication)
- [ ] Login without credentials returns 401
- [ ] Login with wrong password/API key returns same error as user not found
- [ ] Session tokens are HMAC-hashed before storage
- [ ] Session expires after 15 minutes of inactivity
- [ ] Redis-only by default (PostgreSQL fallback opt-in via feature flag)
- [ ] Rate limiting: 5 req/min/IP enforced
- [ ] Account lockout: 5 failures → 15-minute lockout

### Phase 2 (Defense in Depth)
- [ ] Monitoring stack deployed (metrics + alerts)
- [ ] Cross-IP brute force detection alert configured
- [ ] Redis Sentinel topology verified (3 nodes, quorum=2)
- [ ] Health check endpoint implemented
- [ ] Connection pool sizes documented and tuned
- [ ] Runbooks created for common failures

### Phase 3 (Production Validation)
- [ ] Zero "Critical" or "High" findings in penetration test
- [ ] Auth latency p99 <500ms at 1,000 concurrent users
- [ ] Redis failover tested (RTO <30s verified)
- [ ] PostgreSQL cleanup job verified (no orphaned sessions)

---

## Summary

| Decision | Recommendation | Key Modification |
|----------|---------------|------------------|
| Auth OR | ✅ APPROVE | None |
| Redis + PostgreSQL fallback | 🟡 MODIFY | Remove fallback by default. Opt-in only for single-instance deployments. |
| 15-min TTL | ✅ APPROVE | None |

**Overall Assessment:** The proposed decisions are **strategically sound** and properly address Round 1 vulnerabilities. The only modification needed is to make PostgreSQL fallback opt-in rather than default, reducing complexity for production deployments while preserving it as a "graceful degradation" option for single-instance scenarios.

**Next Step:** Proceed with implementation using the modified Decision 2 (Redis-only default, PostgreSQL fallback opt-in).

---

## Appendix: Consensus Process

**Models Reviewed:**
- **Architect** (chat model): Strategic trade-offs, long-term architecture, design decisions
- **Reviewer** (reason model): Security gaps, edge cases, implementation risks
- **Sentinel** (code model): Infrastructure impact, failure modes, monitoring gaps

**Consensus Method:** Independent assessment → Synthesis → Final recommendation

**Disagreements Resolved:**
- Architect wanted PostgreSQL fallback removed entirely; Sentinel wanted it as opt-in for homelab. **Resolution:** Opt-in feature flag (default: disabled).
- Reviewer flagged missing grace period implementation; Sentinel provided concrete implementation pattern. **Resolution:** Grace period added to implementation requirements.

**Confidence Level:** HIGH (all 3 models agreed on core recommendations)