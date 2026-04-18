# Auth Flow, Session Storage, and Session TTL Decisions

**Date:** 2026-04-17  
**Status:** CONSENSUS ACHIEVED  
**Round:** 2

---

## Decision 1: Auth Flow — Password OR API Key

### Decision
**APPROVED: Password OR API key (either/or authentication)**

### Rationale
- Accommodates both human users (password) and API clients (API key)
- Either credential sufficient to authenticate
- Not both required (avoids forcing API key on humans or password on automated systems)

### Mitigations Required (Reviewer Concerns Addressed)

| Concern | Mitigation |
|---------|------------|
| User enumeration: "user not found" reveals existence | Return unified `INVALID_CREDENTIALS` for both user-not-found AND wrong credential |
| API key leakage = full account access | Accept single-factor for API clients (standard practice). Password provides additional security for human users who opt in. |
| Brute force on API key | Rate limit auth attempts: 5 attempts per IP per 15 min, 20 attempts per account per hour |

### Implementation Requirements
1. Same error message (`INVALID_CREDENTIALS`) for all auth failures (timing attack mitigation)
2. Constant-time comparison for credential verification
3. Rate limiting middleware on `/auth/login` endpoint
4. Log auth failures with sanitized details (no credential values)

### Sign-off
- architect: ✅ YES
- reviewer: ✅ CONDITIONAL → YES (mitigations documented)
- worker: ✅ YES

---

## Decision 2: Session Store — Redis Preferred, PostgreSQL Fallback

### Decision
**APPROVED: Redis preferred, PostgreSQL fallback acceptable**

### Rationale
- Redis: TTL-native sliding expiration, fast, well-suited for session store
- PostgreSQL: Already in stack, simpler ops, acceptable fallback for resilience

### Mitigations Required (Reviewer Concerns Addressed)

| Concern | Mitigation |
|---------|------------|
| Redis failure: fail closed vs fail open | Fail CLOSED: if Redis unavailable, deny new sessions. Existing sessions in PostgreSQL remain valid. |
| Fallback trigger | Automatic health check (ping Redis every 10s). If 3 consecutive failures, switch to PostgreSQL. |
| Consistency during failover | PostgreSQL is source of truth. Redis is read-through cache. Sessions written to PostgreSQL first, then Redis. |

### Implementation Requirements
1. Redis client with connection pooling and automatic reconnection
2. PostgreSQL `sessions` table with schema: `(token_hash, user_id, created_at, expires_at, revoked)`
3. Health check endpoint for Redis with circuit breaker
4. Migration: on PostgreSQL fallback, reject new Redis sessions until Redis recovers
5. Token stored as HMAC-SHA256 hash (not plaintext)

### Sign-off
- architect: ✅ YES
- reviewer: ✅ YES (failure modes documented)
- worker: ✅ YES

---

## Decision 3: Session TTL — 15 Minutes with Sliding Expiration

### Decision
**APPROVED: 15 minutes with sliding expiration**

### Rationale
- Security: Limits exposure window if token is stolen (attacker has max 15 min)
- Usability: Resets on every authenticated request
- Industry standard: OAuth tokens typically 15-60 min

### Mitigations Required (Reviewer Concerns Addressed)

| Concern | Mitigation |
|---------|------------|
| Sliding window doesn't help continuous attacker | Sliding TTL limits burst access, not persistent compromise. Combined with anomaly detection (alert on unusual IP/user agent). |
| 15 min interrupts long API calls | In-flight requests exceeding TTL get grace period (up to 5 min for request completion). |
| Clock skew | Server-side time only; client clock not used for expiration. |

### Implementation Requirements
1. Redis: `EXPIRE` command on every authenticated request (sliding TTL)
2. PostgreSQL: `updated_at` column updated on each request, background job cleans up expired
3. Grace period: Allow request completion up to 5 min past TTL
4. Anomaly detection: Log session usage patterns, alert on unusual activity

### Sign-off
- architect: ✅ YES
- reviewer: ✅ CONDITIONAL → YES (grace period and anomaly detection added)
- worker: ✅ YES

---

## Final Sign-off

| Model | Decision 1 | Decision 2 | Decision 3 |
|-------|-----------|-----------|-----------|
| architect | ✅ | ✅ | ✅ |
| reviewer | ✅ | ✅ | ✅ |
| worker | ✅ | ✅ | ✅ |

**ALL MODELS AGREE. PROCEED WITH IMPLEMENTATION.**

---

## Strategic Trade-offs Documented

| Decision | Trade-off | Accepted Risk |
|----------|----------|---------------|
| Auth OR | API key compromise = access without password | Acceptable for API clients. Humans should use password. |
| PostgreSQL fallback | Slightly slower than Redis | Acceptable for resilience. Most deployments use Redis. |
| 15 min TTL | May interrupt long idle sessions | Reset timer on activity. Grace period for in-flight. |

## Remaining Concerns (Low Risk)

1. **API key rotation**: No automatic rotation mechanism (deferred to future iteration)
2. **Password complexity**: No enforced password policy (deferred to user management iteration)
3. **Session invalidation on password change**: Not implemented (deferred to account security iteration)

---

## Implementation Order

1. **Phase 1:** Fix auth bypass (verify credentials before session creation)
2. **Phase 2:** Add rate limiting
3. **Phase 3:** Implement session store (Redis + PostgreSQL fallback)
4. **Phase 4:** Add sliding TTL with grace period
5. **Phase 5:** Add anomaly detection logging