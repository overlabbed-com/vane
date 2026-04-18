# Security Consensus: Vane Authentication System (Round 3 Final)

**Status:** 🔴 BLOCKED (P0 Remediation Required)
**Date:** 2026-04-17
**Scope:** Vane Authentication & Session Management

---

## 1. Executive Summary
The Vane Authentication System has undergone three rounds of security review. While the critical vulnerabilities from Round 1 (Auth Bypass, Plaintext Tokens) have been resolved, Round 3 has identified systemic architectural flaws and implementation bugs that pose significant risks to production stability and security. 

The system currently fails to meet the minimum security baseline due to broken key rotation logic, timing attacks, and critical configuration fallbacks. **Production deployment is prohibited until all P0 Blockers are remediated and verified.**

---

## 2. Round 1 Status (Resolved)
The following critical issues identified in the initial audit are confirmed as resolved:
- [x] **Auth Bypass:** Email-only login removed; password/token verification now mandatory.
- [x] **Plaintext Tokens:** Transitioned to hashed/encrypted token storage.
- [x] **User Enumeration:** Response patterns normalized to prevent account discovery.

---

## 3. Round 2 Decision Assessments

| Decision | Verdict | Notes |
| :--- | :--- | :--- |
| **1. Password OR API Key Auth** | **APPROVE (Modified)** | Valid approach, but requires the addition of **API Key Scopes** to prevent all-or-nothing access. |
| **2. Dual-Store (Redis + Postgres)** | **REJECT** | The PostgreSQL fallback is theoretical and unimplemented. It adds complexity and false confidence. System must commit to a single source of truth. |
| **3. 15-min Sliding TTL** | **APPROVE (Modified)** | Valid for UX, but must be coupled with a strictly enforced **Absolute Timeout** (`maxTokenAgeMs`) to prevent session fixation. |

---

## 4. Critical Gaps (P0 Blockers)
*These items must be fixed and verified by the Reviewer before the system is marked as "Ready for Production".*

### 4.1 Architectural Failures
- **Broken Key Rotation:** The XOR-based rotation is mathematically flawed and invalidates all active sessions upon rotation. **Requirement:** Implement versioned keys or a grace period for overlapping keys.
- **Dead Code (Session Expiry):** `maxTokenAgeMs` (7 days) is defined but never enforced. **Requirement:** Implement absolute session expiration logic.
- **Dual-Store Deception:** Remove all PostgreSQL fallback code. **Requirement:** Standardize on Redis-only for session state.

### 4.2 Security Vulnerabilities
- **Default Secret Fallback:** `API_KEY_SECRET` contains a `'default'` fallback value. **Requirement:** Remove fallback; the system must fail to start if the secret is missing from the environment.
- **Timing Attack:** User-not-found returns significantly faster than wrong-password (Argon2 delay). **Requirement:** Implement constant-time user lookups (dummy hash verification for non-existent users).
- **Lack of Granularity:** API keys grant full administrative access. **Requirement:** Implement scopes: `search:read`, `search:write`, `admin`.

### 4.3 Stability & Performance
- **DoS Vector:** Session revocation uses $O(N)$ `SCAN` operations. **Requirement:** Transition to a set-based or indexed revocation list.
- **Race Conditions:** `verifySession` uses non-atomic `get`/`setex` calls. **Requirement:** Use Lua scripts or Redis transactions to ensure atomicity.
- **Redis Fragility:** Lack of circuit breaking on Redis timeouts. **Requirement:** Implement a circuit breaker to prevent cascading failure during Redis latency spikes.

---

## 5. High Priority Gaps (P1)
*To be addressed in the first maintenance sprint post-launch.*

- **Concurrent Session Limits:** No limit on how many active sessions a single user can hold.
- **Weak Key Derivation:** `SESSION_SECRET` derivation lacks sufficient entropy/salt.
- **Account Lockout:** No mechanism to prevent sustained brute-force attempts against a single account.

---

## 6. Monitoring & Infrastructure Requirements
The system is currently "blind" in production. The following instrumentation is mandatory:

### 6.1 Metrics (Prometheus/Grafana)
- `auth_attempts_total` (labeled by `result`: success, failure, lockout)
- `session_active_count` (gauge of current active sessions)
- `token_rotation_events_total`
- `redis_auth_latency_ms` (p95, p99)

### 6.2 Infrastructure Tuning
- **Redis Timeouts:** Reduce timeout from 5s to 1s to fail fast.
- **Health Checks:** Implement a `/health/auth` endpoint that verifies Redis connectivity.
- **Rate Limiting:** Replace in-memory rate limiting with distributed limiting (Redis-backed) to prevent bypass via pod restarts.

---

## 7. Production Readiness Checklist

- [ ] **P0:** XOR Key Rotation $\rightarrow$ Versioned Keys
- [ ] **P0:** `maxTokenAgeMs` $\rightarrow$ Enforced Absolute Timeout
- [ ] **P0:** `API_KEY_SECRET` $\rightarrow$ No default fallback
- [ ] **P0:** API Keys $\rightarrow$ Scopes implemented (`read`, `write`, `admin`)
- [ ] **P0:** Auth Logic $\rightarrow$ Constant-time user lookup
- [ ] **P0:** Redis $\rightarrow$ Atomic `verifySession` (Lua)
- [ ] **P0:** Redis $\rightarrow$ Circuit Breaker implemented
- [ ] **P0:** Codebase $\rightarrow$ PostgreSQL fallback removed
- [ ] **P1:** Distributed Rate Limiting implemented
- [ ] **P1:** Metrics instrumentation deployed

---

## 8. Deployment Recommendation
**VERDICT: DO NOT DEPLOY.**

The current state of the Vane Authentication System represents a high risk of both security breach (timing attacks, default secrets) and operational outage (broken key rotation, DoS via SCAN). 

**Path to Green:**
1. Execute P0 remediation sprint.
2. Perform a targeted security re-review of the `verifySession` and `rotateKeys` functions.
3. Verify metrics visibility in the staging environment.
4. Final sign-off by Architect and Reviewer.
