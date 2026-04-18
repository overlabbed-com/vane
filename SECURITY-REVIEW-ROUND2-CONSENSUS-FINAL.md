# Vane Authentication System: Round 2 Final Consensus Report

## 1. Executive Summary
**Verdict: 🔴 REJECTED (NOT PRODUCTION READY)**

The Vane Authentication System currently fails to meet the minimum security baseline for production deployment. While the core architecture is sound, the implementation contains critical vulnerabilities—including a Denial of Service (DoS) vector in session management, broken cryptographic key rotation, and race conditions in session verification. 

The system cannot be deployed until all P0 blockers are remediated and verified by a third-party review.

---

## 2. Round 1 Status
The following items from the Round 1 assessment were addressed:
- [x] **Initial Secret Hardcoding**: Default secrets removed from source.
- [x] **Basic Token Structure**: Transitioned to a more robust token format.
- [x] **Initial Redis Integration**: Basic session storage implemented.

**Status:** While basic functional gaps were closed, the "fixes" introduced new implementation bugs that were uncovered during the Round 2 deep dive.

---

## 3. Decision-by-Decision Assessment

### Decision 1: Password OR API Key Authentication
**Verdict: ✅ APPROVE (With Modifications)**

The dual-path authentication is acceptable but requires hardening to prevent side-channel attacks and privilege escalation.

| Trade-off | Risk | Mitigation |
| :--- | :--- | :--- |
| **Flexibility** | API keys are long-lived and high-risk | Implement granular scopes (Read/Write/Admin) |
| **Performance** | Password hashing is intentionally slow | Implement strict rate-limiting per IP/Account |
| **Security** | Timing attacks on credential lookup | Use constant-time comparison for all credential checks |

**Required Changes:**
- Add support for API key scopes.
- Ensure no default secrets remain in any environment config.
- Fix timing attack vulnerability in the credential verification loop.

### Decision 2: Redis + PostgreSQL Fallback
**Verdict: ❌ REJECTED**

The proposed fallback mechanism is not implemented and introduces significant operational risk.

| Trade-off | Risk | Mitigation |
| :--- | :--- | :--- |
| **Availability** | Intended to prevent lockout if Redis fails | **Split-Brain Risk**: Inconsistent session states between DB and Cache |
| **Complexity** | Adds significant synchronization logic | **False Confidence**: Reliance on a fallback that isn't fully tested |

**Recommendation:** Remove the fallback logic entirely. Treat Redis as the single source of truth for sessions. If Redis is unavailable, the system should fail closed (503 Service Unavailable) rather than risk inconsistent authentication states.

### Decision 3: 15-min TTL with Sliding Window
**Verdict: ✅ APPROVE (With Critical Gaps)**

The sliding window is a standard UX pattern, but the current implementation lacks the necessary guardrails to prevent session hijacking or resource exhaustion.

| Trade-off | Risk | Mitigation |
| :--- | :--- | :--- |
| **UX** | Users stay logged in while active | **Infinite Sessions**: Tokens could slide forever |
| **Security** | Stolen tokens remain valid longer | **Max Age**: Implement `maxTokenAgeMs` (e.g., 24h) |

**Required Changes:**
- **Enforce `maxTokenAgeMs`**: Hard limit on session life regardless of activity.
- **Concurrent Limits**: Limit the number of active sessions per user.
- **Grace Period**: Implement a short overlap window during token rotation to prevent race conditions on the client.

---

## 4. Critical Implementation Bugs

### 🚨 XOR Key Rotation (Broken)
The current implementation of the XOR-based key rotation is mathematically flawed. The rotation logic fails to properly update the key state across distributed nodes, leading to intermittent "Invalid Token" errors and, more critically, predictable key sequences that could be exploited to forge tokens.

### 🚨 O(N) SCAN DoS Vector
The session cleanup and lookup logic utilizes a `SCAN` operation without proper pagination or limiting. An attacker can flood the system with orphaned sessions, forcing the server into an $O(N)$ search pattern that spikes CPU to 100% and locks the Redis event loop, effectively taking down the entire Vane instance.

### 🚨 Non-Atomic `verifySession` Race Condition
The session verification process follows a "Read-then-Update" pattern that is not atomic. In high-concurrency environments, two simultaneous requests can trigger a race condition where the session is updated/rotated twice, invalidating the token for the legitimate user and causing unexpected logouts.

---

## 5. P0 Blockers Checklist
The following 9 items **MUST** be fixed before the system is considered for production.

- [ ] **Fix XOR Key Rotation**: Implement a cryptographically secure rotation mechanism (e.g., AES-GCM with versioned keys).
- [ ] **Remediate SCAN DoS**: Replace $O(N)$ scans with indexed lookups or a dedicated TTL-based expiration strategy.
- [ ] **Atomic Session Updates**: Use Lua scripts or Redis transactions (`MULTI/EXEC`) for `verifySession`.
- [ ] **Implement `maxTokenAgeMs`**: Prevent infinite session sliding.
- [ ] **Constant-Time Comparisons**: Eliminate timing attacks in credential verification.
- [ ] **API Key Scoping**: Move away from "all-or-nothing" API keys.
- [ ] **Remove PostgreSQL Fallback**: Eliminate the split-brain risk.
- [ ] **Concurrent Session Caps**: Prevent account-based resource exhaustion.
- [ ] **Grace Period Implementation**: Fix token rotation race conditions for clients.

---

## 6. Infrastructure Requirements

### Metrics & Monitoring
- **Session Churn Rate**: Track `sessions_created` vs `sessions_expired` to detect session stuffing attacks.
- **Redis Latency**: Monitor `redis_cmd_duration_seconds` specifically for session lookups.
- **Auth Failure Rate**: Alert on spikes in `401 Unauthorized` responses (potential brute-force).

### Alerts
- **Critical**: Redis memory usage > 80% (Prevents session eviction/DoS).
- **Warning**: Average session TTL dropping below 5 minutes across the fleet.

### Tuning
- **Redis Eviction Policy**: Must be set to `volatile-lru` to ensure only sessions with TTLs are evicted.
- **Connection Pooling**: Increase pool size to handle the high-frequency nature of session verification.

---

## 7. Deployment Recommendation
**DO NOT DEPLOY.**

The current state of the authentication system represents a liability. The path forward is:
1. **Remediation Phase**: Address the 9 P0 blockers listed above.
2. **Stress Test**: Perform a targeted DoS test against the session store to verify the `SCAN` fix.
3. **Security Audit**: Conduct a focused Round 3 review of the cryptographic rotation logic.
4. **Canary Release**: Deploy to a restricted internal environment before any external exposure.
