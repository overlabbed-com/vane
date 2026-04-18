# Vane Research Engine: Priority Assessment & Remediation Roadmap

**Document Type:** Priority Assessment  
**Date:** 2026-04-17  
**Status:** FINAL — Actionable  
**Scope:** Research Engine Core Design Issues  

---

## Executive Summary

This document synthesizes the findings from the Worker (implementation), Architect (design patterns), and Reviewer (security) analyses regarding four critical design flaws in the Vane Research Engine. These issues collectively threaten the system's data isolation, financial integrity (quota management), and operational stability.

### Priority Matrix

| Issue | Priority | Complexity | Impact | Consensus Rationale |
| :--- | :---: | :---: | :---: | :--- |
| **projectId Spoofing** | **P0** | Low | Critical | Direct violation of multi-tenant isolation; allows cross-project data leakage. |
| **Zombie Race Condition** | **P0** | Medium | Critical | Breaks the staleness guarantee, leading to routing queries to dead workers. |
| **RU Rollback Atomicity** | **P0** | High | Critical | Permanent quota leakage on process crash; leads to service-wide starvation. |
| **Heartbeat TTL** | **P1** | Low | High | Causes false-positive failovers and operational noise under load. |

---

## Detailed Analysis

### 1. projectId Spoofing in Submit Endpoint
**Priority:** P0 | **Complexity:** Low

#### Analysis
The `submit` endpoint currently trusts the `projectId` provided in the client request body. While it validates that the user is a member of that project, it does not enforce the project context associated with the authentication token. An attacker with membership in multiple projects can spoof the `projectId` to query data from projects they should not be accessing in the current session.

- **Operational/Security Impact:** Cross-project data leakage, GDPR/CCPA compliance violations, and corrupted audit trails.
- **Consensus:** This is the highest security risk as it breaks the fundamental tenant isolation boundary.

#### Recommended Fix: Auth Token as Sole Source
Remove `projectId` from the request body and derive it exclusively from the validated `AuthContext` provided by the authentication middleware.

```typescript
async function submitQuery(auth: AuthContext, request: SubmitRequest) {
  // CRITICAL: Ignore client-provided projectId. Use token-sourced ID.
  const projectId = auth.projectId; 
  
  // Defense-in-depth: verify membership is still active
  if (!await validateProjectMembership(auth.userId, projectId)) {
    throw new Error('PROJECT_ACCESS_REVOKED');
  }

  return await vectorDB.query(projectId, request.query, {
    projectId, // Enforce in filter
    ...request.filters,
  });
}
```

- **Rollback Plan:** Re-introduce the request body parameter and revert to the `validateResourceAccess` check.

---

### 2. Zombie Detection Race Condition
**Priority:** P0 | **Complexity:** Medium

#### Analysis
The current zombie detection uses a non-atomic sequence of `ZADD` (update score) and `ZSCORE`/`ZRANGEBYSCORE` (read score). A race window exists where a worker can be updated to "fresh" but read as "stale" (or vice-versa), causing the system to incorrectly identify healthy workers as zombies or allow dead workers to remain in the pool.

- **Operational/Security Impact:** Routing queries to unresponsive workers (increased latency/timeouts) and inconsistent cache eviction.
- **Consensus:** Critical for system reliability; without atomicity, the "stale detection guarantee" is a probabilistic guess, not a guarantee.

#### Recommended Fix: Lua Script Atomicity
Implement a Lua script to handle the Read-Validate-Update cycle atomically within Redis.

```lua
-- zombie_check.lua
local key = KEYS[1]
local worker_id = ARGV[1]
local now = tonumber(ARGV[2])
local stale_threshold = tonumber(ARGV[3])

local current_score = redis.call('ZSCORE', key, worker_id)
if current_score == false then
    redis.call('ZADD', key, now, worker_id)
    return {1, now}
end

if (now - tonumber(current_score)) > stale_threshold then
    redis.call('ZREM', key, worker_id)
    return {0, -1}
else
    redis.call('ZADD', key, now, worker_id)
    return {2, now}
end
```

- **Rollback Plan:** Revert to the TypeScript-based pipeline implementation.

---

### 3. RU Pre-Reservation Rollback Not Atomic
**Priority:** P0 | **Complexity:** High

#### Analysis
The system reserves Research Units (RU) before execution. However, the rollback (returning RUs on failure) is not atomic with the deletion of the reservation key. If the process crashes between `redis.del(reservation)` and `user_quota += amount`, the RUs are permanently leaked.

- **Operational/Security Impact:** Progressive quota starvation. Users will eventually be unable to query despite having "available" credits.
- **Consensus:** This is a "silent killer" bug. It doesn't cause immediate crashes but degrades the service into an unusable state over time.

#### Recommended Fix: Reservation Tokens + Lua
Use a token-based system where the reservation and the quota deduction happen in one Lua script, and the commit/rollback are also atomic.

```typescript
// Atomic Rollback Lua
const rollbackScript = `
  redis.call('DEL', KEYS[1]) -- Delete reservation token
  redis.call('INCRBY', KEYS[2], ARGV[1]) -- Restore quota
  return 1
`;
await redis.eval(rollbackScript, [reservKey, quotaKey], [amount.toString()]);
```

- **Rollback Plan:** Revert to simple `DECRBY`/`INCRBY` calls with a background cleanup job to recover leaked RUs based on TTL.

---

### 4. Heartbeat TTL Too Tight
**Priority:** P1 | **Complexity:** Low

#### Analysis
The current 60s TTL with 30s refresh provides a very narrow margin. Minor network spikes, Redis latency, or GC pauses can cause a worker to miss a heartbeat, leading to a false-positive "stale" detection and unnecessary failover.

- **Operational/Security Impact:** Unnecessary query rerouting, increased p99 latency, and "alert fatigue" from false-positive zombie detections.
- **Consensus:** High operational impact but does not compromise data integrity or security.

#### Recommended Fix: Conservative TTL + Grace Period
Increase the TTL to 300s and introduce a explicit grace period before marking a worker as stale.

```typescript
const CONFIG = {
  ttlSeconds: 300,           // 5 minutes
  refreshIntervalMs: 60000,   // 1 minute
  staleThresholdMs: 330000,  // 5.5 minutes (TTL + 30s grace)
};
```

- **Rollback Plan:** Revert TTL and interval constants to 60/30.

---

## Implementation Roadmap

### Phase 1: Security & Isolation (Immediate)
- **Task:** Implement `projectId` Auth-Sourcing.
- **Acceptance Criteria:** 
  - [ ] Request body `projectId` is ignored.
  - [ ] Queries are restricted to the `projectId` in the JWT/Session.
  - [ ] Unit tests confirm 403 when attempting to access a project not in the token.

### Phase 2: Atomicity & Stability (Short-term)
- **Task:** Deploy Lua scripts for Zombie Detection and RU Rollbacks.
- **Acceptance Criteria:**
  - [ ] Zombie detection race condition eliminated (verified via concurrency test).
  - [ ] RU leaks = 0 during simulated process crashes (Chaos testing).
  - [ ] Redis CPU overhead remains < 5% increase.

### Phase 3: Operational Tuning (Maintenance)
- **Task:** Update Heartbeat TTL and Grace Period.
- **Acceptance Criteria:**
  - [ ] False-positive stale detections drop by > 90%.
  - [ ] Failover latency remains within acceptable bounds (under 6 mins).

---

## Final Acceptance Criteria

| Fix | Verification Method | Success Metric |
| :--- | :--- | :--- |
| **projectId** | Adversarial Request | 0 successful spoofed queries |
| **Zombie** | High-concurrency Heartbeats | 0 inconsistent state reads |
| **RU Rollback** | `kill -9` during rollback | 100% quota restoration |
| **Heartbeat** | Synthetic Latency Injection | 0 false-positives at 500ms latency |
