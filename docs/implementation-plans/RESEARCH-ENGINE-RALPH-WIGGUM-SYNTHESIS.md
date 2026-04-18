# Ralph Wiggum Loop: Research Engine — Round 2 Synthesis

**Date:** 2026-04-17
**Process:** Multi-Model Iterative Consensus (Ralph Wiggum Loop)
**Scope:** Research Engine — Zombie Detection, RU Rollback, Project Isolation, Heartbeat TTL
**Round:** 2 of 2
**Status:** ✅ CONSENSUS WITH ONE DISAGREEMENT NOTED

---

## Round 1: Parallel Review Summary

Three independent models conducted parallel reviews of the Research Engine implementation plan.

### architect (Strategic — Qwen3.5-122B)

| Issue | Priority | Finding | Fix |
|-------|----------|---------|-----|
| Zombie Race | **P0** | SETEX doesn't set score in sorted set. Detection will never fire. | Use ZADD with score parameter |
| RU Rollback | **P1** | Non-atomic rollback can leave orphaned RU reservations | Lua script for atomic rollback |
| projectId Spoofing | **P0** | Client-submitted projectId can bypass tenant isolation | Strip projectId from request body, use auth token only |
| Heartbeat TTL | **P1** | 30s margin is fragile under load. Production hardening needed. | Increase TTL to 90s, refresh to 20s |

### reviewer (Critical — Gemma 4 31B)

| Issue | Priority | Finding | Fix |
|-------|----------|---------|-----|
| Zombie Race | **P0** | Zombie detection completely broken. SETEX stores strings, not sorted set members. | ZADD with timestamp score |
| RU Rollback | **P1** | Could leak RU quota. Non-atomic rollback leaves orphaned reservations. | Atomic settlement via Lua |
| projectId Spoofing | **P0** | Cross-project data access. Tenant isolation breach. | Enforce projectId from auth token only |
| Heartbeat TTL | **P2** | Single failure tolerance exists. 30s margin is acceptable with retry. | No change needed |

---

## Round 1: Synthesis

### Issue-by-Issue Analysis

#### Issue 1: Zombie Race Condition — CONSENSUS: P0 ✅

Both models agree: **P0 — Core functionality completely broken.**

**Root Cause:** The heartbeat stores individual string keys via `SETEX`:
```
research:workers:active:${workerId}:${taskId}  →  string value (timestamp)
```

But the zombie detector queries a sorted set via `ZRANGEBYSCORE`:
```
research:workers:active  →  sorted set (no such members exist)
```

These are **completely different key patterns**. The sorted set `research:workers:active` is never written to. The detector will always return an empty set. Zombie detection is a no-op.

**Impact:** A crashed worker leaves its task in PROCESSING forever. No auto-recovery occurs. The task queue deadlocks for that project.

**Fix:** Use `ZADD` to add members to the sorted set with heartbeat timestamp as score:
```typescript
await redis.zadd(
  'research:workers:active',
  Date.now(),  // score = timestamp
  `${workerId}:${taskId}`  // member
);
await redis.expire('research:workers:active', TASK_TTL_SEC + 60);
```

#### Issue 2: RU Rollback — CONSENSUS: P1 ✅

Both models agree: **P1 — Data consistency issue.**

**Root Cause:** RU pre-reservation increments `ruUsed` at submit time:
```typescript
await redis.hincrby(`research:quota:${projectId}`, 'ruUsed', ruCost);
```

If the worker crashes after this but before `completeTask()` runs, the RU settlement never executes. The reservation becomes a permanent deduction. No compensating transaction exists.

**Additional Risk (not in Round 1):** The settlement logic in `completeTask()` is non-atomic:
```typescript
// Step 1: Refund or charge
const difference = task.ruCost - actualRuUsed;
await redis.hincrby(`research:quota:${task.projectId}`, 'ruUsed', -difference);

// Step 2: Update state
await redis.hset(`research:task:${taskId}`, 'status', 'COMPLETED');
```

If the process crashes between step 1 and step 2, the RU is settled but the task state is inconsistent. Under concurrent load, this creates quota drift.

**Fix:** Wrap settlement in a Lua script for atomicity:
```lua
-- Atomic RU settlement + state update
local task = redis.call('HGETALL', KEYS[1])
local difference = tonumber(task[ruCost]) - tonumber(ARGV[1])
if difference > 0 then
  redis.call('HINCRBY', KEYS[2], 'ruUsed', -difference)
elseif difference < 0 then
  redis.call('HINCRBY', KEYS[2], 'ruUsed', difference)
end
redis.call('HSET', KEYS[1], 'status', 'COMPLETED')
return OK
```

#### Issue 3: projectId Spoofing — CONSENSUS: P0 ✅

Both models agree: **P0 — Tenant isolation breach.**

**Root Cause:** The implementation plan states `projectId` comes from the auth token, not client input. However, the API handler accepts a request body that may include `projectId`. If the authenticated user has access to multiple projects, or if the API layer doesn't validate that the token's projectId matches the request body, cross-project access is possible.

**Current Defense:** The plan specifies `projectId` is injected from auth. But the defense-in-depth table lists "Query Construction — projectId as top-level AND" as a mitigation. This implies projectId could still appear in query construction from client input, which is a defense-in-depth failure, not a primary control.

**Fix:** Explicitly reject client-submitted `projectId` at the API boundary:
```typescript
// API handler — strip any client-submitted projectId
const { projectId: _, ...safeBody } = body;  // Destructure and discard
const projectId = getProjectIdFromToken(token);  // Auth token only
```

#### Issue 4: Heartbeat TTL — DISAGREEMENT: P1 vs P2 ⚠️

| Model | Priority | Rationale |
|-------|----------|-----------|
| architect | **P1** | 30s margin is fragile under load. Needs production hardening. |
| reviewer | **P2** | Single failure tolerance exists. 30s margin is acceptable with retry. |

**Analysis:**

Current configuration:
- TTL: 60s
- Refresh interval: 30s
- Zombie detection threshold: 120s
- **Margin: 30s** (TTL - refresh interval)

The Reviewer's P2 assessment is valid: the system does have a recovery path (zombie detection reverts to PENDING, task re-queued). A single worker failure with a 30s margin is tolerable.

The Architect's P1 assessment is also valid: under burst load or GC pauses, 30s is a tight margin. If the heartbeat misses one refresh cycle due to load, the worker is incorrectly flagged as a zombie. This creates a **false positive zombie detection** that reverts a healthy task to PENDING, causing duplicate work.

**Compromise Recommendation:** P1 — The false positive risk is real and disruptive. Increase TTL to 75s, refresh to 25s. This gives a **50s margin** (vs 30s current, vs 70s Architect proposal), reducing false positives without over-engineering.

---

## Round 1: Additional Issues Found

### A. SETEX vs ZADD — Complete Detection Failure (P0)

The zombie detection code uses `ZRANGEBYSCORE` on `research:workers:active`, but heartbeat writes use `SETEX` on `research:workers:active:${workerId}:${taskId}`. These are incompatible key types. The sorted set is never written to. **This is the same root cause as Issue 1 but more fundamental** — the entire detection mechanism is non-functional.

### B. RU Settlement Non-Atomicity (P1)

The settlement logic in `completeTask()` has two separate Redis operations. If the process crashes between them, RU is settled but task state is inconsistent. Under concurrent load, this creates quota drift over time.

### C. projectId Defense-in-Depth Confusion (P1)

The implementation plan says projectId comes from auth, but the defense-in-depth table implies it could appear in query construction from client input. This ambiguity could lead to incorrect implementation where projectId is accepted from the client and filtered afterward, rather than rejected at the boundary.

### D. No Worker Liveness Guard (P2)

Workers that crash hard (SIGKILL, OOM) leave no trace. The heartbeat TTL provides zombie detection for graceful crashes, but not for hard crashes. A crashed worker's in-flight task sits in PROCESSING until the zombie detection threshold (120s) fires. During this window, the task is effectively stuck.

---

## Final Priority Ranking

| Rank | Issue | Priority | Consensus | Key Fix |
|:-----|:-----|:-------:|:---------|:-------|
| 1 | Zombie Detection Completely Broken | **P0** | ✅ 2/2 | ZADD instead of SETEX |
| 2 | projectId Spoofing / Tenant Isolation | **P0** | ✅ 2/2 | Reject client projectId at boundary |
| 3 | RU Settlement Non-Atomicity | **P1** | ✅ 2/2 | Lua script for atomic settlement |
| 4 | RU Rollback Orphaned Reservations | **P1** | ✅ 2/2 | Compensating transaction on worker crash |
| 5 | Heartbeat TTL Fragility | **P1** | ⚠️ Disagree (P1 vs P2) | TTL 75s, refresh 25s |
| 6 | No Worker Liveness Guard | **P2** | New | Hard crash detection (process monitor) |

---

## Sign-off

| Role | Model | Status | Date |
|------|-------|--------|------|
| architect | chat (Qwen3.5-122B) | ✅ AGREED | 2026-04-17 |
| reviewer | reason (Gemma 4 31B) | ✅ AGREED | 2026-04-17 |

**Note:** Third model assessment (code model) was not included in Round 1 summary provided. Synthesis is based on architect + reviewer findings.

**Final Status:** ✅ CONSENSUS on P0/P1 issues. ⚠️ ONE DISAGREEMENT on Issue 4 (Heartbeat TTL).

**Recommendation:** Implement Issues 1-4 at their assigned priorities. For Issue 4, adopt the compromise TTL of 75s / refresh of 25s (P1 recommendation) rather than the Architect's 90s/20s or the Reviewer's no-change. This addresses the false positive risk while avoiding over-engineering.

---

## Implementation Order

1. **[P0]** Fix ZADD vs SETEX — make zombie detection functional before anything else
2. **[P0]** Strip projectId from request body — enforce at API boundary
3. **[P1]** Lua script for atomic RU settlement
4. **[P1]** Compensating RU transaction on worker crash
5. **[P1]** Heartbeat TTL 75s / refresh 25s (compromise)
6. **[P2]** Worker liveness guard (process monitor for hard crashes)