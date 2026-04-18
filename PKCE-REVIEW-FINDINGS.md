# Ralph Wiggum Adversarial Review: PKCE OAuth Implementation

**Review Date:** 2026-04-17  
**Project:** Vane OAuth  
**Review Type:** PKCE Implementation Design Review  
**Reviewers:** 3 independent agents (reviewer model on dockp02)

---

## Executive Summary

**Verdict:** ⚠️ **CONDITIONAL APPROVAL** - Required changes must be implemented before proceeding.

The PKCE implementation plan demonstrates a solid understanding of RFC 7636 but contains **3 critical flaws** and **5 warnings** that must be addressed before implementation. The core flow is correct, but the execution details introduce security vulnerabilities and potential denial-of-service vectors.

---

## Critical Findings (Must Fix)

### 1. Race Condition in Atomic Delete Pattern ⚠️

**Severity:** Critical  
**Found by:** Agent 2

**Issue:** The proposed flow executes deletion *after* token exchange:
```
6. Look up code_verifier by state
7. Exchange code for tokens using code_verifier
8. Atomically delete code_verifier (prevent replay)
```

**Risk:** If a stolen authorization code is presented to the callback endpoint faster than step 8 executes, an attacker could exchange the same code multiple times before the verifier is deleted.

**Required Fix:** The deletion must occur **before** or **during** the token exchange, not after. The Lua script should be the *first* operation in the callback handler, and if it returns `nil`, the request should be rejected immediately without attempting token exchange.

**Corrected Flow:**
```typescript
// 1. Atomic read-and-delete FIRST
const verifier = await redis.eval(PKCE_DELETE_SCRIPT, ['pkce:' + state]);
if (!verifier) {
  return reject('Invalid or expired code verifier');
}

// 2. THEN exchange code with the retrieved verifier
const tokens = await exchangeCodeForTokens(code, verifier);
```

---

### 2. Lua Script Syntax Error ⚠️

**Severity:** Critical  
**Found by:** Agent 3

**Issue:** The provided Lua script has incorrect syntax:
```lua
-- WRONG (as provided in design):
local verifier = GET KEYS[1]

-- CORRECT:
local verifier = redis.call('GET', KEYS[1])
```

**Risk:** The script will fail to execute, causing the entire OAuth callback flow to crash. This is a Denial-of-Service vulnerability for all authentication.

**Required Fix:** Use the correct Redis Lua API:
```typescript
const PKCE_DELETE_SCRIPT = `
  local verifier = redis.call('GET', KEYS[1])
  if verifier then
    redis.call('DEL', KEYS[1])
    return verifier
  end
  return nil
`;
```

---

### 3. State-to-Verifier Coupling Vulnerability ⚠️

**Severity:** Critical  
**Found by:** Agent 1, Agent 3

**Issue:** The `code_verifier` is stored in Redis keyed by the `state` nonce. If the `state` is leaked (via Referer headers, server logs, or browser history), an attacker can:
1. Retrieve the `code_verifier` from Redis
2. Use it to validate any intercepted authorization code
3. Bypass the PKCE protection entirely

**Risk:** PKCE's security guarantee is that only the party that generated the `code_verifier` can complete the flow. Coupling it to `state` creates a single point of failure for both CSRF and PKCE protections.

**Required Fix:** Use **independent, high-entropy identifiers** for PKCE storage:
```typescript
// Generate separate PKCE identifier
const pkceId = randomBytes(32).toString('hex'); // Independent from state

// Store verifier keyed by pkceId, not state
await redis.setex(`pkce:${pkceId}`, 600, codeVerifier);

// Send pkceId as additional parameter (or embed in state)
// But do NOT use state as the Redis key
```

**Alternative:** If you must use state as the key, ensure:
- State is never logged (sanitize all logs)
- State is not sent in Referer headers (use POST for callback if possible)
- State has high entropy (32+ bytes of CSPRNG output)

---

## Warnings (Should Fix)

### 4. Missing Redis TTL for code_verifier ⚠️

**Severity:** High  
**Found by:** All 3 agents

**Issue:** The design mentions storing `code_verifier` in Redis but does not specify a TTL.

**Risk:** Memory exhaustion attack (DoS) via "half-open" OAuth flows. An attacker could initiate thousands of OAuth flows without completing them, filling Redis with orphaned `code_verifier` entries.

**Required Fix:** Enforce a strict TTL matching the OAuth flow timeout:
```typescript
// 10 minutes - matches state nonce TTL
await redis.setex(`pkce:${pkceId}`, 600, codeVerifier);
```

---

### 5. Rate Limiting Strategy Flaws ⚠️

**Severity:** High  
**Found by:** All 3 agents

**Issue A - Callback endpoint (`IP + state`):**
The `state` parameter is unique per request, so rate limiting by `IP + state` provides **zero protection** against flooding. An attacker can generate unlimited unique states to bypass the limit.

**Issue B - Initiation endpoint (`IP + user_agent`):**
User-Agent headers are trivially spoofable and unstable (browsers change them frequently). This provides minimal protection against distributed attacks.

**Required Fix:**

**Callback endpoint:**
```typescript
// Rate limit by IP alone (stricter)
await checkRateLimit(clientIp, 'oauth_callback', { maxRequests: 10, windowMs: 60000 });

// OR: Rate limit by active state count per IP
const activeStates = await redis.zcard(`oauth:active_states:${clientIp}`);
if (activeStates > 5) {
  return reject('Too many concurrent OAuth flows');
}
```

**Initiation endpoint:**
```typescript
// Rate limit by IP with stricter limits
await checkRateLimit(clientIp, 'oauth_initiate', { maxRequests: 5, windowMs: 60000 });

// Add CAPTCHA after 3 failed attempts
// Or implement device fingerprinting beyond User-Agent
```

---

### 6. Entropy Source Ambiguity ⚠️

**Severity:** High  
**Found by:** Agent 2, Agent 3

**Issue:** The design specifies "random string" but does not mandate a cryptographically secure source.

**Risk:** If `Math.random()` is used instead of `crypto.randomBytes()`, the `code_verifier` becomes predictable, completely defeating PKCE's security guarantees.

**Required Fix:** Explicitly use CSPRNG:
```typescript
import { randomBytes } from 'crypto';

// Generate 32 bytes (256 bits of entropy)
const verifierBytes = randomBytes(32);
const codeVerifier = verifierBytes.toString('base64url');
// Result: 43-character base64url string (meets RFC 7636 minimum)
```

---

### 7. code_challenge_method Not Specified ⚠️

**Severity:** Medium  
**Found by:** Agent 1, Agent 2, Agent 3

**Issue:** The design does not explicitly set `code_challenge_method=S256` in the OAuth URL.

**Risk:** Google may default to `plain` method or no PKCE, which provides less security than S256.

**Required Fix:** Explicitly specify S256:
```typescript
const params = new URLSearchParams({
  // ... other params
  code_challenge: codeChallenge,
  code_challenge_method: 'S256',  // EXPLICIT
});
```

---

### 8. Secret Leakage in Logs ⚠️

**Severity:** Medium  
**Found by:** Agent 1

**Issue:** The Lua script returns the `code_verifier` to the application. If this return value is logged during error handling or debugging, the secret is leaked.

**Risk:** `code_verifier` exposure allows an attacker to complete any intercepted OAuth flow.

**Required Fix:** Return a boolean success indicator, not the verifier:
```typescript
const PKCE_DELETE_SCRIPT = `
  local verifier = redis.call('GET', KEYS[1])
  if verifier then
    redis.call('DEL', KEYS[1])
    return 1  -- Return success indicator, not the verifier
  end
  return nil
`;

const success = await redis.eval(PKCE_DELETE_SCRIPT, ['pkce:' + state]);
if (!success) {
  return reject('Invalid PKCE state');
}
// Retrieve verifier separately if needed (or store it in memory before delete)
```

**Better approach:** Store the verifier in memory before calling the script:
```typescript
const key = `pkce:${state}`;
const verifier = await redis.get(key);
if (!verifier) {
  return reject('Invalid PKCE state');
}
await redis.del(key);  // Delete after retrieval
// Use verifier for token exchange
```

---

## Edge Cases Not Covered

### 9. Missing Edge Cases

| Edge Case | Risk | Recommendation |
|-----------|------|----------------|
| **Redis failure during callback** | Auth flow breaks | Implement circuit breaker; fail closed (reject request) |
| **Clock skew between app and Redis** | TTL validation issues | Use Redis server time, not client time |
| **Concurrent callback requests** | Race condition on verifier | Atomic delete handles this, but add idempotency check |
| **Code expired before callback** | Token exchange fails | Add explicit error handling for `expired_token` |
| **State collision (extremely rare)** | CSRF bypass | Use 32+ bytes entropy for state |
| **Base64URL padding issues** | Verification fails | Use `toString('base64url')` consistently (no padding) |

---

## Dependencies Analysis

### New Dependencies Required

| Dependency | Purpose | Risk Level |
|------------|---------|------------|
| `crypto` (built-in) | CSPRNG for verifier generation | ✅ None (Node.js built-in) |
| `redis.eval()` | Lua script execution | ⚠️ Requires Redis 2.6+ |
| None | No npm packages needed | ✅ Good |

**Verdict:** ✅ No new npm dependencies required.

---

## RFC 7636 Compliance Checklist

| Requirement | Status | Notes |
|-------------|--------|-------|
| `code_verifier` is 43-128 characters | ⚠️ Not specified | Must enforce in implementation |
| `code_verifier` uses unreserved chars | ⚠️ Not specified | Use base64url encoding |
| `code_challenge` = BASE64URL(SHA256(verifier)) | ✅ Correct | S256 method |
| `code_challenge_method=S256` in request | ⚠️ Not explicit | Must add to URL params |
| `code_verifier` transmitted at token endpoint | ✅ Correct | In `code_verifier` param |
| Server validates challenge against verifier | ✅ Correct | SHA256 comparison |

---

## Recommended Implementation Order

1. **Create `lib/auth/oauth/pkce.ts`** with:
   - `generateCodeVerifier()` using `crypto.randomBytes(32)`
   - `deriveCodeChallenge(verifier)` using SHA256 + base64url
   - `storeCodeVerifier(pkceId, verifier, ttlSeconds)` with Redis SETEX
   - `consumeCodeVerifier(pkceId)` using Lua script (corrected syntax)

2. **Update `lib/auth/oauth/google.ts`**:
   - Add `generatePkce()` function returning `{ codeVerifier, codeChallenge, pkceId }`
   - Add `getGoogleAuthUrlWithPkce(state, codeChallenge)` with `code_challenge_method=S256`

3. **Update `api/auth/oauth/google/route.ts`**:
   - Call `generatePkce()` and store verifier
   - Pass `codeChallenge` to Google URL
   - Rate limit by `IP` (not `IP + user_agent`)

4. **Update `api/auth/oauth/google/callback/route.ts`**:
   - **First** call `consumeCodeVerifier(state)` (atomic delete)
   - If fails, reject immediately
   - Use retrieved verifier in token exchange
   - Rate limit by `IP` (not `IP + state`)

5. **Add tests** for:
   - PKCE generation (entropy, length)
   - Code challenge derivation (SHA256 correctness)
   - Atomic consume (race condition, replay prevention)
   - TTL enforcement (expired verifier rejection)
   - Rate limiting (callback flood, initiation flood)

---

## Final Verdict

**Approval Status:** ⚠️ **CONDITIONAL APPROVAL**

**Required Before Implementation:**
1. Fix atomic delete race condition (delete BEFORE exchange)
2. Correct Lua script syntax
3. Decouple `code_verifier` storage from `state` (use independent `pkceId`)
4. Add Redis TTL (10 minutes)
5. Fix rate limiting keys (use `IP` alone, not `IP + state`)
6. Explicitly use CSPRNG (`crypto.randomBytes`)
7. Explicitly set `code_challenge_method=S256`
8. Prevent secret leakage in logs

**Optional but Recommended:**
- Add constant-time comparison for verifier validation
- Implement comprehensive edge case handling
- Add audit logging for PKCE failures (masked values)

**Estimated Implementation Time:** 2-3 hours (including tests)

---

## Reviewer Notes

**Agent 1:** Focus on state/verifier coupling and log leakage  
**Agent 2:** Focus on race condition in delete sequence  
**Agent 3:** Focus on Lua syntax and rate limiting logic

All three reviewers independently identified the same core issues, confirming their severity. The implementation is feasible but requires careful attention to the critical fixes before proceeding.

---

*Generated by Ralph Wiggum adversarial review process*  
*Review completed: 2026-04-17*
