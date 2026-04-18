# M1 - Error Response Jitter Implementation Plan

**Document Type:** Implementation Plan  
**Date:** 2026-04-17  
**Finding ID:** M1  
**Severity:** P2 (MEDIUM)  
**CWE:** CWE-208 (Timing Attack)  
**Status:** Ready for Implementation  

---

## 1. Executive Summary

This plan adds random jitter (10-50ms) to all authentication failure responses to prevent timing attacks that could determine valid usernames or correct passwords. The jitter is added to error paths only, ensuring consistent response timing that does not leak information about authentication state. Combined with the existing dummy hash verification, this provides defense-in-depth against timing oracle attacks.

**Risk After Implementation:** MEDIUM → LOW  
**Timeline:** 1-2 hours  
**Files Created:** 1 (`lib/auth/timing.ts`)  
**Files Modified:** 2 (`api/auth/login/route.ts`, `api/auth/oauth/google/callback/route.ts`)  

---

## 2. Threat Model

### 2.1 Attack Scenario

An attacker measures response times for login attempts:

```bash
# Measure response time for valid user
time curl -X POST https://vane.example.com/api/auth/login \
  -d '{"email":"admin@example.com","password":"wrong"}'
# Response: ~150ms (user exists, password check takes time)

# Measure response time for invalid user
time curl -X POST https://vane.example.com/api/auth/login \
  -d '{"email":"nonexistent@example.com","password":"wrong"}'
# Response: ~50ms (user not found, no password check)
```

By measuring timing differences, the attacker can enumerate valid email addresses.

### 2.2 Mitigated Threats

| Threat | CWE | Attack Vector | Mitigation |
|:---|:---|:---|:---|
| Username enumeration via timing | CWE-208 | Measure response time differences | Jitter masks timing differences |
| Password enumeration via timing | CWE-208 | Measure password check duration | Jitter + constant-time comparison |
| Brute force acceleration | CWE-307 | Timing shortcuts for valid creds | Consistent timing removes advantage |

### 2.3 Existing Mitigations

The codebase already has partial mitigations:

1. **Dummy hash verification** (`login/route.ts`):
   ```typescript
   if (!user) {
     await verifyPassword(password, DUMMY_HASH); // Timing oracle mitigation
     return NextResponse.json({ error: 'INVALID_CREDENTIALS' }, { status: 401 });
   }
   ```

2. **Constant-time password comparison** (`password.ts`):
   ```typescript
   // argon2.verify uses constant-time comparison internally
   return argon2.verify(hash, password);
   ```

This plan adds jitter to mask any remaining timing variance.

### 2.4 Rate Limit Path

Rate limit exceeded responses should also have jitter:

```
Attacker: Why is this response fast? → Must be rate limited
Attacker: This response is slow → Not rate limited (continue attack)
```

**Mitigation:** Rate limit responses get the same jitter as other errors. Attacker cannot distinguish rate limited requests from regular auth failures based on timing.

### 2.5 Success/Failure Timing Distinction

Successful logins should NOT have jitter:
```
Success: Fast response (no jitter) - attacker already knows creds valid
Failure: Slow response (50-100ms jitter) - masks timing differences
```

**This is intentional.** On successful authentication, the attacker already knows the credentials are valid. Adding jitter to success responses would only harm legitimate users. The security benefit comes from masking failure timing differences.

---

## 3. Implementation Details

### 3.1 Jitter Function

**File:** `lib/auth/timing.ts` (new)

```typescript
/**
 * Timing utilities for defense against timing attacks.
 * 
 * Features:
 * - Random jitter on error responses
 * - Consistent base delay
 * - Constant-time operations
 * 
 * Reference: M1 finding
 */

/**
 * Jitter configuration.
 * Base delay + random jitter = total delay.
 */
const JITTER_CONFIG = {
  // Base delay: 50ms (covers typical Redis variance)
  baseDelayMs: 50,
  // Jitter range: 0-50ms (random additional delay)
  jitterRangeMs: 50,
  // Maximum total delay: 100ms
  maxDelayMs: 100,
} as const;

/**
 * Adds random jitter to response time.
 * Uses a Promise with setTimeout to delay response.
 * 
 * @param baseMs - Base delay in milliseconds (default: 30)
 * @param rangeMs - Jitter range in milliseconds (default: 20)
 * @returns Promise that resolves after the delay
 */
export function addJitter(
  baseMs: number = JITTER_CONFIG.baseDelayMs,
  rangeMs: number = JITTER_CONFIG.jitterRangeMs
): Promise<void> {
  // Calculate jitter: random value between 0 and rangeMs
  const jitter = Math.floor(Math.random() * (rangeMs + 1));
  
  // Total delay = base + jitter (capped at maxDelayMs)
  const totalDelay = Math.min(baseMs + jitter, JITTER_CONFIG.maxDelayMs);
  
  return new Promise(resolve => setTimeout(resolve, totalDelay));
}

/**
 * Gets the current jitter configuration.
 * Useful for testing and monitoring.
 */
export function getJitterConfig(): Readonly<{
  baseDelayMs: number;
  jitterRangeMs: number;
  maxDelayMs: number;
}> {
  return { ...JITTER_CONFIG };
}
```

### 3.2 Login Route Integration

**File:** `api/auth/login/route.ts`

Add jitter to all error response paths:

```typescript
// Import jitter function
import { addJitter } from '@/lib/auth/timing';

// In POST handler

// Error: User not found
if (!user) {
  await logLoginFailure(/* ... */);
  // Existing: Dummy hash verification for timing oracle mitigation
  if (password) {
    await verifyPassword(password, DUMMY_HASH);
  }
  // NEW: Add jitter before error response
  await addJitter();
  return NextResponse.json(
    { error: 'INVALID_CREDENTIALS', message: ERROR_MESSAGES.INVALID_CREDENTIALS },
    { status: 401 }
  );
}

// Error: Invalid password
if (!passwordValid) {
  await logLoginFailure(/* ... */);
  // NEW: Add jitter before error response
  await addJitter();
  return NextResponse.json(
    { error: 'INVALID_CREDENTIALS', message: ERROR_MESSAGES.INVALID_CREDENTIALS },
    { status: 401 }
  );
}

// Error: Invalid API key
if (!apiKeyValid) {
  await logLoginFailure(/* ... */);
  // NEW: Add jitter before error response
  await addJitter();
  return NextResponse.json(
    { error: 'INVALID_CREDENTIALS', message: ERROR_MESSAGES.INVALID_CREDENTIALS },
    { status: 401 }
  );
}

// Error: Internal error
catch (error) {
  console.error(/* ... */);
  // NEW: Add jitter on error paths too
  await addJitter();
  return NextResponse.json(
    { error: 'INTERNAL_ERROR', message: ERROR_MESSAGES.INTERNAL_ERROR },
    { status: 500 }
  );
}
```

### 3.3 OAuth Callback Integration

**File:** `api/auth/oauth/google/callback/route.ts`

Add jitter to error response paths:

```typescript
// Import jitter function
import { addJitter } from '@/lib/auth/timing';

// In GET handler

// Error: OAuth error from Google
if (error) {
  await logLoginFailure(/* ... */);
  // NEW: Add jitter before error response
  await addJitter();
  return NextResponse.json(
    { error: 'GOOGLE_AUTH_FAILED', message: ERROR_MESSAGES.GOOGLE_AUTH_FAILED },
    { status: 401 }
  );
}

// Error: Invalid state
if (!stateValid) {
  await logLoginFailure(/* ... */);
  // NEW: Add jitter before error response
  await addJitter();
  return NextResponse.json(
    { error: 'INVALID_STATE', message: ERROR_MESSAGES.INVALID_STATE },
    { status: 400 }
  );
}

// Error: Missing code
if (!code) {
  await logLoginFailure(/* ... */);
  // NEW: Add jitter before error response
  await addJitter();
  return NextResponse.json(
    { error: 'MISSING_CODE', message: ERROR_MESSAGES.MISSING_CODE },
    { status: 400 }
  );
}

// Error: PKCE verifier not found
if (!codeVerifier) {
  await logLoginFailure(/* ... */);
  // NEW: Add jitter before error response
  await addJitter();
  return NextResponse.json(
    { error: 'INVALID_STATE', message: ERROR_MESSAGES.INVALID_STATE },
    { status: 400 }
  );
}

// Error: Unverified email
if (!googleUser.email_verified) {
  await logLoginFailure(/* ... */);
  // NEW: Add jitter before error response
  await addJitter();
  return NextResponse.json(
    { error: 'GOOGLE_AUTH_FAILED', message: 'Email not verified by Google' },
    { status: 401 }
  );
}

// Error: Internal error
catch (error) {
  console.error(/* ... */);
  // NEW: Add jitter on error paths too
  await addJitter();
  return NextResponse.json(
    { error: 'INTERNAL_ERROR', message: ERROR_MESSAGES.INTERNAL_ERROR },
    { status: 500 }
  );
}
```

### 3.4 Consistent Hash Timing

The existing dummy hash verification already provides timing consistency:

```typescript
// In login/route.ts (existing code)
if (!user) {
  // Dummy hash verification ensures password check always runs
  if (password) {
    await verifyPassword(password, DUMMY_HASH);
  }
  await addJitter();
  return error();
}
```

This ensures that both existing-user-wrong-password and non-existent-user take similar time because both perform Argon2id verification.

---

## 4. Files to Create/Modify

### 4.1 New Files

| File | Purpose | Lines |
|:---|:---|:---|
| `lib/auth/timing.ts` | Jitter function and configuration | ~50 |
| `lib/auth/timing.test.ts` | Unit tests for jitter function | ~50 |

### 4.2 Modified Files

| File | Change | Lines |
|:---|:---|:---|
| `api/auth/login/route.ts` | Add `await addJitter()` to error paths | ~10 |
| `api/auth/oauth/google/callback/route.ts` | Add `await addJitter()` to error paths | ~15 |

---

## 5. Test Cases

### 5.1 Jitter Range Tests

```typescript
// lib/auth/timing.test.ts

it('adds delay between base and max', async () => {
  const config = getJitterConfig();
  const start = Date.now();
  
  await addJitter();
  
  const elapsed = Date.now() - start;
  expect(elapsed).toBeGreaterThanOrEqual(config.baseDelayMs);
  expect(elapsed).toBeLessThanOrEqual(config.maxDelayMs);
});

it('adds jitter within range', async () => {
  const config = getJitterConfig();
  const start = Date.now();
  
  await addJitter();
  
  const elapsed = Date.now() - start;
  // Jitter is 0 to rangeMs, so total is base to base+range
  expect(elapsed).toBeGreaterThanOrEqual(config.baseDelayMs);
  expect(elapsed).toBeLessThanOrEqual(config.baseDelayMs + config.jitterRangeMs);
});

it('produces variable delays', async () => {
  const delays: number[] = [];
  
  for (let i = 0; i < 10; i++) {
    const start = Date.now();
    await addJitter();
    delays.push(Date.now() - start);
  }
  
  // At least some variation expected (random jitter)
  const uniqueDelays = new Set(delays).size;
  expect(uniqueDelays).toBeGreaterThan(1);
});
```

### 5.2 Custom Delay Tests

```typescript
it('respects custom base delay', async () => {
  const start = Date.now();
  
  await addJitter(100, 0); // Fixed 100ms delay
  
  const elapsed = Date.now() - start;
  expect(elapsed).toBeGreaterThanOrEqual(100);
  expect(elapsed).toBeLessThan(110); // Allow small variance
});

it('respects custom jitter range', async () => {
  const start = Date.now();
  
  await addJitter(50, 10); // 50ms base + 0-10ms jitter
  
  const elapsed = Date.now() - start;
  expect(elapsed).toBeGreaterThanOrEqual(50);
  expect(elapsed).toBeLessThanOrEqual(65); // 50 + 10 + small variance
});
```

### 5.3 Integration Tests

```typescript
it('adds jitter on login failure', async () => {
  const start = Date.now();
  
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'nonexistent@example.com',
      password: 'wrong'
    })
  });
  
  const elapsed = Date.now() - start;
  expect(response.status).toBe(401);
  expect(elapsed).toBeGreaterThanOrEqual(30); // Base delay
  expect(elapsed).toBeLessThan(60); // Max delay
});

it('adds jitter on invalid password', async () => {
  const start = Date.now();
  
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'user@example.com',
      password: 'wrong'
    })
  });
  
  const elapsed = Date.now() - start;
  expect(response.status).toBe(401);
  expect(elapsed).toBeGreaterThanOrEqual(30);
  expect(elapsed).toBeLessThan(60);
});
```

### 5.4 No Jitter on Success Tests

```typescript
it('no jitter on successful login', async () => {
  const start = Date.now();
  
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'user@example.com',
      password: 'correct'
    })
  });
  
  const elapsed = Date.now() - start;
  expect(response.status).toBe(200);
  // Success should be fast (no jitter)
  expect(elapsed).toBeLessThan(100);
});
```

### 5.5 Integration Test for Rate Limit Path

```typescript
it('adds jitter on rate limit exceeded', async () => {
  // Make many requests to trigger rate limit
  for (let i = 0; i < 10; i++) {
    await fetch('/api/auth/login', { ... });
  }
  
  const start = Date.now();
  const response = await fetch('/api/auth/login', { ... });
  const elapsed = Date.now() - start;
  
  expect(response.status).toBe(429);
  expect(elapsed).toBeGreaterThanOrEqual(50); // Base delay
  expect(elapsed).toBeLessThan(110); // Max + small variance
});
```

---

## 6. Edge Cases

### 6.1 High-Latency Redis

If Redis latency is high (e.g., 100ms), the total error response time becomes:

```
Total = Redis latency + Argon2id time + Jitter
      = 100ms + 50ms + 50ms
      = 200ms
```

**Mitigation:** Jitter is additive, not cumulative. The jitter is added AFTER the operation completes, so high Redis latency is not masked but also not amplified.

### 6.2 Multiple Auth Failures

If a user fails authentication multiple times:

```
Request 1: Error after 200ms (high Redis) + 50ms jitter = 250ms
Request 2: Error after 50ms (low Redis) + 50ms jitter = 100ms
Request 3: Error after 100ms (avg Redis) + 50ms jitter = 150ms
```

**Mitigation:** The jitter masks the variance between requests. The absolute timing still varies, but the attacker cannot easily distinguish between "user not found" and "wrong password" because both get the same jitter.

### 6.3 Success Path Timing

Successful logins should NOT have jitter added:

```
Success: Fast response (no artificial delay)
Failure: Delayed response (jitter added)
```

**Mitigation:** Jitter is only added to error paths. Success responses are fast, which is acceptable because the attacker already knows the credentials are valid.

### 6.4 Rate Limiting Interaction

Rate limiting adds additional delay:

```
Rate limited: 429 response + jitter
```

**Mitigation:** Rate limit check happens BEFORE jitter. The rate limit response gets jitter, which is fine because the attacker already knows they're rate limited.

### 6.5 Timeout Scenarios

If an operation times out:

```
Timeout: 500 error + jitter
```

**Mitigation:** Timeouts are already slow (5+ seconds). Adding 50ms jitter is negligible. The timeout itself is the dominant factor.

---

## 7. Integration Points

### 7.1 Login Endpoint

**File:** `api/auth/login/route.ts`

```
POST /api/auth/login
  ├── Check rate limit (existing)
  ├── Validate request (existing)
  ├── Get user (existing)
  ├── Verify password (existing)
  │   └── Dummy hash if user not found (existing)
  ├── Create session (existing)
  └── Error paths:
      ├── User not found + addJitter() (NEW)
      ├── Invalid password + addJitter() (NEW)
      ├── Invalid API key + addJitter() (NEW)
      └── Internal error + addJitter() (NEW)
```

### 7.2 OAuth Callback

**File:** `api/auth/oauth/google/callback/route.ts`

```
GET /api/auth/oauth/google/callback
  ├── Check rate limit (existing)
  ├── Validate state (existing)
  ├── Exchange code (existing)
  ├── Get Google user (existing)
  └── Error paths:
      ├── OAuth error + addJitter() (NEW)
      ├── Invalid state + addJitter() (NEW)
      ├── Missing code + addJitter() (NEW)
      ├── PKCE failure + addJitter() (NEW)
      ├── Unverified email + addJitter() (NEW)
      └── Internal error + addJitter() (NEW)
```

### 7.3 Future Endpoints

Any future authentication endpoint should add jitter to error paths:

```typescript
// Example pattern
try {
  // ... auth logic ...
} catch (error) {
  await addJitter();
  return NextResponse.json({ error: 'ERROR' }, { status: 500 });
}
```

---

## 8. Verification Steps

### 8.1 Unit Tests

```bash
npm test -- lib/auth/timing.test.ts
# Expected: All tests pass
```

### 8.2 Timing Tests

```bash
# Test 1: Measure error response timing
for i in {1..10}; do
  time curl -s -X POST https://vane.example.com/api/auth/login \
    -d '{"email":"nonexistent@example.com","password":"wrong"}' &
done | grep real
# Expected: 0.03-0.05 range (consistent jitter)

# Test 2: Measure valid user error timing
for i in {1..10}; do
  time curl -s -X POST https://vane.example.com/api/auth/login \
    -d '{"email":"user@example.com","password":"wrong"}' &
done | grep real
# Expected: Similar range to nonexistent user

# Test 3: Measure success timing
for i in {1..10}; do
  time curl -s -X POST https://vane.example.com/api/auth/login \
    -d '{"email":"user@example.com","password":"correct"}' &
done | grep real
# Expected: Faster than error responses (< 0.1s)
```

### 8.3 Statistical Tests

```bash
# Collect timing samples
for i in {1..100}; do
  curl -s -X POST https://vane.example.com/api/auth/login \
    -d '{"email":"nonexistent@example.com","password":"wrong"}' \
    -w "%{time_total}\n" -o /dev/null
done > timing_samples.txt

# Analyze timing distribution
python3 << EOF
import statistics

with open('timing_samples.txt') as f:
    samples = [float(line.strip()) for line in f if line.strip()]

mean = statistics.mean(samples)
stdev = statistics.stdev(samples)
min_val = min(samples)
max_val = max(samples)

print(f"Mean: {mean:.3f}s")
print(f"Stdev: {stdev:.3f}s")
print(f"Min: {min_val:.3f}s")
print(f"Max: {max_val:.3f}s")

# Check for timing oracle (high variance indicates leak)
if stdev > 0.05:
    print("WARNING: High variance detected - timing oracle may exist")
else:
    print("OK: Timing is consistent")
EOF
```

---

## 9. Acceptance Criteria

- [ ] Jitter added to all login error paths
- [ ] Jitter added to all OAuth callback error paths
- [ ] Jitter range: 50-100ms (base + random)
- [ ] No jitter on success paths
- [ ] Timing variance reduced on error responses
- [ ] Unit tests: 100% coverage for timing functions
- [ ] No timing oracle detectable via statistical analysis
- [ ] Jitter added to rate limit exceeded responses
- [ ] Success responses have no jitter

---

## 10. Dependencies

| Dependency | Required For | Status |
|:---|:---|:---|
| None | Standalone implementation | N/A |

---

## 11. Security Considerations

### 11.1 Jitter Adequacy

The 20ms jitter range is sufficient to mask timing differences from:

- Argon2id variance (typically ±10ms)
- Redis latency variance (typically ±20ms)
- Node.js event loop variance (typically ±5ms)

Combined variance without jitter: ~35ms  
Jitter range: 20ms  
Total coverage: ~55ms (sufficient to mask combined variance)

### 11.2 Performance Impact

Jitter adds 30-50ms to error responses:

- User experience: Negligible (errors are already slow)
- Throughput: Minimal (error responses are rare compared to successes)
- DoS risk: Low (jitter is small compared to rate limiting)

### 11.3 Bypass Prevention

An attacker cannot bypass jitter by:

1. **Sending many requests:** Rate limiting still applies
2. **Measuring average timing:** Jitter is random per request
3. **Filtering outliers:** Jitter affects all error responses

---

## 12. Next Steps

1. **Implement:** Create `lib/auth/timing.ts` with jitter function
2. **Test:** Add unit tests in `lib/auth/timing.test.ts`
3. **Integrate:** Add jitter to login route error paths
4. **Integrate:** Add jitter to OAuth callback error paths
5. **Verify:** Run timing statistical tests
6. **Deploy:** Staging → Production