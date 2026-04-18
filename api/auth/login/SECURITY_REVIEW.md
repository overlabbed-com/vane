# Adversarial Security Review: Vane Authentication Endpoint

**Target:** `vane/api/auth/login/route.ts`
**Review Date:** 2026-04-17
**Focus:** Authentication Bypass Vulnerabilities

---

## Executive Summary

**CRITICAL FINDING:** The authentication logic contains a **design flaw** that allows password-only OR apiKey-only authentication, contrary to the documented security model. While not a direct bypass, this creates an attack surface where compromising one credential type grants full access.

**SEVERITY:** MEDIUM-HIGH (Design Flaw, not Direct Bypass)

---

## 1. Credential Validation Analysis

### `validateCredentials()` Function (Lines 85-96)

```typescript
function validateCredentials(body: LoginBody): { valid: boolean; error?: string } {
  const hasPassword = body.password && body.password.length > 0;
  const hasApiKey = body.apiKey && body.apiKey.length > 0;

  if (!hasPassword && !hasApiKey) {
    return { valid: false, error: 'Password or API key is required' };
  }

  return { valid: true };
}
```

#### Test Cases:

| Input | `hasPassword` | `hasApiKey` | Result |
|-------|---------------|-------------|--------|
| `{email: "x", password: "", apiKey: ""}` | `false` (empty string) | `false` (empty string) | **REJECTED** ✅ |
| `{email: "x", password: "pass"}` | `true` | `false` | **ACCEPTED** |
| `{email: "x", apiKey: "key"}` | `false` | `true` | **ACCEPTED** |
| `{email: "x"}` (no credentials) | `false` | `false` | **REJECTED** ✅ |
| `{email: "x", password: "p", apiKey: "k"}` | `true` | `true` | **ACCEPTED** |

**Edge Cases:**
- Empty string `""` → Fails validation (correct)
- `null` or `undefined` → Fails validation (correct)
- Whitespace `"   "` → **PASSES** validation (potential issue - should trim?)

---

## 2. Logic Flow Vulnerabilities (Lines 140-180)

### Critical Finding: Independent Verification Blocks

```typescript
// Line 187-198: Password verification (CONDITIONAL)
if (password) {
  const passwordValid = await verifyPassword(password, user.passwordHash);
  if (!passwordValid) {
    return NextResponse.json(
      { error: 'INVALID_CREDENTIALS', message: ERROR_MESSAGES.INVALID_CREDENTIALS },
      { status: 401 }
    );
  }
}

// Line 200-212: API key verification (CONDITIONAL)
if (apiKey) {
  const apiKeyValid = await verifyApiKey(apiKey, user.apiKeyHash);
  if (!apiKeyValid) {
    return NextResponse.json(
      { error: 'INVALID_CREDENTIALS', message: ERROR_MESSAGES.INVALID_CREDENTIALS },
      { status: 401 }
    );
  }
}

// Line 214-217: Session creation (UNCONDITIONAL after user found)
const metadata = getClientMetadata(request);
const session = await createSession(user.id, metadata);
```

### Vulnerability Analysis:

#### Q: Are both blocks mandatory?
**A: NO.** Each block is **conditionally executed** based on whether that credential was provided.

#### Q: What if user provides BOTH password AND apiKey?
**A:** Both verification blocks execute. BOTH must pass for session to be created.

```
Input: {email: "user@example.com", password: "pass", apiKey: "key"}
Flow:
  1. validateCredentials() → passes (both present)
  2. User lookup → found
  3. if (password) → executes, must pass
  4. if (apiKey) → executes, must pass
  5. createSession() → called
```

#### Q: What if user provides ONLY password?
**A:** Password verification executes, **apiKey check is SKIPPED entirely**.

```
Input: {email: "user@example.com", password: "pass"}
Flow:
  1. validateCredentials() → passes (password present)
  2. User lookup → found
  3. if (password) → executes, must pass
  4. if (apiKey) → SKIPPED (apiKey is undefined)
  5. createSession() → called
```

#### Q: What if user provides ONLY apiKey?
**A:** API key verification executes, **password check is SKIPPED entirely**.

```
Input: {email: "user@example.com", apiKey: "key"}
Flow:
  1. validateCredentials() → passes (apiKey present)
  2. User lookup → found
  3. if (password) → SKIPPED (password is undefined)
  4. if (apiKey) → executes, must pass
  5. createSession() → called
```

---

## 3. Session Creation Conditions

### Line 214-217: `createSession()` is called when:

1. ✅ User found (lines 157-165)
2. ✅ Either password OR apiKey passed validation (line 149-155)
3. ✅ **If password provided:** password verification passed (lines 187-198)
4. ✅ **If apiKey provided:** apiKey verification passed (lines 200-212)

### Critical Question: Is there ANY path to line 214 without valid credentials?

**Answer: NO direct bypass exists, BUT:**

The authentication model is **OR** not **AND**:
- Password-only → Session created ✅
- ApiKey-only → Session created ✅
- Both provided → Both must pass ✅

This contradicts the comment at line 21:
```typescript
* - Password OR API key required (no email-only login)
```

The comment is **technically accurate** but misleading - it suggests dual-factor when it's actually single-factor with two options.

---

## 4. Attack Scenario Analysis

### Scenario 1: Empty Password
```json
{
  "email": "user@example.com",
  "password": ""
}
```

**Result:** REJECTED at line 149-155
- `validateCredentials()` returns `{valid: false}` because `"".length > 0` is `false`
- HTTP 400 returned

**Verdict:** ✅ **Protected**

---

### Scenario 2: Empty API Key
```json
{
  "email": "user@example.com",
  "apiKey": ""
}
```

**Result:** REJECTED at line 149-155
- `validateCredentials()` returns `{valid: false}`
- HTTP 400 returned

**Verdict:** ✅ **Protected**

---

### Scenario 3: No Credentials
```json
{
  "email": "user@example.com"
}
```

**Result:** REJECTED at line 149-155
- `validateCredentials()` returns `{valid: false}`
- HTTP 400 returned

**Verdict:** ✅ **Protected**

---

### Scenario 4: userId with Password (Bypass Verification?)
```json
{
  "userId": "123",
  "password": "anything"
}
```

**Result:** Password verification still executes
- Line 157-165: User lookup by userId
- Line 187-198: `if (password)` → **executes** because password is truthy
- `verifyPassword("anything", user.passwordHash)` → returns `false`
- HTTP 401 returned

**Verdict:** ✅ **Protected** - userId doesn't bypass password verification

---

### Scenario 5: Password-Only Authentication (Design Flaw)
```json
{
  "email": "user@example.com",
  "password": "correct-password"
}
```

**Result:** Session created (apiKey check skipped)
- This is **intended behavior** per the OR logic
- But creates single-point-of-failure

**Verdict:** ⚠️ **Design Issue** - Not a bypass, but weakens security model

---

### Scenario 6: API Key-Only Authentication (Design Flaw)
```json
{
  "email": "user@example.com",
  "apiKey": "correct-key"
}
```

**Result:** Session created (password check skipped)
- This is **intended behavior** per the OR logic

**Verdict:** ⚠️ **Design Issue** - Not a bypass, but weakens security model

---

## 5. Deep Dive: Verification Functions

### `verifyPassword()` (password.ts, lines 68-85)

```typescript
export async function verifyPassword(
  password: string,
  hash: string
): Promise<boolean> {
  if (!password || !hash) {
    return false;  // ✅ Explicitly rejects empty inputs
  }

  try {
    const isValid = await argon2.verify(hash, password);
    return isValid;
  } catch (error) {
    console.error('Password verification error:', error.message);
    return false;  // ✅ Errors return false, not exception
  }
}
```

**Security Properties:**
- ✅ Empty password → returns `false`
- ✅ Empty hash → returns `false`
- ✅ Argon2.verify uses constant-time comparison
- ✅ Exceptions caught and return `false`

**No bypass possible here.**

---

### `verifyApiKey()` (api-key.ts, lines 77-100)

```typescript
export async function verifyApiKey(
  plainKey: string,
  hash: string
): Promise<boolean> {
  // Input validation
  if (!plainKey || !hash) {
    return false;  // ✅ Explicitly rejects empty inputs
  }

  // Validate key format (should be hex, 64 characters for 256-bit)
  if (plainKey.length !== 64 || !/^[a-fA-F0-9]+$/.test(plainKey)) {
    return false;  // ✅ Format validation
  }

  try {
    const isValid = await argon2.verify(hash, plainKey);
    return isValid;
  } catch (error) {
    console.error('API key verification error:', error.message);
    return false;  // ✅ Errors return false
  }
}
```

**Security Properties:**
- ✅ Empty key → returns `false`
- ✅ Wrong length (≠64) → returns `false`
- ✅ Non-hex characters → returns `false`
- ✅ Argon2.verify uses constant-time comparison
- ✅ Exceptions caught and return `false`

**No bypass possible here.**

---

## 6. Timing Oracle Mitigation (Lines 167-185)

```typescript
if (!user) {
  // Log attempt without PII
  console.log(JSON.stringify({
    event: 'auth.login.failed',
    reason: 'user_not_found',
    identifier_type: email ? 'email' : 'userId',
    identifier_hash: email
      ? sanitizeForLog(email).replace(/./g, 'x')
      : 'unknown',
    ip: clientIp,
    timestamp: new Date().toISOString(),
  }));
  // Timing oracle mitigation: verify against dummy hash
  if (password) {
    await verifyPassword(password, DUMMY_HASH);
  }
  return NextResponse.json(
    { error: 'INVALID_CREDENTIALS', message: ERROR_MESSAGES.INVALID_CREDENTIALS },
    { status: 401 }
  );
}
```

**Analysis:**
- ✅ Same response for user not found OR wrong password (401, same message)
- ✅ Timing oracle mitigation: `verifyPassword(password, DUMMY_HASH)` ensures consistent timing
- ⚠️ **Gap:** No timing mitigation for apiKey-only login when user not found

**Issue:** If attacker sends `{email: "fake@example.com", apiKey: "xxx"}`:
- User not found → returns immediately
- No `verifyApiKey(password, DUMMY_HASH)` call
- Response time differs from `{email: "fake@example.com", password: "xxx"}`

**Recommendation:** Add dummy apiKey verification for timing consistency.

---

## 7. Summary of Findings

### ✅ Protected Against:
1. Empty password bypass
2. Empty apiKey bypass
3. No-credentials bypass
4. userId-based bypass
5. User enumeration (same error response)
6. Timing attacks on password verification (dummy hash)
7. Injection in logs (sanitizeForLog)

### ⚠️ Design Issues (Not Bypasses):
1. **OR logic instead of AND:** Password-only OR apiKey-only authentication works
   - This is a **security model decision**, not a bug
   - But contradicts implied dual-factor security
   - Compromising one credential type grants full access

2. **Missing timing mitigation for apiKey:** When user not found and apiKey provided, no dummy verification occurs

### ❌ No Direct Authentication Bypass Found:
- All credential validation paths require at least one valid credential
- `createSession()` cannot be reached without passing verification
- Both verification functions properly reject empty/invalid inputs

---

## 8. Recommendations

### High Priority:
1. **Clarify Security Model:** Update comment at line 21 to explicitly state:
   ```
   * - Password OR API key authentication (single-factor)
   ```
   Not:
   ```
   * - Password OR API key required (no email-only login)
   ```

2. **Add Timing Mitigation for apiKey:**
   ```typescript
   if (!user) {
     // Timing oracle mitigation for both credential types
     if (password) {
       await verifyPassword(password, DUMMY_HASH);
     }
     if (apiKey) {
       await verifyApiKey(apiKey, DUMMY_HASH);  // Add this
     }
     return NextResponse.json(...);
   }
   ```

### Medium Priority:
3. **Whitespace Handling:** Consider trimming credentials:
   ```typescript
   const hasPassword = body.password?.trim().length > 0;
   ```

4. **Audit Logging:** Add metric for credential type used (password vs apiKey) to detect if one method is being targeted

### Low Priority:
5. **Consider Dual-Factor Mode:** Add config flag to require BOTH password AND apiKey for sensitive operations

---

## 9. Conclusion

**Direct authentication bypass:** NOT FOUND ✅

**Design weakness:** Single-factor authentication with two credential types (OR logic instead of AND) ⚠️

**Recommendation:** This is acceptable for most use cases where password OR API key is the intended security model. If dual-factor is required, the logic must be changed to require both credentials.

**Next Steps:**
1. Confirm intended security model with product owner
2. If dual-factor required, modify lines 187-212 to enforce both
3. Add missing timing mitigation for apiKey
4. Update documentation to reflect actual behavior

---

**Reviewer:** Adversarial Security Review Agent
**Models Used:** Qwen3.5-122B (chat), Gemma 4 31B (reason), MiniMax M2.7 (code)
**Review Method:** Static analysis, logic tracing, edge case testing
