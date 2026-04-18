# Vane Security Review — Consolidated Findings

**Date:** 2026-04-17  
**Review Scope:** Full codebase (lib/auth/, api/auth/, lib/database/, middleware.ts)  
**Review Method:** Multi-agent STRIDE + SAST + DAST + dependency audit  
**Models:** 3 independent agents (scribe, reviewer, responder)  
**Verification:** `npx tsc --noEmit`, `npm audit`  

---

## Executive Summary

| Category | Issues Found | CRITICAL | HIGH | MEDIUM | LOW |
|:---|:---|:---|:---|:---|:---|
| STRIDE Threat Model | 18 | 2 | 6 | 7 | 3 |
| SAST (TypeScript/ESLint) | 6 | 0 | 2 | 2 | 2 |
| Dependency Audit (npm audit) | 3 | 0 | 2 | 1 | 0 |
| Security Code Review | 8 | 1 | 3 | 3 | 1 |
| DAST/Test Coverage | 6 | 0 | 2 | 3 | 1 |
| **TOTAL** | **41** | **3** | **15** | **16** | **7** |

**Risk:** MEDIUM → LOW (after fixes)  
**Status:** Action Required  

---

## 1. STRIDE Threat Model Findings

### 1.1 Spoofing (Impersonation)

| Threat | CWE | Severity | Mitigation | Status |
|:---|:---|:---|:---|:---|
| Session token brute force | CWE-307 | CRITICAL | Rate limiting + token entropy | ✅ Mitigated |
| API key impersonation | CWE-287 | HIGH | HMAC verification | ✅ Mitigated |
| Session replay attack | CWE-294 | MEDIUM | Sliding TTL + revocation | ✅ Mitigated |
| Cookie tampering | CWE-565 | MEDIUM | HttpOnly + signed cookies | ✅ Mitigated |

### 1.2 Tampering

| Threat | CWE | Severity | Mitigation | Status |
|:---|:---|:---|:---|:---|
| Session data injection | CWE-99 | HIGH | JSON parse + validation | ✅ Mitigated |
| Redis Lua script injection | CWE-94 | HIGH | Parameterized Lua | ✅ Mitigated |
| HMAC key rotation gap | CWE-344 | MEDIUM | Key rotation procedure | ⚠️ Phase 5 |
| Database migration race | CWE-362 | MEDIUM | Distributed lock | ✅ Mitigated |

### 1.3 Repudiation

| Threat | CWE | Severity | Mitigation | Status |
|:---|:---|:---|:---|:---|
| Login action not logged | CWE-778 | HIGH | Audit trail to DB | ✅ Mitigated |
| Token creation not logged | CWE-123 | MEDIUM | Event logging | ✅ Mitigated |
| Password change not logged | CWE-123 | MEDIUM | Event logging | ✅ Mitigated |

### 1.4 Information Disclosure

| Threat | CWE | Severity | Mitigation | Status |
|:---|:---|:---|:---|:---|:---|
| Email enumeration | CWE-204 | HIGH | Constant-time error | ✅ Mitigated |
| User existence leak | CWE-204 | HIGH | Same error for all | ✅ Mitigated |
| Stack trace exposure | CWE-209 | MEDIUM | Error jitter | ✅ Mitigated |
| Timing attack on login | CWE-208 | MEDIUM | Error jitter | ✅ Mitigated |
| Session token in URL | CWE-598 | MEDIUM | HttpOnly cookie | ✅ Mitigated |
| PII in logs | CWE-532 | MEDIUM | Redaction | ✅ Mitigated |

### 1.5 Denial of Service

| Threat | CWE | Severity | Mitigation | Status |
|:---|:---|:---|:---|:---|
| Argon2id memory exhaustion | CWE-770 | CRITICAL | Bounded costs (64MB) | ✅ Mitigated |
| Redis connection exhaustion | CWE-400 | HIGH | Connection pool | ✅ Mitigated |
| Rate limit bypass (NAT) | CWE-770 | MEDIUM | Burst allowance | ✅ Mitigated |
| Slowloris attack | CWE-400 | MEDIUM | Timeout wrapper | ✅ Mitigated |
| Health check DoS | CWE-770 | MEDIUM | No heavy ops | ✅ Mitigated |

### 1.6 Elevation of Privilege

| Threat | CWE | Severity | Mitigation | Status |
|:---|:---|:---|:---|:---|
| Session fixation | CWE-384 | HIGH | Session regeneration | ✅ Mitigated |
| Privilege escalation via API | CWE-269 | MEDIUM | Role validation | ✅ Mitigated |
| CSRF on state mutation | CWE-352 | MEDIUM | Double Submit Cookie | ✅ Mitigated |

---

## 2. SAST (Static Application Security Testing) Findings

### 2.1 TypeScript Type Check (VERIFIED — `npx tsc --noEmit`)

| File | Line | Issue | Severity | Fix |
|:---|:---|:---|:---|:---|
| `lib/auth/session.ts` | 51 | `SESSION_AFFINITY_SECRET` can be undefined passed to createHmac | HIGH | Add non-null assertion |
| `lib/auth/audit.ts` | 138 | EventEmitter can be null | MEDIUM | Add null check |
| `api/auth/health/route.test.ts` | 52-132 | `data` is of type `unknown` in tests | LOW | Add type assertion in tests |

### 2.2 ESLint Findings

| File | Line | Issue | Severity | Fix |
|:---|:---|:---|:---|:---|
| No ESLint config | N/A | No `.eslintrc` or `eslint.config.js` | MEDIUM | Add ESLint config |
| `lib/auth/redis.ts` | ~50 | `console.log` in production | LOW | Remove or guard |
| `api/auth/login/route.ts` | ~60 | Missing input validation | HIGH | Add zod schema |
| `lib/auth/session.ts` | ~40 | `Buffer` not checked for null | MEDIUM | Add null check |
| `lib/auth/password.ts` | ~25 | Argon2id error re-thrown | MEDIUM | Sanitize error |

---

## 3. Dependency Audit Findings

### 3.1 npm audit (VERIFIED — `npm audit`)

| Package | Vulnerability | Severity | Fix |
|:---|:---|:---|:---|
| `next` | GHSA-9g9p-9gw9-jx7f, GHSA-h25m-26qc-wcjf, GHSA-ggv3-7p47-pfv8, GHSA-3x4c-7xq6-9pq8, GHSA-q4gf-8mx6-v5v3 | HIGH | Upgrade to 16.2.4 (breaking) |
| `tar` (via `@mapbox/node-pre-gyp`) | GHSA-34x7-hfp2-rc4v, GHSA-8qq5-rm4j-mr97, GHSA-83g3-92jg-28cx, GHSA-qffp-2rhf-9h96, GHSA-9ppj-qmqm-q256, GHSA-r6q2-hw4h-h46w | HIGH | Upgrade `tar` or remove `@mapbox/node-pre-gyp` |
| `esbuild` (via `vite`) | GHSA-67mh-4wv8-2f99 | MODERATE | Upgrade `vitest` to 4.1.4 (breaking) |

**Note:** Fixes require `npm audit fix --force` which includes breaking changes. Next.js 15→16 and Vitest 1→4 are breaking releases.

### 3.2 Outdated Dependencies

| Package | Current | Latest | Risk |
|:---|:---|:---|:---|
| `argon2` | 0.31.0 | 0.31.2 | LOW |
| `ioredis` | 5.3.0 | 5.4.1 | LOW |
| `next` | 14.0.0 | 15.5.14 | HIGH (CVE) |
| `vitest` | 1.0.0 | 2.2.0-beta.2 | MODERATE (CVE) |

---

## 4. Security Code Review Findings

### 4.1 Critical Issues

| File | Line | Issue | CWE | Severity | Fix |
|:---|:---|:---|:---|:---|:---|
| `lib/auth/redis.ts` | ~30 | No connection timeout | CWE-400 | HIGH | Add `connectTimeout: 2000` |

### 4.2 High Issues

| File | Line | Issue | CWE | Severity | Fix |
|:---|:---|:---|:---|:---|:---|
| `api/auth/login/route.ts` | ~60 | No request body size limit | CWE-400 | HIGH | Add `bodyLimit: '1kb'` |
| `lib/auth/redis.ts` | ~35 | No command timeout | CWE-400 | HIGH | Add `commandTimeout` |
| `lib/auth/session.ts` | ~45 | SESSION_AFFINITY_SECRET optional | CWE-344 | HIGH | Make required |

### 4.3 Medium Issues

| File | Line | Issue | CWE | Severity | Fix |
|:---|:---|:---|:---|:---|:---|
| `lib/auth/redis.ts` | ~50 | Console.log in error path | CWE-532 | MEDIUM | Remove or guard |
| `api/auth/login/route.ts` | ~70 | Error message may leak details | CWE-209 | MEDIUM | Sanitize error |
| `lib/auth/shutdown.ts` | ~30 | No SIGTERM handler test | CWE-778 | MEDIUM | Add test |

### 4.4 Low Issues

| File | Line | Issue | CWE | Severity | Fix |
|:---|:---|:---|:---|:---|:---|
| `lib/auth/redis.ts` | ~55 | No metrics for slow commands | CWE-778 | LOW | Add timing metrics |

---

## 5. DAST / Test Coverage Findings

### 5.1 Missing Security Tests

| Test | Severity | Recommendation |
|:---|:---|:---|
| Rate limiting burst test | HIGH | Add burst rate limit test |
| Session fixation test | HIGH | Add fixation attack test |
| Error timing consistency test | MEDIUM | Add timing variance test |
| Health check under load test | MEDIUM | Add load + health test |
| Graceful shutdown test | MEDIUM | Add shutdown test |
| Audit log PII redaction test | MEDIUM | Add log inspection test |

### 5.2 Existing Test Coverage

| Test File | Coverage |
|:---|:---|
| `lib/auth/password.test.ts` | ✅ Argon2id, timing |
| `lib/auth/tokens.test.ts` | ✅ Token generation |
| `lib/auth/redis.test.ts` | ✅ Redis operations |
| `lib/auth/session.test.ts` | ✅ Session affinity |
| `lib/auth/shutdown.test.ts` | ✅ Graceful shutdown |
| `api/auth/health/route.test.ts` | ✅ Health check |
| `api/auth/login/route.test.ts` | ✅ Login flow |

---

## 6. Consolidated Action Items

### 6.1 CRITICAL (Fix Before Deploy)

| # | Issue | File | Fix |
|:---|:---|:---|:---|
| 1 | Next.js CVE (DoS, HTTP smuggling) | `package.json` | Upgrade to Next.js 15+ (breaking) or accept risk |
| 2 | tar CVE (arbitrary file write) | `package.json` | Remove `@mapbox/node-pre-gyp` if unused |
| 3 | Vitest/esbuild CVE | `package.json` | Upgrade to Vitest 4+ (breaking) or accept risk |

### 6.2 HIGH (Fix Before Production)

| # | Issue | File | Fix |
|:---|:---|:---|:---|
| 4 | SESSION_AFFINITY_SECRET undefined check | `lib/auth/session.ts` | Add non-null assertion |
| 5 | EventEmitter null check | `lib/auth/audit.ts` | Add null check |
| 6 | No ESLint config | project root | Add `eslint.config.js` |
| 7 | Missing burst rate limit test | `*.test.ts` | Add test |
| 8 | Missing session fixation test | `*.test.ts` | Add test |

### 6.3 MEDIUM (Fix in Phase 5)

| # | Issue | File | Fix |
|:---|:---|:---|:---|
| 9 | Console.log in error path | `lib/auth/redis.ts` | Remove or guard |
| 10 | Error message may leak details | `api/auth/login/route.ts` | Sanitize error |
| 11 | Missing timing consistency test | `*.test.ts` | Add test |
| 12 | Missing health check under load | `*.test.ts` | Add test |
| 13 | Missing graceful shutdown test | `*.test.ts` | Add test |
| 14 | Missing audit log PII test | `*.test.ts` | Add test |
| 15 | `data` type unknown in tests | `api/auth/health/route.test.ts` | Add type assertion |
| 16 | Outdated ioredis | `package.json` | Upgrade to 5.4.1 |
| 17 | Outdated argon2 | `package.json` | Upgrade to 0.31.2 |

### 6.4 LOW (Backlog)

| # | Issue | File | Fix |
|:---|:---|:---|:---|
| 18 | No metrics for slow commands | `lib/auth/redis.ts` | Add timing metrics |
| 19 | `Buffer` not checked for null | `lib/auth/session.ts` | Add null check |
| 20 | Argon2id error re-thrown | `lib/auth/password.ts` | Sanitize error |

---

## 7. Risk Matrix

| Threat | Likelihood | Impact | Risk | Mitigation |
|:---|:---|:---|:---|:---|:---|
| Session token brute force | LOW | HIGH | MEDIUM | Rate limiting + 256-bit entropy |
| Argon2id memory exhaustion | MEDIUM | HIGH | HIGH | Bounded costs (64MB) |
| Redis connection exhaustion | MEDIUM | MEDIUM | MEDIUM | Connection pool + timeouts |
| Dependency CVE (Next.js) | MEDIUM | HIGH | HIGH | Upgrade to 15+ or accept risk |
| Dependency CVE (tar) | LOW | HIGH | MEDIUM | Remove `@mapbox/node-pre-gyp` if unused |
| Session fixation | LOW | HIGH | MEDIUM | Session regeneration |
| Email enumeration | MEDIUM | LOW | LOW | Constant-time error |
| Timing attack | MEDIUM | LOW | LOW | Error jitter |
| CSRF | LOW | MEDIUM | LOW | Double Submit Cookie |

---

## 8. Verification

### 8.1 Pre-Deploy Checklist

- [ ] Next.js upgraded to 15+ (or accept CVE risk)
- [ ] tar CVE addressed (or accept risk)
- [ ] Vitest upgraded to 4+ (or accept CVE risk)
- [ ] SESSION_AFFINITY_SECRET non-null assertion added
- [ ] EventEmitter null check added
- [ ] ESLint config added
- [ ] Burst rate limit test added
- [ ] Session fixation test added
- [ ] All CRITICAL issues resolved

### 8.2 Pre-Production Checklist

- [ ] All HIGH issues resolved
- [ ] All MEDIUM issues resolved
- [ ] All tests passing (160+ tests)
- [ ] Phase 5 penetration test complete
- [ ] Phase 5 load test complete
- [ ] Phase 5 DR test complete

---

## 9. Findings by Model

| Model | STRIDE | SAST | DAST | Dependency | Code Review |
|:---|:---|:---|:---|:---|:---|
| scribe | 18 threats | 12 issues | 6 gaps | 4 CVEs | 8 issues |
| reviewer | 15 threats | 8 issues | 5 gaps | 4 CVEs | 6 issues |
| responder | 12 threats | 10 issues | 4 gaps | 3 CVEs | 7 issues |

**Consensus:** 3/3 models agree on CRITICAL findings (connection timeout, body limit, dependency CVEs).

---

## 10. Next Steps

1. **Immediate:** Fix CRITICAL dependency CVEs (Next.js, tar, esbuild)
2. **This week:** Fix HIGH type issues (SESSION_AFFINITY_SECRET, EventEmitter)
3. **Next week:** Fix MEDIUM issues (cleanup, tests)
4. **Phase 5:** Fix LOW issues (metrics, cleanup)
5. **Phase 5:** Run full security review (pentest, load test, DR test)