# Vane Research Engine Remediation Plan

**Document Type:** Remediation Plan  
**Date:** 2026-04-17  
**Status:** APPROVED WITH MODIFICATIONS — Ralph Wiggum Consensus  
**Scope:** 8 issues (3 CRITICAL, 5 HIGH)  

---

## 1. Executive Summary

This plan addresses 8 issues identified in the Vane authentication codebase, spanning dependency upgrades, TypeScript fixes, test coverage gaps, and security hardening.

**Overall Risk:** CRITICAL → MEDIUM (after implementation)  
**Timeline:** 18-21 days (3 weeks with buffer)  
**Implementation Scope:** 6 files, ~300 lines  

---

## 2. Key Changes from Original

| # | Change | Rationale |
|:---|:---|:---|
| 1 | **Status:** DRAFT → APPROVED WITH MODIFICATIONS | Plan has passed Ralph Wiggum adversarial review |
| 2 | **Timeline:** 2 weeks → 18-21 days | Added Phase 0 (baseline validation) + buffer days between phases |
| 3 | **Phase reorder:** Added Phase 0, renamed phases | Phase 0 ensures baseline works before breaking changes; Phase 2 split for safer rollout |
| 4 | **Rollback procedures added** | Each phase now has explicit rollback steps for rapid recovery |

---

## 3. Issue Inventory

### 3.1 Critical Issues (Breaking Changes)

| ID | Issue | Severity | Risk | Mitigation |
|:---|:---|:---|:---|:---|
| **C-01** | Next.js 14→15+ upgrade | CRITICAL | Breaking API changes in Next.js 15 | Full test suite regression |
| **C-02** | Vitest 1→4+ upgrade | CRITICAL | Breaking config changes between versions | Config migration + test update |

### 3.2 High Priority Issues

| ID | Issue | Severity | Risk | Mitigation |
|:---|:---|:---|:---|:---|
| **H-01** | SESSION_AFFINITY_SECRET TypeScript | HIGH | Type is `string`, not validated at type level | Add to env types |
| **H-02** | EventEmitter TypeScript | HIGH | `require('events').EventEmitter` pattern | Use proper import |
| **H-03** | Root ESLint configuration | HIGH | No root config exists | Create eslint.config.mjs |
| **H-04** | Burst rate limit tests | HIGH | No burst scenario testing | Add burst tests |
| **H-05** | Session fixation tests | HIGH | No fixation scenario testing | Add fixation tests |
| **H-06** | Explicit login body limit | HIGH | No body size limit | Add body parser limit |

---

## 4. Proposed Phases

### Phase 0: Baseline & Validation (Day 1-2)
**Goal:** Establish working baseline before any changes.

```
Files Modified:
- None (validation only)

Steps:
1. [ ] Run full test suite — record pass/fail status for each test
2. [ ] Measure test coverage baseline (target: >90%)
3. [ ] Verify Redis connectivity and NAT detection logic
4. [ ] Document any pre-existing flaky tests
5. [ ] Create baseline snapshot of package.json versions

Rollback Procedure:
- No changes made — this is a validation phase
- If baseline fails, block Phase 1 until resolved
```

### Phase 1: Quick Wins (Day 3-4)
**Goal:** Fix TypeScript issues and add security hardening.

```
Files Modified:
- lib/auth/session.ts (H-01)
- lib/auth/audit.ts (H-02)
- api/auth/login/route.ts (H-06)
- eslint.config.mjs (H-03 - new file)

Steps:
1. [ ] Add SESSION_AFFINITY_SECRET to env types (lib/env.ts or similar)
2. [ ] Replace require('events').EventEmitter with proper import
3. [ ] Add explicit body size limit to login route (10KB)
4. [ ] Create root eslint.config.mjs with TypeScript rules

Rollback Procedure:
- git checkout HEAD~1 on modified files
- Revert env type changes
- Revert ESLint config creation
- Re-run tests to confirm baseline restored
```

### Phase 2a: Breaking Changes — Next.js (Day 5-8)
**Goal:** Upgrade Next.js with staged validation.

```
Files Modified:
- package.json (C-01)
- Potentially middleware files (C-01)

Steps:
1. [ ] Read Next.js 15 migration guide
2. [ ] Upgrade Next.js: 14.0.0 → 15.0.0
3. [ ] Run full test suite
4. [ ] Fix any breaking API changes
5. [ ] Update middleware if needed
6. [ ] Verify all tests pass before proceeding

Rollback Procedure:
- npm install next@14.0.0 vitest@1.0.0
- git checkout HEAD~1 on package.json
- Block Phase 2b until Phase 2a fully validated
```

### Phase 2b: Breaking Changes — Vitest (Day 9-12)
**Goal:** Upgrade Vitest after Next.js validated.

```
Files Modified:
- package.json (C-02)
- vitest.config.ts (C-02)
- Multiple test files (C-02)

Steps:
1. [ ] Read Vitest 4 migration guide
2. [ ] Upgrade Vitest: 1.0.0 → 4.0.0
3. [ ] Migrate vitest.config.ts syntax
4. [ ] Update test syntax if needed
5. [ ] Verify all tests pass

Rollback Procedure:
- npm install vitest@1.0.0
- git checkout HEAD~1 on vitest.config.ts
- Block Phase 3 until Vitest 4 fully validated
```

### Phase 3: Testing (Day 13-16)
**Goal:** Add missing test scenarios.

```
Files Modified:
- lib/auth/rate-limit.test.ts (H-04)
- lib/auth/session.test.ts (H-05)

Steps:
1. [ ] Add burst rate limit tests
   - Test burst allowance behavior
   - Test NAT exemption scenarios
   - Test sliding window reset
2. [ ] Add session fixation tests
   - Test session regeneration on login
   - Test old session revocation
   - Test concurrent session handling

Rollback Procedure:
- git checkout HEAD~1 on test files
- Revert test additions
- Maintain >90% coverage via existing tests
```

### Phase 4: Security Hardening (Day 17-21)
**Goal:** Final verification and hardening.

```
Steps:
1. [ ] Verify all phases complete
2. [ ] Run full security scan
3. [ ] Update documentation
4. [ ] Final test suite verification
5. [ ] Performance regression check

Rollback Procedure:
- Full revert via git checkout HEAD~N on all modified files
- Re-run Phase 0 baseline validation
- Re-apply fixes incrementally if needed
```

---

## 5. Risk Assessment

### Phase 0 Risks

| Risk | Likelihood | Impact | Mitigation |
|:---|:---|:---|:---|
| Pre-existing test failures | MEDIUM | HIGH | Block all phases until baseline clean |

### Phase 1 Risks

| Risk | Likelihood | Impact | Mitigation |
|:---|:---|:---|:---|:---|
| ESLint config conflicts with existing | LOW | LOW | Merge with existing, no overwrite |
| TypeScript errors cascade | LOW | MEDIUM | Incremental fixes |

### Phase 2a Risks

| Risk | Likelihood | Impact | Mitigation |
|:---|:---|:---|:---|
| Next.js 15 breaking changes | MEDIUM | HIGH | Full regression suite |
| Runtime failures | LOW | HIGH | Staged rollout with validation gates |

### Phase 2b Risks

| Risk | Likelihood | Impact | Mitigation |
|:---|:---|:---|:---|
| Vitest 4 config migration | MEDIUM | MEDIUM | Read migration guide first |
| Test flakiness | LOW | MEDIUM | Mock Redis properly |

### Phase 3 Risks

| Risk | Likelihood | Impact | Mitigation |
|:---|:---|:---|:---|
| Edge case gaps | MEDIUM | MEDIUM | Review coverage |
| Test flakiness | LOW | LOW | Mock Redis properly |

### Phase 4 Risks

| Risk | Likelihood | Impact | Mitigation |
|:---|:---|:---|:---|:---|
| Performance regression | LOW | MEDIUM | Benchmark before/after |

---

## 6. Verification Criteria

### Phase 0
- [ ] Full test suite passes at baseline
- [ ] Coverage >90%
- [ ] Redis connectivity verified
- [ ] Pre-existing issues documented

### Phase 1
- [ ] SESSION_AFFINITY_SECRET typed in env types
- [ ] EventEmitter imported via ES module
- [ ] Login body limited to 10KB
- [ ] ESLint config exists and passes

### Phase 2a
- [ ] Next.js 15 installed
- [ ] All tests pass
- [ ] No console errors
- [ ] Middleware updated if needed

### Phase 2b
- [ ] Vitest 4 installed
- [ ] vitest.config.ts migrated
- [ ] All tests pass
- [ ] No console errors

### Phase 3
- [ ] Burst tests cover all scenarios
- [ ] Fixation tests cover all scenarios
- [ ] 95% test coverage maintained

### Phase 4
- [ ] Security scan clean
- [ ] Documentation updated
- [ ] Final regression passes
- [ ] Performance baseline maintained

---

## 7. Open Questions (Resolved)

| # | Question | Resolution |
|:---|:---|:---|
| 1 | ESLint config extend Next.js recommended or custom? | Extend Next.js recommended + custom TypeScript rules |
| 2 | Vitest 4 migration path from v1? | Follow official migration guide, staged (2a then 2b) |
| 3 | Body limit 10KB or 5KB? | 10KB — sufficient for OAuth redirects |
| 4 | Burst window to test? | 10s burst, 60s sliding window |

---

## 8. Rollback Summary

| Phase | Rollback Command |
|:---|:---|
| Phase 0 | No rollback needed (validation only) |
| Phase 1 | `git checkout HEAD~1` on modified files |
| Phase 2a | `npm install next@14.0.0 && git checkout HEAD~1 package.json` |
| Phase 2b | `npm install vitest@1.0.0 && git checkout HEAD~1 vitest.config.ts` |
| Phase 3 | `git checkout HEAD~1` on test files |
| Phase 4 | `git checkout HEAD~N` on all modified files |

---

## 9. Ralph Wiggum Loop Summary

### Iteration 1 (2026-04-17)

| Model | Role | Finding |
|:---|:---|:---|
| **architect** | Strategic design | Phase 2 too compressed; Vitest and Next.js upgrades should be separate phases |
| **reviewer** | Adversarial review | No baseline validation; breaking changes applied without knowing starting state |
| **planner** | Plan synthesis | Added Phase 0; split Phase 2 into 2a/2b; added rollback procedures |

### Consensus Reached

All three models agreed on:
1. Phase 0 (Baseline) required before any changes
2. Phase 2 split into 2a (Next.js) and 2b (Vitest) for safer rollback
3. Explicit rollback procedures for each phase
4. 18-21 day timeline with buffer days between phases

### Changes from Original Plan

| Change | Source |
|:---|:---|
| Added Phase 0 | architect + reviewer |
| Split Phase 2 | architect |
| Added rollback procedures | planner |
| Extended timeline to 18-21 days | consensus |
| Resolved open questions | reviewer adversarial questioning |