# Critical Evaluation: Agent Security Harness v3.2.0 (Round 5)

**Date:** 2026-03-23
**Evaluation rounds:** 5
**Test suite:** 68 automated tests, all passing
**This round's change:** README-only — AIUC-1 crosswalk added (PR#31)

---

## What Changed (PR#31)

A 71-line addition to README.md mapping the framework's tests to [AIUC-1](https://www.aiuc-1.com), described as the first AI agent certification standard. The crosswalk maps 15 of 20 testable AIUC-1 requirements to specific harnesses and test categories.

**No code changes.** All prior fixes remain intact.

---

## AIUC-1 Crosswalk Assessment

### What It Claims
- 15 of 20 AIUC-1 testable requirements are covered
- 100% coverage of Security (B) requirements
- References to specific harnesses (MCP, A2A, identity, GTG-1002, enterprise, advanced attacks)
- 209 executable tests with JSON audit reports and statistical CIs
- Positioned as a pre-certification adversarial testing tool

### What's Good
- **Honest scoping** — Claims 15/20 rather than overstating. Explicitly notes which categories have gaps.
- **Concrete mapping** — Each AIUC-1 requirement ID (B001, C010, D004, etc.) maps to specific harness modules.
- **Test count consistent** — The crosswalk says "209 executable tests" which matches the CLI and pyproject.toml.
- **References real capabilities** — The harnesses and test categories cited actually exist in the codebase.

### What Could Be Improved
- **AIUC-1 is very new** — As a first certification standard, its requirements may evolve. The crosswalk should note the specific AIUC-1 version referenced.
- **"100% Security coverage" is a strong claim** — While the framework does have extensive security tests, certification auditors will evaluate whether the *depth* of coverage matches, not just the *breadth*. A note about this distinction would add credibility.
- **5 uncovered requirements not listed** — The crosswalk says 15/20 but doesn't explicitly list which 5 are missing. Transparency about gaps strengthens trust.
- **No version pinning** — The crosswalk doesn't specify which AIUC-1 version it maps to. When AIUC-1 updates, the crosswalk may become stale.

---

## All Regression Tests — Status

All 15 previously fixed issues remain fixed. No regressions.

| # | Issue | Status |
|---|-------|--------|
| 1-15 | All prior issues | FIXED (verified) |

---

## Remaining Minor Items (Unchanged from Round 4)

1. **CLI `--delay` cosmetic for protocol harnesses** — prints message but doesn't apply delay
2. **Mock server MCP-only** — A2A/L402/x402 need live targets
3. **No version bump since PR#25-30 fixes** — still 3.2.0

---

## Score

| Round | Change | Score |
|-------|--------|-------|
| 1 | Initial evaluation | 7/10 |
| 2 | x402 + CI | 7.5/10 |
| 3 | All critical fixes | 8.5/10 |
| 4 | Polish fixes | 9/10 |
| 5 | AIUC-1 crosswalk | **9/10** |

Score unchanged at **9/10**. The AIUC-1 crosswalk is a valuable documentation addition that strengthens the framework's positioning for compliance use cases, but doesn't change the technical capabilities. The minor crosswalk suggestions (version pinning, explicit gap listing) are documentation nits, not score-affecting issues.

---

## Cumulative Assessment

Over 5 rounds, this framework has matured from a 7/10 to a 9/10:
- **15 issues raised, 15 fixed, 0 regressions**
- **Code:** Zero-dep core, response body leak detection, timezone-aware, lazy imports
- **CI:** Multi-Python, syntax checks, per-method ID uniqueness
- **Documentation:** Complete README, AIUC-1 crosswalk, mock server docs
- **Standards:** OWASP ASI01-10, NIST AI 800-2, NIST NCCoE, STRIDE, ISA/IEC 62443, AIUC-1

The framework fills a genuine gap in AI security tooling — no other open-source tool provides protocol-level testing for MCP, A2A, L402, and x402. The maintainer's responsiveness throughout this evaluation process has been exemplary.
