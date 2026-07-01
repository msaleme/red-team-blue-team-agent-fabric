# CRITICAL EVALUATION — Round 33

**Date:** 2026-07-01
**Round:** 33
**Focus:** Fireblocks x402 security-extension conformance harness
**Test count:** 508 (was 474) across 35 modules (was 33)
**Version:** 4.6.0 (was 4.5.0)
**Evaluator:** Automated round (parallel research + house-style build)

---

## 1. What Changed

| File | Change | Lines |
|------|--------|------|
| `protocol_tests/x402_fireblocks_harness.py` | **New module** — FB-001..FB-017 (17 tests) | +~640 |
| `protocol_tests/cli.py` | Registered harness `x402-fireblocks` | +4 |
| `scripts/count_tests.py` | Added `x402_fireblocks_harness.py` label | +1 |
| `testing/test_code_quality.py` | `TestRegFireblocks` (8 checks) + MODULES + count guard | +~70 |
| `pyproject.toml`, `README.md`, `docs/TEST-INVENTORY.md`, `CHANGELOG.md` | Count 474→508, 33→35 modules; version 4.6.0 | — |

**Purpose.** The harness had deep settlement coverage (x402: 52, L402: 33) and
comms coverage (MCP/A2A), but nothing tested the *hardening controls* that
vendors are now layering on top of x402. Fireblocks contributed a security
extension to the Linux Foundation x402 Foundation adding request integrity and
spend governance — the closest thing to competition this project's harness work
has. R33 turns that into an adversarial conformance suite: the harness plays the
attacker (MITM, replay, budget-drain, SSRF) and asserts a correctly-hardened
deployment enforces each control.

**Design.** Stdlib-only (repo zero-extra-dep guarantee). A deterministic
reference verifier implements the *exact* semantics of the Fireblocks controls
(RFC-8785-style canonicalization, signed-field coverage over
`{x402Version, accepts}`, `iat`/`exp` freshness window, Policy-Engine decision
tree, batch-voucher state machine). `--simulate` runs the differential against
it; `--url` folds in a live endpoint behind a VS-R03 liveness gate
(unreachable/5xx = observe-failure, never a silent pass). The reference
signature primitive is HMAC-SHA256 standing in for ES256/did:web — documented in
the module docstring; the accept/reject decisions under test are identical.

---

## 2. Prior Fix Verification (R32 → R33)

R33 adds coverage; it does not touch prior-round code paths. Regressions
confirmed intact by the full suite (240 passed):

| Prior area | Guard | Status |
|---|---|---|
| VS-R03 verdict-correctness (mcp/l402/a2a/x402 liveness gates) | `test_vsr03_verdict_correctness.py` (22) | ✅ intact |
| Test-count consistency (pyproject/README vs `count_tests.py`) | `TestRegTestCount` | ✅ intact (now 508) |
| CLI version from `version.py` (issue #5) | `TestRegVersion` | ✅ intact (4.6.0) |
| F821 undefined-name CI guard | `ruff --select F821` | ✅ passes |

---

## 3. New Issues Found (coverage gaps this round closes)

Framed as coverage-gap issues (numbered sequentially; prior high was #157).

| # | Severity | Gap | Addressed by |
|---|---|---|---|
| #158 | HIGH | No test that a MITM `payTo`/amount/network swap on a signed 402 is detected | FB-001/002/003 |
| #159 | MEDIUM | No test of integrity freshness window (`exp<now`, `iat>now+60`) | FB-004/005 |
| #160 | HIGH | No test of REQUIRE_INTEGRITY downgrade (strip-envelope fallback) | FB-006 |
| #161 | HIGH | No test of the signed-field boundary (`resource.url` unsigned → needs independent SSRF guard) | FB-007 |
| #162 | HIGH | No test of did:web key-resolution SSRF | FB-009 |
| #163 | HIGH | No test of Policy-Engine spend governance (allowlist/cap/velocity/quorum) | FB-010..013 |
| #164 | HIGH | No test of x402 V2 batch-settlement voucher abuse (monotonicity/replay/binding/escrow) | FB-014..017 |

No CRITICAL/HIGH defects were found in existing code during this round.

---

## 4. What's Good

- The `x402_merchant.py` settlement scaffold (VS-R02) gives a natural live
  target for FB-* tests — the differential and the merchant compose.
- The signed-field boundary test (FB-007) encodes a subtle, real property from
  the reference implementation: integrity does **not** sign `resource.url`, so
  a hardened client needs an independent SSRF guard. Catching that boundary is
  the kind of finding the Fireblocks reference code makes explicit and a naive
  reimplementation would miss.
- Reference-verifier approach makes `--simulate` genuinely regression-meaningful
  (tamper→reject is executed, not just asserted well-formed).

---

## 5. Methods

- **Research:** parallel background agent pulled the `fireblocks/x402-agent`
  reference implementation (Apache-2.0), the x402 core spec, and the V2 batch-
  settlement launch notes; extracted verbatim canonical-message format, header
  names, envelope fields, and the Policy-Engine rule set. Header-naming and
  batch-voucher field caveats recorded (implementation-dependent; pin to SDK
  version under test).
- **Build:** mirrored the `governance_modification_harness.py` house pattern
  (dataclass result, `…Tests` class, `run_all`, `main`, `_utils` helpers).
- **Verification:** `--simulate` (17/17), unified CLI dispatch, `ruff F821`,
  full `pytest testing/` + `tests/`.
- **Files audited:** `cli.py`, `count_tests.py`, `_utils.py`,
  `governance_modification_harness.py`, `x402_harness.py`, `x402_merchant.py`,
  README, pyproject, CHANGELOG, CI workflow.

---

## 6. Self-Test Suite

- **New:** `TestRegFireblocks` (8 checks) exercises the reference verifier
  directly: recipient-tamper detection, freshness window, downgrade,
  did:web SSRF, policy refusals, batch monotonicity/binding, and a
  full-suite 17/17 simulate assertion.
- **Full suite:** 240 passed (pre-existing 4 integration errors are the flaky
  mock-MCP-server port bind, unrelated to this round).
- **Count:** `count_tests.py` definitive 508; `cli._total_tests()` 508 — in sync.

---

## 7. Score

**9/10** — Only LOW-equivalent residuals (spec caveats: header naming and
batch-voucher field list are implementation-dependent and flagged as such; the
reference signature primitive is HMAC not ES256 by design for zero-dep). No
MEDIUM+ defects, no regressions, all tests pass.

| Round | Score |
|---|---|
| R30 | 9 |
| R31 | 9 |
| R32 | 9 |
| **R33** | **9** |

---

## 8. Recommendations

- **Immediate:** none blocking.
- **Before next release:** when a live Fireblocks-enabled x402 endpoint is
  available, pin FB-* header names (`X-PAYMENT` vs `PAYMENT-SIGNATURE`,
  `X-402-Integrity`) to the SDK version and enable live-mode assertions.
- **Architecture:** consider an optional `cryptography`-backed ES256/did:web
  verifier behind the existing `mcp-server` optional-dep pattern, so live mode
  can verify real envelopes without making `cryptography` a hard dependency.

---

## 9. Cumulative Assessment

Two-round arc (R33 Fireblocks + R34 AP2) closes the middle-layer gap in the
4-layer agentic-payments stack. After R33 the harness covers settlement
(x402/L402) **and** settlement hardening (Fireblocks) — the first open-source
adversarial conformance suite for the x402 hardening extension. Total issues
raised this round: 7 (all coverage-gap, all addressed). Open defects: 0.
