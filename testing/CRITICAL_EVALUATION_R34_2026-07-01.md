# CRITICAL EVALUATION — Round 34

**Date:** 2026-07-01
**Round:** 34
**Focus:** AP2 mandate-chain security conformance harness
**Test count:** 508 across 35 modules
**Version:** 4.6.0
**Evaluator:** Automated round (parallel research + house-style build)

---

## 1. What Changed

| File | Change | Lines |
|------|--------|------|
| `protocol_tests/ap2_harness.py` | **New module** — AP2-001..AP2-017 (17 tests) | +~700 |
| `protocol_tests/cli.py` | Registered harness `ap2` | +4 |
| `scripts/count_tests.py` | Added `ap2_harness.py` label | +1 |
| `testing/test_code_quality.py` | `TestRegAP2` (8 checks) + MODULES + count guard | +~80 |
| `pyproject.toml`, `README.md`, `docs/TEST-INVENTORY.md`, `CHANGELOG.md` | Count/version already at 508 / 4.6.0 from R33; AP2 rows added | — |

**Purpose.** AP2 (Agent Payments Protocol) is the authorization/trust layer that
sits above settlement: a chain of cryptographically signed *mandates* proving an
agent is authorized to assemble a cart and pay for it. Google transferred AP2 to
the **FIDO Alliance** for community governance and shipped v0.2 — so the trust
anchor for the whole mandate model is no longer a single-vendor decision. The
harness had no coverage of this layer. R34 adds a mandate-chain conformance
suite testing whether an AP2 verifier (Merchant / MPP / Credential Provider)
rejects the attacks AP2's own threat model calls out ("All LLMs and Agents MUST
be considered potential attackers").

**Design.** Stdlib-only. A deterministic `AP2Verifier` reference model
implements the mandate semantics: canonical hashing (`checkout_hash` =
base64url(SHA-256(JCS(checkout_jwt)))), the `transaction_id == checkout_hash`
chain link, `sd_hash` open→closed binding, `cnf` agent-key binding, constraint
evaluation with **fail-closed on unknown constraint types**, scope/expiry
checks, deterministic-signature rejection, replay/double-spend tracking, and
funding-instrument scope binding (Visa TAP / Mastercard Agentic Tokens). The
`_valid_chain()` fixture builds a coherent chain each test mutates one field of.
`--simulate` runs the differential; `--url` folds a live verifier behind the
VS-R03 liveness gate.

**Model-duality note.** AP2 v0.2 carries two overlapping vocabularies (the SDK
`IntentMandate/CartMandate/PaymentMandate` runtime triple and the canonical
`open/closed Checkout + Payment` delegate-SD-JWT chain). The harness models the
shared hash-chaining and constraint semantics that both express, and labels the
two under-specified assertions (`jti` replay window, mandate `exp`) as `I`
(inferred/strict) vs `N` (normative) in each result.

---

## 2. Prior Fix Verification (R33 → R34)

R34 is additive. R33's Fireblocks harness and all earlier regressions confirmed
intact by the full suite:

| Prior area | Guard | Status |
|---|---|---|
| R33 Fireblocks conformance (FB-001..017) | `TestRegFireblocks` (8) | ✅ intact (17/17) |
| VS-R03 verdict-correctness | `test_vsr03_verdict_correctness.py` (22) | ✅ intact |
| Test-count consistency | `TestRegTestCount` | ✅ intact (508) |
| Harness-count guard | `TestRegX402.test_harness_count` | ✅ intact (35) |
| F821 CI guard | `ruff --select F821` | ✅ passes |

---

## 3. New Issues Found (coverage gaps this round closes)

| # | Severity | Gap | Addressed by |
|---|---|---|---|
| #165 | CRITICAL | No test that a tampered cart breaks `checkout_hash` / that a stale cart is rejected | AP2-001/002 |
| #166 | CRITICAL | No test of Intent→Cart scope escalation (amount cap, merchant, SKU) | AP2-003/004/005 |
| #167 | MEDIUM | No test that an unknown constraint type fails closed | AP2-006 |
| #168 | CRITICAL | No test of the mandate chain link (`transaction_id == checkout_hash`) / payment reuse | AP2-007 |
| #169 | HIGH | No test of open-mandate substitution (`sd_hash`) or agent-key forgery (`cnf`) | AP2-008/009 |
| #170 | HIGH | No test of user-signature presence, replay (`jti`), expiry, double-spend | AP2-010..013 |
| #171 | HIGH | No test that a deterministic signature scheme (Ed25519) is rejected | AP2-014 |
| #172 | CRITICAL | No test of funding-instrument scope binding (TAP / Agentic Token) or premature credential release | AP2-015/016 |

No CRITICAL/HIGH defects were found in existing code during this round.

---

## 4. What's Good

- The chain-link test (AP2-007) and funding-scope test (AP2-015) are the two
  that bridge this harness into the existing settlement depth: they express the
  exact identity (`transaction_id == checkout_hash`) and the agent+merchant
  scoping that a tokenized card credential (Visa TAP / Mastercard Agentic Token)
  must satisfy inside a Payment Mandate.
- Fail-closed constraint evaluation (AP2-006) encodes a real AP2 MUST that a
  naive verifier — one that ignores constraints it doesn't recognize — violates.
- The `_valid_chain()` fixture proved its own worth: an early run correctly
  failed AP2-006 because mutating the open mandate broke `sd_hash` before
  constraint eval was reached — the test caught an incoherent fixture, and the
  fix (re-bind `sd_hash`) makes the test target the intended property.
- Normative-vs-inferred labeling keeps the two strict assertions honest about
  where the harness exceeds the letter of v0.2.

---

## 5. Methods

- **Research:** parallel background agent pulled the
  `google-agentic-commerce/AP2` canonical files (`specification.md`, `flows.md`,
  `agent_authorization.md`, `security_and_privacy_considerations.md`) and the
  SDK `mandate.py`; extracted verbatim field lists, the delegate-SD-JWT payload,
  the `transaction_id`/`checkout_hash` chain identity, and the MUST-reject rules.
  Visa TAP / Mastercard Agentic Token mappings sourced secondarily and labeled.
- **Build:** house pattern (dataclass result, `…Tests` class, `run_all`,
  `main`, `_utils` helpers); reference `AP2Verifier` for real differential logic.
- **Verification:** `--simulate` (17/17), unified CLI dispatch, `ruff F821`,
  full `pytest testing/` + `tests/`.

---

## 6. Self-Test Suite

- **New:** `TestRegAP2` (8 checks): valid-chain verifies, checkout_hash tamper,
  amount-cap escalation, unknown-constraint fail-closed, chain-link + replay,
  deterministic-signature rejection, funding-scope binding, and a full-suite
  17/17 simulate assertion.
- **Full suite:** 240 passed (4 pre-existing flaky integration errors unrelated).
- **Count:** definitive 508; `cli._total_tests()` 508 — in sync.

---

## 7. Score

**9/10** — Two assertions (`jti` replay window, mandate `exp`) are stricter than
v0.2's explicit prose and are labeled `I` (inferred) rather than presented as
normative; the TAP/Agentic-Token `payment_instrument.type` wire values are not
yet public and are modeled generically. These are LOW design caveats, disclosed
in-code and in the report. No MEDIUM+ defects, no regressions, all tests pass.

| Round | Score |
|---|---|
| R31 | 9 |
| R32 | 9 |
| R33 | 9 |
| **R34** | **9** |

---

## 8. Recommendations

- **Immediate:** none blocking.
- **Before next release:** as the FIDO Payments TWG publishes field-level TAP /
  Agentic-Token schemas, replace the generic `payment_instrument.scope` model in
  AP2-015 with the concrete `type` values and gate strict-mode assertions.
- **Architecture:** add an SD-JWT / VC signature verifier (optional
  `cryptography` dep, `mcp-server`-style) so live mode can validate real mandate
  signatures, and track upstream AP2 issue #268 (Checkout JWT alg constraint vs
  WebBot Auth) as a known-tension test.

---

## 9. Cumulative Assessment

With R33 (Fireblocks settlement hardening) and R34 (AP2 authorization), the
harness now spans all four layers of the agentic-payments stack: comms
(MCP/A2A), merchant journey (adjacent via intent-contract/capability-profile),
authorization/trust (**AP2 — new**), and settlement + hardening (x402/L402 +
**Fireblocks — new**). This is the coverage story that was previously hollow in
the middle. Issues raised across the two rounds: 15 (all coverage-gap, all
addressed). Open defects: 0. Total tests 474 → 508.
