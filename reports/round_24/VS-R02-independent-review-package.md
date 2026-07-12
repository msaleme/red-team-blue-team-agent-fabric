# VS-R02 Vendor Surface Evaluation — Independent Review Package

**Target:** AWS Bedrock AgentCore Payments (preview) + Coinbase CDP delegated signing
**Round:** VS-R02 (Tier A — sign-time evidence)
**Harness:** `agent-security-harness` (protocol_tests/agentcore_payments_harness.py, `test_agentcore_signtime_*`)
**Date:** 2026-07-11
**Predecessor:** VS-R01 (admission-time evidence, E1/E2) — `reports/round_23/VS-R01-independent-review-package.md`

---

## Headline

VS-R01 established, at the admission layer (E1/E2), that AgentCore Payments does not aggregate spend caps across parallel sessions under one principal. VS-R02 Tier A carries that and three sibling questions **through real Coinbase CDP delegated signing** — i.e. to a live `PROOF_GENERATED` cryptographic authorization, one step past admission but short of on-chain settlement. Two VS-R01 characteristics **persist at the signing layer**; one candidate finding was **refuted by a redesigned test** (the platform control works); several positive controls were confirmed.

**No test in this round settled on-chain. All claims are bounded to sign-time (evidence class E2.5, defined below). No E3/settlement claim is made.**

---

## Evidence taxonomy (extends VS-R01)

VS-R01 defined E1–E5. VS-R02 introduces one sub-tier to describe evidence that is stronger than admission-time but has not settled:

| Class | Definition | Max claim strength |
|---|---|---|
| E1 | Static / documentation observation | Descriptive only |
| E2 | Admission-time runtime observation (input/admission gate, before signing) | Admission characterization |
| **E2.5 (new)** | **Sign-time, pre-settlement — derived from a real CDP cryptographic signing operation (`PROOF_GENERATED`, past admission) that did NOT settle on-chain** | **Signing-layer characterization; may NOT claim settlement, enforcement of settled spend, or on-chain outcome** |
| E3 | Settlement-time observation — calls that actually settled | Settlement / enforcement characterization |
| E4 | Persistence / replay-resistance | Replay-resistance claims |
| E5 | Isolation / security-boundary | Boundary claims |

The E2.5 tier exists specifically to stop the E2→E3 drift the VS-R01 taxonomy was built to catch. A signed authorization is a real, security-relevant artifact — it is what an intermediary would present — but whether it *settles* (and whether settled spend aggregates, or reaches an illegitimate recipient) is untested until Tier B.

---

## Executive summary

Four Tier-A stubs were executed end-to-end against a live CDP Base Sepolia testnet wallet (`0x7889…4649286`), delegated-signing grant active, then subjected to an **independent skeptical audit** (1 BLOCK, 3 RESCOPE) whose corrections were applied and the suite re-run before this package was written. All authorizations stopped at `PROOF_GENERATED` (0 gas, nothing submitted to a merchant/facilitator). Every reported `PROOF_GENERATED` resolved from a structured `status` field (recorded per result via `status_extraction_method`), not a heuristic fallback.

**Characteristics that persist at the signing layer (E2.5):**
- **O1′ — No cross-session spend-cap aggregation.** Five parallel sessions under one `(userId, agentName)`, each capped $0.05, all five reached `PROOF_GENERATED`; each session's `availableSpendAmount` decremented only by its own signed amount. No shared accounting was **visible via the per-session `availableSpendAmount` field** at sign-time (a settlement-time principal ledger would not surface here). Confirms the VS-R01 admission-time finding through real signing. **Contrast:** budget *does* aggregate **within** a single session (three sequential signs took $0.05→$0.02) — the gap is specifically cross-*session*.
- **O2′ — CDP signing does not gate recipient legitimacy.** Delegated signing produced valid authorizations for the zero address and syntactically-valid unknown addresses; only *malformed* recipients were rejected. *Interpretive assessment (not an observed platform guarantee):* this is expected behavior for a signing primitive — payTo vetting is a merchant/facilitator-layer concern, not a CDP-signing concern. Documented so operators do not assume the signer validates recipients.

**Positive controls confirmed (the platform behaves correctly):**
- **C1′ — Cap-vs-amount enforced at sign-time.** With $0.02 of a $0.05 session cap remaining, a $5.00 request was rejected pre-sign ("Pending amount: 0.02 USD, Transaction amount: 5.0000"). Verified arithmetically. Closes a VS-R01 gap (cap-vs-amount was previously unreachable due to an upstream short-circuit).
- **C2′ — Session deletion voids signing.** After a session was deleted, a sign attempt against it **with a fresh client token** returned `ValidationException: Payment session not found`. A fresh session under the same principal re-signed independently. *(This corrects a VS-R01-lineage test that held the client token constant across deletion and mistook AWS idempotency de-duplication for session-binding evidence — see Audit, below.)*
- **C3′ — Structural input validation and client-token idempotency** both function as documented (malformed addresses, exotic networks, negative amounts rejected pre-sign; identical resubmissions de-duplicated).

**Net:** amount and lifecycle controls hold at the signing layer; the cross-session aggregate ceiling and recipient-legitimacy checks are absent (the latter by design). The absent aggregate ceiling is the load-bearing finding — carried from VS-R01 and now confirmed one layer deeper.

---

## Audit discipline (artifact integrity)

After the first execution, an independent auditor was run with an explicit hostile mandate (find tautologies, claim/measurement mismatches, evidence-class overclaims, layer confounds). Verdict: **1 BLOCK, 3 RESCOPE, 0 SOUND**. Corrections applied before this package:

1. **BLOCK — ACP-010 (session-reset replay)** was invalid as first run: it held the client token constant across the session delete, so `PROOF_GENERATED` on replay was an idempotency-cache hit, not evidence a deleted session signs. Redesigned with the client token as the isolated variable and re-run → the platform correctly refuses (C2′ above). The original "deleted session still signs" reading is **retracted**.
2. **RESCOPE — evidence class.** All four were tagged E3; none settled. Relabeled **E2.5** and the tier defined in the taxonomy.
3. **RESCOPE — ACP-011 layering.** The four pre-sign `ValidationException` results are AgentCore's own validator (E2, admission-style); only the three `PROOF_GENERATED` payTo variants are CDP-signing evidence (E2.5). Separated in the artifact; `malformed_rejected` demoted to a sanity check.
4. **RESCOPE — ACP-016 ledger claim** tightened to "no shared accounting *visible via the per-session `availableSpendAmount` field*."
5. Added `status_extraction_method` to every result so a reviewer can confirm each status came from a structured field, not a substring match.

This package reflects the corrected verdicts, not the first-pass ones.

---

## Findings (detail)

| ID | Carries forward | Result | Class |
|---|---|---|---|
| ACP-009 | ACP-001 | 5/5 parallel sessions signed; no cross-session aggregation at sign-time | E2.5 |
| ACP-016 (Tier-A) | — | Per-session ledgers independent; no shared accounting visible via `availableSpendAmount` | E2.5 |
| ACP-011 | ACP-003 | payTo legitimacy not gated at signing (interpretive); cap-vs-amount enforced (C1′); pre-sign validator rejects malformed/exotic/negative/over-budget (E2) | E2.5 / E2 |
| ACP-010 | ACP-002 | Session deletion voids signing (C2′); fresh session re-signs independently. Corrected from a client-token confound | E2.5 |

Raw artifacts: `reports/round_24/acp-0{09,10,11,16}-*.json`.

---

## Restraints in effect

- **No claim beyond E2.5.** Settlement-time behavior (does settled spend aggregate; does an authorization to an illegitimate recipient settle) is Tier B, deferred until the wallet is funded.
- **No "vulnerability" framing.** Findings are architectural characteristics, signing-layer observations, and positive controls — not exploits. The absent cross-session ceiling requires operators to layer principal-level accounting at the application layer; this is a documentation/architecture observation.
- **No typosquat framing** (carried from VS-R01 O2a — unvalidated).
- **`vs-r01/skeleton @ 7515831` remains the immutable VS-R01 cite-from-here state.** VS-R02 artifacts live under `reports/round_24/` on `vs-r02/skeleton`.

---

## Methodology & reproducibility

Env: `scripts/vs-r02-env.sh` (extends `vs-r01-env.sh`). Run under `bash` (env scripts are `BASH_SOURCE`-based) with `PYTHONPATH="$PWD"`; each test is a plain function returning an `AgentCoreTestResult`. AWS profile `harness-testnet` / `us-east-1`; CDP credential held server-side by the AgentCore CredentialProvider `vsr01cdpcreds`; delegated-signing grant active through 2026-09-09. Burn-address (`0xdEaD…`) payTo throughout; 0 gas.

## Tier B (deferred)

The strictly-E3 questions — settled-spend aggregation (ACP-016 full), receipt nonce reuse (ACP-012), delegation-expiry and revoke-race enforcement at settlement (ACP-017/018) — require a funded Base Sepolia wallet and are out of scope for this round.
