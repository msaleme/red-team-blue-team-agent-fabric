# VS-R02 Tier-B Runbook — Settlement-Time Evidence (E3, real on-chain)

**Scope:** ACP-012 (receipt nonce reuse), ACP-016 full (cross-session aggregate at settlement), ACP-017 (delegation/authorization expiry, sign-time vs settlement-time), ACP-018 (revoke-and-immediately-spend race). Unlike Tier A, every test in this round **settles on-chain — real Base Sepolia gas + USDC, real transaction hashes.**

**Status as of 2026-07-18: HOLD. Settlement has not been reached. ACP-012 reached `PROOF_GENERATED`, but the selected facilitator refused the old request before settlement. Four compatibility defects are reconciled: the adapter supplied the base64 `X-PAYMENT` header string where `/verify` expects the decoded payment object; x402.org returned Cloudflare `error code: 1010` only to Python's default `Python-urllib/*` user agent; the merchant relay omitted the `extra.name` / `extra.version` EIP-712 domain from `paymentRequirements`; and the assumed token name was wrong. Base Sepolia USDC contract `0x036CbD53842c5426634e7929541eC2318f3dCF7e` returns `USDC` from `name()` on two read-only RPCs, while the old `USD Coin` domain caused `invalid_exact_evm_token_name_mismatch`. With all four corrections in place, the final ACP-012 attempt reached facilitator transaction simulation but returned HTTP 200 / `invalid_exact_evm_transaction_simulation_failed`, without a transaction hash or an explanatory detail. The run ended fail-closed: 0 test USDC, 0 payer-side ETH, no replay. x402.org currently advertises v1 `base-sepolia` as well as v2 `eip155:84532`, so version mismatch is not the demonstrated cause. Do not retry or run ACP-016/017/018 until this simulation failure is grounded by facilitator diagnostics or a non-guesswork preflight reconciliation.**

**Branch:** `vs-r02/skeleton`. **Code:** `protocol_tests/agentcore_payments_harness.py` (functions `test_agentcore_settle_*`, appended after the Tier-A `test_agentcore_signtime_*` stubs). **Merchant:** `protocol_tests/x402_merchant.py` (vendored, uncommitted — see provenance note below). **Env:** `scripts/vs-r02-env.sh` (unchanged — same env extends to Tier B; the Tier B code adds its own `AGENTCORE_TIER_B_SETTLE_OK` gate on top).

---

## 1. Funding prerequisite — read this first

The delegation is live and valid to **2026-09-09** on wallet `0x7889454DF1EB44B2fA0878179A1845F5b4649286`, but the wallet holds **0 ETH and 0 USDC on Base Sepolia**. Nothing in this round can run until it is funded.

**What to fund:**

| Asset | Amount needed | Why |
|---|---|---|
| Base Sepolia ETH | ~0.005 ETH (safety margin; the x402 "exact" scheme is typically gas-sponsored by the facilitator, not the payer, but keep a buffer in case any CDP-side operation needs payer gas) | Defensive — VS-R01's prerequisites table shows 0.0008 ETH was "sufficient for tens of test transactions" under the old flow; keep at least that much again |
| Base Sepolia USDC | 1.0 USDC minimum (this round's own hard-capped total is $0.10 — see §3 — 1.0 USDC leaves ~10x headroom for retries/re-runs without re-funding) | The four Tier B tests spend real USDC; retries after a wrong-guess extraction failure cost $0 (see §4), but a successful settlement round plus a couple of re-runs should stay comfortably under 1.0 USDC |

**Faucets:**

- Base Sepolia ETH: [Coinbase Developer Platform faucet](https://portal.cdp.coinbase.com/products/faucet) (select Base Sepolia, ETH) — this is the same CDP account already provisioned for the wallet's delegated signing, so it's the natural first stop.
- Base Sepolia USDC: same CDP faucet, select the USDC asset. Alternative: [Circle's testnet USDC faucet](https://faucet.circle.com/) if the CDP faucet is rate-limited.
- Send both to `0x7889454DF1EB44B2fA0878179A1845F5b4649286`. Confirm receipt on a Base Sepolia block explorer (e.g. Basescan Sepolia) before proceeding — do not rely on the CDP dashboard balance alone.

**After funding:** re-run the Tier-A wall-check probe (`source scripts/vs-r02-env.sh`, one light `create_payment_session` + `process_payment` call) to confirm delegated signing is still enabled and the grant hasn't lapsed, before spending any Tier B budget.

---

## 2. What's real vs. what's a stub — merchant scaffold assessment

**Verdict: the merchant relay logic is real and runnable, not a stub. The AgentCore→merchant handoff is the one genuinely unverified link — and the code fails closed (spends $0) if that link doesn't work as assumed.**

`protocol_tests/x402_merchant.py` (vendored into this working tree, uncommitted, from commit `3cf9797` on branch `feat/vs-r02-x402-merchant` / PR #217 — **not merged, and that branch has diverged from current `main`**, see the provenance note at the top of the file):

- `SyntheticMerchant.handle()` — real request logic (402 challenge, X-PAYMENT parsing, verify+settle dispatch, settlement bookkeeping). Socket-free; the Tier B tests call it **directly in-process**, no HTTP server or public URL needed.
- `MockFacilitator` — real, deterministic, in-memory. Enforces EIP-3009-style nonce uniqueness. Used only for offline sanity-checking (see below), never for a live run.
- `CoinbaseFacilitator` — real. POSTs to the actual x402 facilitator's `/verify` and `/settle` endpoints (`https://x402.org/facilitator` by default), which broadcast the EIP-3009 `transferWithAuthorization` on Base Sepolia and return a genuine transaction hash. This is the live path every Tier B test uses.
- 10 unit tests existed on PR #217 (`testing/test_x402_merchant.py`, not vendored here — out of scope for this staging pass; TODO(Mike) below).

I additionally ran an **offline sanity check** (no network, no AWS) wiring the harness's new `_tier_b_submit_for_settlement()` helper against `MockFacilitator`: sign→extract→submit→settle succeeded, and a same-nonce replay was correctly rejected. This confirms the harness-to-merchant plumbing is correct; it does **not** confirm the AgentCore-to-harness plumbing (see below), which can only be confirmed live.

**Observed AgentCore handoff, 2026-07-18:** a live `PROOF_GENERATED` response returns the signed material at `paymentOutput.cryptoX402.payload`, with `authorization` and `signature` fields. `_extract_settlement_proof()` now recognizes that exact path and still requires both fields before returning a usable proof. The first live ACP-012 attempt therefore reached the real facilitator, which returned HTTP 403 on `/verify`; no transaction was broadcast. The remaining integration question is facilitator authorization or endpoint compatibility, not whether AgentCore returns a signed proof.

**If this assumption is wrong** (AgentCore settles internally, no proof is exposed), the on-chain question can still be answered, just with a different plan:

- **Plan B (not implemented, do this manually if Plan A's extraction fails on the first live run):** point `payTo` at a real wallet address Mike controls, run the sign call with a real (non-burn) `payTo`, and confirm settlement by watching the wallet's incoming balance on a Base Sepolia block explorer instead of trying to intercept and resubmit a proof. This still answers ACP-012/016/017's questions (does it settle, does it aggregate, does expiry hold) — it just moves verification from "inspect the merchant's settlement record" to "inspect the chain directly." ACP-018's race-window design is unaffected either way (it doesn't depend on proof extraction).

**TODO(Mike):**
1. Reconcile `protocol_tests/x402_merchant.py` with PR #217 properly (rebase and merge, or replace this vendored copy with the merged version) — don't let the two copies drift.
2. On the very first live run of ACP-012, check `proof_extraction_method` in the result JSON immediately. `"none"` means Plan A's core assumption is wrong — stop, read §4, decide whether to fix `_extract_settlement_proof`'s candidate keys or fall back to Plan B.
3. Bring over `testing/test_x402_merchant.py` from PR #217 if you want the merchant's own unit tests in this branch's test suite (not done in this staging pass — the four Tier B tests already exercise the merchant's real code paths, this would just add isolated coverage).

---

## 3. Safety rails (enforced in code, not just documented)

| Rail | Mechanism | Value |
|---|---|---|
| Fail-closed settlement gate | `_tier_b_settle_gate()` — every `test_agentcore_settle_*` calls this first; `pytest.skip()` unless the env var below is `1` | `AGENTCORE_TIER_B_SETTLE_OK=1` |
| Per-transaction USD cap | `_tier_b_check_cap()` raises `AssertionError` before any network call if a single settle would exceed this | `TIER_B_MAX_USD_PER_TX = 0.02` |
| Per-suite USD cap | Same function, checked against a module-level running total across all four tests in one process | `TIER_B_MAX_USD_PER_SUITE = 0.10` |
| Every tx hash logged | `_tier_b_record_spend()` appends `{test_id, usd_amount, tx_hash, timestamp, running_total_usd}` to `_tier_b_spend_ledger` and prints a `[TIER-B-SPEND]` line per settlement; every real settlement also prints a `[TIER-B-TX]` line with the tx hash | Inspect `_tier_b_spend_ledger` after a run, or grep the console log |
| No fabricated proofs | `_extract_settlement_proof()` only accepts a proof carrying a **real signature**; returns `(None, "")` otherwise. `_encode_x_payment_with_real_signature()` never falls back to a placeholder signature (unlike `x402_merchant.encode_x_payment()`, its own test helper, which is deliberately NOT reused here for this reason) | Fail closed, not fail fake |
| Burn-address payTo throughout | Every signed authorization and every `SyntheticMerchant`'s `PaymentRequirements.pay_to` uses `BURN_PAYTO = 0x000...dEaD` | No counterparty, minimal blast radius |
| Failed/rejected attempts cost $0 against the caps | `_tier_b_record_spend()` is only called with a nonzero amount when `settle_success` is `True` | A wrong extraction guess, a rejected replay, or a correctly-refused expired settlement never eats suite budget |

**Stated total spend estimate for a full clean run of all four tests:**

| Test | Real settlements | Approx USDC |
|---|---|---|
| ACP-012 | 1 (first settle) + 1 replay attempt (expected rejected, $0 if it behaves as expected) | $0.01 |
| ACP-016 (full) | 3 (one per parallel session) | $0.03 |
| ACP-017 | 2 (within-window + past-window attempt; past-window expected rejected, $0 if it behaves as expected) | $0.01–0.02 |
| ACP-018 | up to 5 small attempts in the race loop | up to $0.01 |
| **Total (expected)** | | **~$0.05–0.07** |
| **Hard ceiling (enforced in code)** | | **$0.10** (`TIER_B_MAX_USD_PER_SUITE`) |

If any test behaves anomalously (e.g. ACP-012's replay unexpectedly settles), the ledger will show the real amount and the suite-cap check will halt further spending once $0.10 is reached — it will not silently keep going. **If ACP-012 reports `ANOMALY_replay_settled: true`, stop immediately and verify manually against the actual chain state before running anything further or citing the result anywhere.**

**Approved payer-side gas ceiling: exactly 0 Base Sepolia ETH per attempt.** The selected x402.org facilitator submits the EIP-3009 transaction, so a wallet-originated gas transaction is not expected. If any preflight, response, or wallet prompt indicates payer gas is required, stop before broadcast and preserve the evidence. This ceiling is separate from the 0.02 test-USDC per-attempt and 0.10 test-USDC suite caps; neither cap may be relaxed during a run.

---

## 4. Run commands

Same invocation convention as Tier A: plain Python functions returning a dataclass, `bash`-only (env script uses `BASH_SOURCE`), `PYTHONPATH="$PWD"`.

**Step 0 — confirm funding and gates:**

```bash
cd ~/clawd/red-team-blue-team-agent-fabric
git checkout vs-r02/skeleton
source scripts/vs-r02-env.sh
# Confirm the printed wallet balance summary shows nonzero ETH + USDC before continuing.
# (scripts/vs-r02-env.sh currently prints "UNFUNDED — Tier A only"; that line
# needs updating once funded — see TODO in that script.)
```

**Step 1 — collect-only sanity check (safe with or without creds, no gate needed):**

```bash
PYTEST_COLLECT_ONLY=1 PYTHONPATH="$PWD" pytest --collect-only -q protocol_tests/agentcore_payments_harness.py -k settle
```

**Step 2 — run ACP-012 alone first** (cheapest, and the one that tells you immediately whether the proof-extraction assumption in §2 holds):

```bash
source scripts/vs-r02-env.sh
export AGENTCORE_TIER_B_SETTLE_OK=1
PYTHONPATH="$PWD" python3 -c "
import dataclasses, json
from protocol_tests.agentcore_payments_harness import test_agentcore_settle_receipt_nonce_reuse as t
r = t()
print(json.dumps(dataclasses.asdict(r), indent=2))
"
```

Check `response_received.first_settle.proof_extraction_method` and facilitator result in the output:
- `structured_dict_with_signature:paymentOutput.cryptoX402.payload` → the observed AgentCore handoff worked. Continue only if the first facilitator verification succeeds.
- `"none"` → AgentCore did not return anything `_extract_settlement_proof` recognizes. **$0 was spent** (the test never reached `merchant.handle()`). Inspect only the response schema, extend the candidate-key list deliberately, and re-run ACP-012 before any other case.
- A 4xx/5xx facilitator refusal after proof extraction → **stop all Tier-B cases.** This is an integration blocker, not settlement evidence. Capture the status and sanitized reason, then validate the configured facilitator endpoint/authorization before retrying.
- Before enabling the settlement gate, confirm the facilitator evidence manifest includes: the `/supported` capability snapshot, facilitator URL, request payment/requirements digests, HTTP status, and bounded redacted response body. Never retain a reusable signed authorization in that manifest.

**Step 3 — run the remaining three, saving result JSONs:**

```bash
source scripts/vs-r02-env.sh
export AGENTCORE_TIER_B_SETTLE_OK=1
PYTHONPATH="$PWD" python3 - <<'PY'
import dataclasses, json, pathlib
from protocol_tests.agentcore_payments_harness import (
    test_agentcore_settle_cross_session_aggregate,
    test_agentcore_settle_delegation_expiry_boundary,
    test_agentcore_settle_revoke_race,
)

out_dir = pathlib.Path("reports/round_24")
out_dir.mkdir(parents=True, exist_ok=True)

runs = [
    (test_agentcore_settle_cross_session_aggregate, "acp-016-settle-cross-session-aggregate.json"),
    (test_agentcore_settle_delegation_expiry_boundary, "acp-017-settle-delegation-expiry.json"),
    # ACP-018 requires manual WalletHub coordination — see the note printed
    # when it starts. Run it LAST, and be ready to click Revoke in the
    # WalletHub UI during the ~5s loop window.
    (test_agentcore_settle_revoke_race, "acp-018-settle-revoke-race.json"),
]

for fn, filename in runs:
    print(f"running {fn.__name__} ...")
    result = fn()
    path = out_dir / filename
    path.write_text(json.dumps(dataclasses.asdict(result), indent=2))
    print(f"  -> {path} (passed={result.passed}, evidence_class={result.evidence_class})")
PY
```

Save ACP-012's own JSON the same way (or re-run Step 2's snippet with a `path.write_text(...)` added) as `reports/round_24/acp-012-settle-receipt-nonce-reuse.json`.

**ACP-018 needs you at the keyboard.** It prints `[ACP-018] Session ready. Starting 5-attempt loop (1.0s apart). CLICK REVOKE IN WALLETHUB NOW if running interactively.` — have the WalletHub UI open and revoke the grant for `vs-r01-walletub-1779903158` / `vs-r01-cdp-grant-probe` during that ~5-second window. **This will end the grant for every subsequent test** — see §5.

---

## 5. Order matters — ACP-018 is destructive to the grant

Run ACP-012, ACP-016, ACP-017 **before** ACP-018. ACP-018 asks the operator to revoke the only active delegated-signing grant partway through its loop — after that, every subsequent `ProcessPayment` call (Tier A or Tier B, any test, any future round) will fail with `AccessDeniedException` until the grant is re-issued through the WalletHub UI (same manual step VS-R02's test plan already anticipated: "WalletHub permission grant expires mid-round... re-grant if needed"). Treat ACP-018 as the last thing you run in a session, and expect to need to manually re-grant before doing anything else with this identity afterward.

---

## 6. Expected evidence per test

| Test | Question | Evidence Class (as coded) |
|---|---|---|
| ACP-012 | Does a resubmitted (same-nonce) signed authorization settle twice? | E3 if first settle succeeds; E2.5 if it doesn't reach settlement |
| ACP-016 (full) | Does SETTLED spend aggregate across parallel sessions, or does fragmentation (shown at admission in ACP-001, at sign-time in ACP-009) persist all the way to real settlement? | E3 if ≥1 session settles; E2.5 otherwise |
| ACP-017 | Is a signed authorization's `validBefore` boundary re-checked at settlement, or only honored at sign time? (Reframed from the WalletHub grant's real expiry — see docstring for why) | E3 if the past-window settlement attempt is reached; E2.5 otherwise |
| ACP-018 | Does a mid-flight WalletHub revoke stop an in-flight settlement race? **Requires manual coordination — not fully push-button** | E3 if ≥1 attempt settles; E2.5 otherwise |

All four are characterizations, not vulnerability verdicts — same convention as every prior VS-R01/VS-R02 test (`passed` means "the measurement completed cleanly," not "the security property holds"). No "vulnerability" framing in any artifact; industry-pattern-first language; no commercial CTAs.

---

## 7. Result JSON locations

`reports/round_24/acp-012-settle-receipt-nonce-reuse.json`, `acp-016-settle-cross-session-aggregate.json`, `acp-017-settle-delegation-expiry.json`, `acp-018-settle-revoke-race.json` — same directory and `AgentCoreTestResult` schema as Tier A, with `evidence_class` now genuinely reaching `"E3"` where settlement succeeds.

The module-level `_tier_b_spend_ledger` (printed as `[TIER-B-SPEND]` lines during the run) is the authoritative cross-test spend audit trail — capture the console output alongside the JSONs, since the ledger itself is not persisted to a file by the run snippets above.

---

## 8. After the run

- Registration in `protocol_tests/cli.py` / `scripts/count_tests.py` is deliberately **not** done by this staging pass, same discipline as Tier A — Mike registers after live validation.
- Fold results into `testing/CRITICAL_EVALUATION_VS-R02_{date}.md` and update `reports/round_24/VS-R02-independent-review-package.md`'s evidence-class table (it currently states plainly: "No test in this round settled on-chain... require a funded Base Sepolia wallet and are out of scope for this round" — that sentence needs updating once Tier B actually runs).
- If ACP-012 or ACP-016 produces an unexpected finding (replay settles, or aggregation is NOT enforced at settlement), apply the same audit-correction discipline VS-R01/Tier-A went through before any public framing — get a second read, resolve E2.5-vs-E3 calibration questions explicitly, and route through `playbook_vendor_surface_disclosure.md` if the finding is security-relevant enough to warrant coordinated disclosure.
