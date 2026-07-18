# VS-R02 Tier-A Runbook — Sign-Time Settlement Evidence

**Scope:** ACP-009, ACP-010, ACP-011, and the Tier-A portion of ACP-016. Proof-only (Tier A): every test stops at `PROOF_GENERATED` via Coinbase CDP delegated signing — nothing is submitted to a merchant/facilitator, 0 gas, no chain state changes.

**Why Tier A only:** the VS-R02 wallet (`0x7889454DF1EB44B2fA0878179A1845F5b4649286`) is currently **unfunded**. Tier B (on-chain settlement — ACP-012 nonce-reuse, the settlement half of ACP-016) requires Base Sepolia ETH + USDC and is out of scope until the wallet is funded. Do not attempt Tier B tests against this runbook.

**Branch:** `vs-r02/skeleton`. **Code:** `protocol_tests/agentcore_payments_harness.py` (functions `test_agentcore_signtime_*`, appended after the VS-R01 ACP-001..008 stubs). **Env:** `scripts/vs-r02-env.sh` (extends `scripts/vs-r01-env.sh`).

---

## What this runbook does NOT guarantee

The VS-R01 code this round is modeled on never got past `AccessDeniedException("Delegated signing is not enabled...")` or the `extra.name is required for EVM payments` structural gate — every VS-R01 `ProcessPayment` call was rejected before reaching a live signed response. The `PROOF_GENERATED` verification on 2026-06-08 (referenced in `VS-R02-test-plan.md`) was run **ad hoc, outside version control** — the exact request/response that produced it is not in this repo or in the Obsidian vault at the time this runbook was written.

Concretely, two things in the new test code are **best-effort scaffolding, not confirmed against a live response**:

1. **The `extra` payload field.** `_build_x402_exact_payload()` defaults to `extra.name="USD Coin"`, `extra.version="2"` (the public x402 "exact" scheme convention for a USDC-class EIP-712 domain). If AgentCore expects a different shape, every sign attempt will fail at the structural gate again, just like VS-R01. Override via `AGENTCORE_X402_EXTRA_NAME` / `AGENTCORE_X402_EXTRA_VERSION` if so.
2. **The `ProcessPayment` success-status field name.** `_extract_payment_status()` probes `status` / `paymentStatus` / `processPaymentStatus` and falls back to a substring search for the literal `PROOF_GENERATED` in the stringified response. This will not crash on an unrecognized schema, but it may under-report — always inspect `response_received.per_session_sign_result` / `per_variant_status` in the result JSON directly, not just the `passed` field, on the first live run.

If either assumption is wrong, the fix is localized: adjust `_build_x402_exact_payload` or `_STATUS_CANDIDATE_KEYS` / `_extract_payment_status` in `protocol_tests/agentcore_payments_harness.py`, no other files need to change.

---

## Prerequisites

| Prerequisite | Source | Notes |
|---|---|---|
| Python venv with `boto3` + `pytest` | `~/venvs/harness` | Created during VS-R01; `vs-r01-env.sh` activates it |
| AWS profile `harness-testnet`, region `us-east-1` | `~/.aws/credentials` (not in repo) | Read from env only — never hardcoded |
| `AGENTCORE_LIVE_NET_OK=1`, `AGENTCORE_ALLOW_TESTNET=1` | `scripts/vs-r01-env.sh` | Kill-switch env vars the module asserts on at import |
| `AGENTCORE_TESTNET_WALLET` | `scripts/vs-r01-env.sh` | The vsr01testnet embedded CDP wallet (module-level import gate only; not the VS-R02 wallet) |
| `AGENTCORE_PAYMENT_MANAGER_ARN`, `AGENTCORE_PAYMENT_CONNECTOR_ID`, `AGENTCORE_CRED_PROVIDER_NAME` | `scripts/vs-r01-env.sh` | Carried forward unchanged from VS-R01 provisioning |
| `AGENTCORE_VSR02_WALLET`, `AGENTCORE_CDP_PROJECT_ID` | `scripts/vs-r02-env.sh` (defaulted) | Not secrets — public wallet address + CDP project id |
| `AGENTCORE_VSR02_USER_ID`, `AGENTCORE_VSR02_AGENT_NAME`, `AGENTCORE_VSR02_INSTRUMENT_ID` | `scripts/vs-r02-env.sh` (defaulted) | The WalletHub-granted identity — the only tuple with an active delegated-signing grant |
| CDP API key file, wallet secret file | `/home/mikes/CDP/cdp_api_key.json`, `/home/mikes/CDP/cdp_wallet_secret.txt` | Referenced by `scripts/vs-r01-env.sh`; never read directly by the harness code (AgentCore's CredentialProvider holds the CDP credential server-side) |

None of the four new test functions take secrets as arguments. They authenticate exclusively via the AWS profile in scope (boto3 default credential chain) and the pre-provisioned `PaymentManagerArn` / `PaymentConnectorId` / `paymentInstrumentId` — the same pattern as every VS-R01 stub.

---

## Pre-run checklist

- [ ] Confirm today's date is before **2026-09-09** (WalletHub delegation grant expiry). If past, the grant must be re-issued before any of these tests will reach `PROOF_GENERATED` — expect `AccessDeniedException` on every sign attempt if expired.
- [ ] Confirm the VS-R02 wallet (`0x7889...4649286`) is still unfunded, or if it has been funded, **stop and re-scope**: funding changes the safety posture and Tier B tests become in-scope, which this runbook does not cover.
- [ ] `cd ~/clawd/red-team-blue-team-agent-fabric && git checkout vs-r02/skeleton`
- [ ] `source scripts/vs-r02-env.sh` — verify the printed summary shows the granted identity and CDP project id.
- [ ] Optional: a light wall-check probe (e.g. `create_payment_session` + one `process_payment` call with a trivial payload) before running the full suite, to confirm delegated signing is still enabled and to validate/correct the `extra` field assumption in isolation before spending a full test's worth of API calls on a wrong guess.
- [ ] Confirm no other agent/process is concurrently using the same `AGENTCORE_VSR02_USER_ID` / `AGENTCORE_VSR02_AGENT_NAME` (parallel-session tests are sensitive to concurrent state).

---

## Run commands

Each test is a plain Python function returning a dataclass — same invocation pattern as VS-R01 (no `__main__` CLI, no `cli.py` registration; see the module footer comment).

Collect-only (syntax/skip-decorator sanity check, safe with or without creds):

```bash
source scripts/vs-r02-env.sh
pytest --collect-only -q protocol_tests/agentcore_payments_harness.py -k signtime
```

Run all four Tier-A tests and save result JSONs:

```bash
source scripts/vs-r02-env.sh
python3 - <<'PY'
import dataclasses, json, pathlib
from protocol_tests.agentcore_payments_harness import (
    test_agentcore_signtime_spend_fragmentation,
    test_agentcore_signtime_session_reset_replay,
    test_agentcore_signtime_terms_forgery,
    test_agentcore_signtime_cross_session_aggregate_tier_a,
)

out_dir = pathlib.Path("reports/round_24")
out_dir.mkdir(parents=True, exist_ok=True)

runs = [
    (test_agentcore_signtime_spend_fragmentation, "acp-009-signtime-spend-fragmentation.json"),
    (test_agentcore_signtime_session_reset_replay, "acp-010-signtime-session-reset-replay.json"),
    (test_agentcore_signtime_terms_forgery, "acp-011-signtime-terms-payto-legitimacy.json"),
    (test_agentcore_signtime_cross_session_aggregate_tier_a, "acp-016-tier-a-cross-session-aggregate.json"),
]

for fn, filename in runs:
    print(f"running {fn.__name__} ...")
    result = fn()
    path = out_dir / filename
    path.write_text(json.dumps(dataclasses.asdict(result), indent=2))
    print(f"  -> {path} (passed={result.passed}, evidence_class={result.evidence_class})")
PY
```

Or run one test at a time (recommended for the first live pass, so a wrong `extra` payload assumption doesn't burn all four tests' worth of API calls before you notice):

```bash
source scripts/vs-r02-env.sh
python3 -c "
import dataclasses, json
from protocol_tests.agentcore_payments_harness import test_agentcore_signtime_spend_fragmentation as t
r = t()
print(json.dumps(dataclasses.asdict(r), indent=2))
"
```

---

## Result JSON location

`reports/round_24/acp-009-signtime-spend-fragmentation.json`, `acp-010-signtime-session-reset-replay.json`, `acp-011-signtime-terms-payto-legitimacy.json`, `acp-016-tier-a-cross-session-aggregate.json` — same directory and naming convention as VS-R01's `reports/round_23/acp-00N-*.json`.

Schema is `AgentCoreTestResult` (same as VS-R01) plus one additive field, `evidence_class`, new for VS-R02 — VS-R01 tagged evidence class only in the independent-review-package markdown; these four tests set it programmatically to `"E3"` in the JSON itself.

---

## Expected evidence per test

| Test | Carries forward | What a clean run tells you | Evidence Class (as coded) |
|---|---|---|---|
| ACP-009 | ACP-001 | Whether sign-time aggregation exists across parallel sessions under one (userId, agentName) — i.e. whether ACP-001's admission-time finding still holds once real CDP signing is involved | E3 |
| ACP-010 | ACP-002 | Whether a signed proof is bound to the session that produced it (session B, same clientToken + payload as deleted session A, produces a distinct response) | E3 |
| ACP-011 | ACP-003 | Whether delegated signing gates on `payTo` legitimacy or only on payload well-formedness; whether cap-vs-amount is enforced at sign-time now that `extra.name` is populated (closes the VS-R01 ACP-003 gap) | E3 |
| ACP-016 (Tier-A portion) | — | Whether the per-session `availableSpendAmount` ledger shows any cross-session coupling at sign-time. **Does not** confirm or refute settled-spend aggregation — that is Tier B, deferred | E3 (explicitly labeled partial in `details` and `response_received.note`) |

### Evidence-class calibration caveat — read before publishing anything

The normative Evidence Class taxonomy in `reports/round_23/VS-R01-independent-review-package.md` defines **E3 = "Settlement-time runtime observation — derived from calls that actually settled (post-admission)."** These four tests stop at `PROOF_GENERATED` (successful CDP delegated signing) and **do not settle on-chain**. Strictly, that is stronger than E2 (admission-time only — no real signing occurred in VS-R01) but short of the taxonomy's literal E3 definition (requires actual settlement).

The VS-R02 test plan itself already labels these Tier-A tests "E3" (see `VS-R02-test-plan.md`'s ranked-candidates table), so this runbook follows that designation in the code and JSON output as instructed. But before any of these results go into a public artifact, resolve the tension explicitly — either:

- add a sub-label (e.g. "E3-provisional / sign-time, pre-settlement") to the taxonomy doc and use that in public framing, or
- treat these results as upper-bound-E2 / lower-bound-E3 until the Tier B settlement round produces results that are unambiguously E3 by the strict definition.

This is exactly the overclaim class the taxonomy doc exists to catch (E3-strength claims from evidence that doesn't fully support them) — do the calibration pass before citing these results anywhere external.

---

## After the run

### ACP-019 controlled reproduction - 2026-07-18

Two fresh alternate agent identities, each tested after a new successful
granted-agent positive control, independently returned PROOF_GENERATED:
vs-r02-independent-control-c and vs-r02-independent-control-d. Every request
used the Tier-A burn-address payload and both sessions were deleted. The
retained artifacts are acp-019-independent-c.json and
acp-019-independent-d.json.

This reproduces the observed sign-time behavior across distinct alternate
agent names. It remains **E2.5, proof-only, pre-settlement evidence** and is
not by itself a security conclusion or a basis for public disclosure.

- Inspect every `errors` array and every `UNRECOGNIZED*` status string in the result JSONs before trusting `passed`. `passed` on these four tests only means "the measurement completed cleanly," not "the security property holds" — same convention as VS-R01's audit-corrected ACP-002/ACP-004.
- If `_extract_payment_status` never returns `PROOF_GENERATED` on any test, the most likely causes in order: (1) the WalletHub grant expired or was scoped to a different identity, (2) the `extra` payload shape is wrong, (3) the response-status field-name guess is wrong. Check `session_a_sign_response` / raw response strings in the JSON to disambiguate before re-running.
- Write `testing/CRITICAL_EVALUATION_VS-R02_{date}.md` and `reports/round_24/VS-R02-independent-review-package.md` per the VS-R02 test-plan deliverables table, after applying the same audit-correction pass VS-R01 went through (see `vault/projects/vs-r01-acp-audit-2026-05-26.md` for the pattern: verdicts get rescoped when a test's premise turns out to be tautological or the wrong layer).
- Registration in `protocol_tests/cli.py` / `scripts/count_tests.py` is deliberately **not** done by this staging pass — per this repo's `CLAUDE.md` and the module footer comment, that happens after live validation, done by Mike.
