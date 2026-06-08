# VS-R02 Test Plan — Settlement-time evidence (E3+)

**Lineage:** VS-R02 per the round-naming convention in `reference_harness_round_lineages.md`. Reports under `reports/round_24/`. Test stubs continue `acp-NNN` numbering from VS-R01 (next: ACP-009).

**Branch:** `vs-r02/skeleton` from `vs-r01/skeleton @ 7515831`.

**Created:** 2026-06-08.

## Scope and posture

VS-R01 established admission-time and structural-layer evidence (E1/E2) across 8 ACP stubs. With the delegated-signing wall down and `PROOF_GENERATED` verified 2026-06-08 15:07 UTC, settlement-time evidence (E3-E5) becomes reachable. VS-R02 produces evidence at the layers VS-R01 could not reach: actual signing, real on-chain settlement, persistence, replay, and isolation.

**Evidence Class targets:**

- E3 (transactional / enforcement characterization) — primary
- E4 (persistence / replay-resistance) — secondary
- E5 (isolation / security-boundary) — tertiary, requires positive controls

**Brand-voice posture:** no "vulnerability" framing in any artifact. Maintain admission-vs-settlement and structural-vs-enforcement language from VS-R01. Each test produces a single evidence claim mapped to a single Evidence Class.

## Prerequisites verified 2026-06-08

| Gate | State |
|---|---|
| CDP project-level Delegated Signing toggle | ON (2026-06-08 ~10:01 UTC) |
| WalletHub per-wallet grant for `0x7889454DF1EB44B2fA0878179A1845F5b4649286` | Granted (2026-06-08 15:05 UTC, expires 2026-07-08) |
| ProcessPayment returns `PROOF_GENERATED` | Verified (2026-06-08 15:07 UTC, ProcessPayment ID `3ffb5e2f-4d1f-40c4-a8bc-ffabd1533e50`) |
| Base Sepolia ETH balance | 0.0008 ETH (sufficient for tens of test transactions) |
| Base Sepolia USDC balance | 4.0 USDC (sufficient for hundreds of $0.01 tests) |
| CDP project policy | `fa4712b5-7283-4dd7-9c7f-3ea04c97488e`, permissive `ethValue` on `base-sepolia` |
| AgentCore CredentialProvider | `vsr01cdpcreds`, apiKeyId `4ef66e37-1fa0-4490-8e78-fc1822e0dc7d` |
| PaymentManager | `vsr01testmanager-5wnc0eppzd` |
| PaymentConnector | `vsr01cdpconnector-35v7gsfbtn` |
| PaymentInstrument | `payment-instrument-YQFWKtbGbKUuiMF` |
| userId | `vs-r01-walletub-1779903158` |
| agentName | `vs-r01-cdp-grant-probe` (carry-forward); new agentName per test for isolation rounds |

## Test surface taxonomy

Two execution tiers:

**Tier A — proof-only tests (cheap, no gas cost).** Test ends at `PROOF_GENERATED`; the signed payment authorization is captured but not submitted to a merchant. Validates signing scope, delegation enforcement, replay, isolation without touching the chain. Most tests live here.

**Tier B — settlement tests (real gas + USDC cost).** Test ends with on-chain settlement via a synthetic x402 merchant we control. Validates that the signed proof actually settles, gas accounting, receipt provenance. Smaller subset.

## New ACP stubs (12 candidates, ranked by evidence-class lift)

### Carry-forward verification at settlement-time

| ID | Carries forward | New evidence layer | Tier | Cost |
|---|---|---|---|---|
| **ACP-009** | ACP-001 (spend fragmentation) | E3 — real signed payments fragment across N parallel sessions; do they aggregate at sign-time? | A | 0 gas |
| **ACP-010** | ACP-002 (session reset replay) | E3 — re-issued PaymentSession on same instrument; can old session's signed proofs replay? | A | 0 gas |
| **ACP-011** | ACP-003 (402 terms forgery) | E3 — agent-constructed x402 payload signed by CDP; does signing care about `payTo` legitimacy? | A | 0 gas |

### New settlement-only tests (not testable at admission-time)

| ID | Test | Evidence Class | Tier | Cost |
|---|---|---|---|---|
| **ACP-012** | Receipt nonce reuse: submit the same signed authorization twice within `validBefore` window. Does CDP/AgentCore reject? | E4 (replay-resistance) | B (settlement required) | ~$0.02 USDC + gas |
| **ACP-013** | `validBefore` / `validAfter` boundary timing: signed proof valid at T-1s, T, T+1s of `validAfter`; same at `validBefore` boundary | E3 (enforcement) | A | 0 gas |
| **ACP-014** | Cross-instrument signature attempt: request sign for wallet B using delegation granted only for wallet A under same `(userId, agentName)`. Does CDP enforce per-wallet delegation scope? | E5 (isolation) | A | 0 gas |
| **ACP-015** | Multi-instrument admission with shared delegation: create instrument-B for same email, attempt sign without re-granting. Does grant on wallet A leak to wallet B for same end user? | E5 (isolation) | A | 0 gas |
| **ACP-016** | Cross-session aggregate spend limit enforcement under real transactions. VS-R01 ACP-001 showed admission-time caps don't aggregate; now test whether *settled* spend aggregates | E3 (enforcement) | B | ~$0.05 USDC over 5 tx |
| **ACP-017** | Delegation expiry boundary: sign at T-5min of expiry, sign at T+5min. Does CDP enforce expiry at sign-time or at settlement-time? | E3 (enforcement) | A | 0 gas (requires near-expiry delegation, or revoke-then-sign sequence) |
| **ACP-018** | Revoke-and-immediately-spend race: end user clicks Revoke in WalletHub at T; agent submits ProcessPayment at T+50ms with cached delegation | E3 (enforcement) + E5 (isolation) | A | 0 gas |
| **ACP-019** | Cross-agent delegation isolation: same `userId` but different `agentName`. Does grant for `vs-r01-cdp-grant-probe` allow signing under `vs-r02-attacker-agent`? | E5 (isolation) | A | 0 gas |
| **ACP-020** | Settlement-time audit trace completeness: re-test VS-R01 ACP-005 with actual `PROOF_GENERATED` returned. Verify the audit trail surfaces every field VS-R01 stub couldn't observe at admission-time | E4 (persistence) | A | 0 gas |

## Execution order (recommended)

**Round 1 — pure isolation tests (cheapest, highest-information):** ACP-014, ACP-015, ACP-019. These probe the per-wallet / per-agent delegation scoping that VS-R01 could not test. Likely highest finding density.

**Round 2 — replay and timing:** ACP-012, ACP-013, ACP-017, ACP-018. Test the validBefore/validAfter + revoke-race envelope.

**Round 3 — carry-forwards at settlement:** ACP-009, ACP-010, ACP-011. Validate or refute the VS-R01 admission-time findings at settlement-time.

**Round 4 — settlement-required:** ACP-016. The most expensive test (~$0.05 USDC + gas across multiple parallel-session settlements).

**Round 5 — audit completeness:** ACP-020. Cleanup round; capture the full audit trail with successful settlements in place.

## Synthetic merchant for Tier B tests

ACP-012 and ACP-016 need real settlement. Two paths:

**Path X — facilitator submission:** submit the `X-PAYMENT` header to the Coinbase x402 facilitator with a synthetic merchant endpoint we control. Requires spinning up a tiny x402-compliant endpoint (10 min, FastAPI or similar).

**Path Y — Coinbase x402 Bazaar:** route through the public Bazaar to a low-cost test endpoint. Cheaper to set up but introduces a third-party dependency.

**Recommend Path X** — keeps the integration entirely under our control, removes the third-party signal. The synthetic-merchant endpoint becomes a reusable harness component.

## Risk register

| Risk | Mitigation |
|---|---|
| Real transactions reduce wallet balance | Tier A tests are 0-cost; Tier B caps at <$0.10 USDC total per round; faucet drops available if balance runs low |
| Tests trigger CDP rate limits or temporary bans on the project | Run with delays between calls; abort round if 429 observed; document any rate-limit-as-finding |
| WalletHub permission grant expires mid-round (30-day default → 2026-07-08) | Complete VS-R02 before 2026-07-01; re-grant if needed |
| Test artifacts include real signatures that could theoretically be submitted by an attacker | Sign with `payTo=0xdEaD` (burn address) for all proof-only tests; never sign against real merchant addresses |
| Disclosure timing if a finding emerges that IS security-relevant | Switch to coordinated disclosure discipline per `playbook_vendor_surface_disclosure.md` before any public reference |

## Deliverables

| Artifact | Location | When |
|---|---|---|
| Test stub code (ACP-009 through ACP-020) | `protocol_tests/agentcore_payments_harness.py` (append to existing) | Round-by-round as executed |
| Per-test result JSON | `reports/round_24/acp-NNN-*.json` | One per test |
| Critical Evaluation report | `testing/CRITICAL_EVALUATION_VS-R02_{date}.md` | After all rounds |
| Independent Review Package | `reports/round_24/VS-R02-independent-review-package.md` | After internal eval |
| Branch | `vs-r02/skeleton` (this branch) | Created 2026-06-08 |

## Estimated effort

- **Test stub coding:** 4-6 hours for 12 stubs (most are variants of existing patterns)
- **Round 1-3 execution:** 30-60 min per round (mostly waiting on CDP/AgentCore responses)
- **Round 4 execution:** 90 min (settlement-required, slower)
- **Round 5 + audit:** 30 min
- **Critical evaluation writeup:** 2 hours
- **Independent review package:** 1 hour
- **Total:** ~10-14 hours over 2-3 sessions

## Coordination with VS-R01 disclosure

The VS-R02 work happens **after** the AWS Bedrock disclosure clock starts. If AWS or Coinbase responds during VS-R02 execution with a docs update, error-string fix, or behavior change, fold those into VS-R02's findings (some D-findings may close before the round finishes, which is itself useful evidence).

## Brand-voice / employment guardrails

- E1 framing for documentation/UX findings (D-class continues from VS-R01)
- E3/E4/E5 framing for newly testable enforcement/persistence/isolation findings
- No "vulnerability" framing publicly until VS-R02 internal audit completes
- No commercial CTAs in any artifact
- Maintainer credit to Coinbase Developer Support for the 2026-06-08 unblock
- Industry-pattern-first language preserved

## Memory + state captured (2026-06-08)

- `project_vs_r01_followup_actions.md` updated: Coinbase action marked resolved, this plan file referenced
- `reference_harness_round_lineages.md` updated: VS-R02 lineage formalized
- `~/clawd/memory/_AGENT_PRIMER.md` updated: integration verified state, VS-R02 plan pointer

## Resume-from-reboot checklist

After machine reboot, the work resumes from this state:

1. `cd ~/clawd/red-team-blue-team-agent-fabric`
2. `git checkout vs-r02/skeleton` (this branch)
3. `source scripts/vs-r01-env.sh` (env carries forward — same PaymentManager, Connector, Instrument)
4. Verify wall is still down: `python -c "..."` (use the wall-check probe from the 2026-06-08 success log)
5. Start with Round 1: ACP-014, ACP-015, ACP-019. Implement stubs in `protocol_tests/agentcore_payments_harness.py`, run, save JSONs to `reports/round_24/`.

The WalletHub permission grant remains active until 2026-07-08, so resume can happen any time before then without re-granting.

Related: [[reference_harness_round_lineages]], [[playbook_vendor_surface_disclosure]], [[project_vs_r01_followup_actions]].
