# Critical Evaluation — VS-R01 (Vendor Surface Eval, Round 01)

**Date:** 2026-05-24 (scoped); executed 2026-05-25 → 2026-05-26; audit-corrected 2026-05-26
**Evaluator:** Claude Opus 4.7 (independent audit lineage)
**Harness version:** v4.4.2 (post-release)
**Round type:** Vendor surface evaluation (distinct lineage from internal-QA rounds R29–R32). See scope at `~/vault/projects/harness-vs-r01-scope.md`. See lineage convention at `~/.claude/projects/-home-mikes/memory/reference_harness_round_lineages.md`.
**Branch under eval:** `vs-r01/skeleton` (origin HEAD: `88ecff7`)

---

## Scope (recap)

Three vendor surfaces targeted by VS-R01:

| Surface | Target | Status |
|---|---|---|
| Surface 1 | Anthropic MCP Tunnels + Self-Hosted Sandboxes | **SKELETON ONLY** — 7 test stubs scaffolded, all `@pytest.mark.skip`-decorated pending Anthropic research-preview access (request not yet submitted) |
| Surface 2 | AWS Bedrock AgentCore Payments (Preview) | **8 of 8 ACP stubs implemented + run end-to-end against live preview** (post-audit-correction) |
| Surface 3 | Salesforce Agent Scanners | **CLAIM-MATRIX ONLY** — `docs/comparative_scanner_coverage_2026-05.md` (public docs only, no execution, no employment-credentialed access per filter) |

Round VS-R01 ships with Surface 2 substantively complete; Surface 1 deferred to a future VS round on preview-access timing; Surface 3 ships as documentation comparison only.

---

## Infrastructure stood up (Surface 2)

| Component | Identifier | Status |
|---|---|---|
| AWS CLI v2 | 2.34.53 | installed via brew |
| AWS IAM user | `harness-testnet` | account masked; us-east-1 |
| IAM user policies | `AmazonBedrockFullAccess`, `BedrockAgentCorePreview` (inline, includes `iam:PassRole` + `secretsmanager:*` scoped) | attached |
| IAM service role | `BedrockAgentCorePaymentRole` | attached `bedrock-agentcore:*` + `bedrock-agentcore-control:*` + `bedrock:InvokeModel` + `logs:*` |
| AgentCore PaymentManager | `vsr01testmanager-5wnc0eppzd` | READY |
| Coinbase CDP CredentialProvider | `vsr01cdpcreds` | secrets stored in AWS Secrets Manager |
| Payment Connector | `vsr01cdpconnector-35v7gsfbtn` | READY |
| CDP Server Wallet EVM account | `vsr01testnet` at `0x0E88cF39132336a4A9a7C0D37C1253Fa321F557B` | Base Sepolia, funded 0.0001 ETH + 1 USDC |
| Python venv | `~/venvs/harness` | python 3.14.5, boto3 1.43.14, pytest 9.0.3, cdp-sdk 1.46.0 |
| Reusable env script | `scripts/vs-r01-env.sh` | all IDs + paths baked in |

Setup encountered ~7 IAM permission gates (each a legitimate AWS guardrail). All resolved. Cleanup verified: 0 leftover sessions/instruments after every test cycle.

---

## Test execution summary (Surface 2, 8 of 8 ACP stubs)

All severities and verdicts reflect **post-audit-correction** state. The audit (`~/vault/projects/vs-r01-acp-audit-2026-05-26.md`) flagged 4 BLOCK + 1 FIX + 3 NOTE issues prior to publication; all corrections were applied in commit `88ecff7` and tests re-run.

### Evidence taxonomy (used throughout)

| Class | Definition |
|---|---|
| **E1** | Static / documentation observation (passive registry, docs, schemas) |
| **E2** | Admission-time runtime observation (live API at admission gate, pre-settlement) |
| **E3** | Settlement-time runtime observation (post-admission, real settlement) |
| **E4** | Adversarial replay / persistence validated |
| **E5** | Cross-context isolation confirmed with positive controls |

This round produces E1 and E2 only. E3+ deferred to a follow-up round once Coinbase delegated signing is enabled.

| Test | Verdict | Evidence | Scope |
|---|---|---|---|
| ACP-001 Parallel-Session Admission-Control Aggregation | Observation (architectural characteristic) | **E2** | Admission control admits 5 parallel sessions under same (userId, agentName). Scope: admission only, NOT settlement-time. Not a confirmed bypass on this round's evidence. |
| ACP-002 Session Lifecycle Characterization | Pass — characterization | **E2** | Cap state is session-scoped, not principal-scoped. Companion to ACP-001 on the temporal axis. Not a vulnerability. |
| ACP-003 Client-Side Payload Validation | Positive assurance — strong input validation observed | **E2** | 8 crafted x402 variants → 7 distinct error classes across structural, network-binding, amount-sign, address-format layers. Scope: cap-vs-amount validation not probed (variant short-circuited upstream). |
| ACP-004 ProcessPayment Structural-Layer Characterization | Pass — characterization | **E2** | Tests reached structural validation only; idempotency layer NOT measured. Documents the delegated-signing prerequisite. |
| ACP-005 Audit Trace Intent Surface Analysis (input schema only) | Pass — characterization | **E1** | 0 of 13 candidate intent-capture fields exist on the 3 Payment-API input schemas. Scope: server-side audit pipelines (CloudWatch / X-Ray / internal) not probed. |
| ACP-006 Cross-Agent Wallet/Instrument Isolation | Positive assurance — cross-context isolation observed | **E2** (E5 deferred) | List + Get cross-context returns ResourceNotFoundException; isolation holds at data-plane. Ambiguity: RNF semantically indistinguishable from non-existent ID. Promotion to E5 requires positive-control GET-as-owner. |
| ACP-007 Bazaar Inventory (split findings) | Observation | **E1** | Two distinct findings: (a) 10 near-duplicate hostname clusters / 28 hosts (Levenshtein ≤ 2; typosquat attribution requires manual validation); (b) 71.9% top-host concentration (marketplace-diversity signal, distinct from the near-duplicate signal). |
| ACP-008 Multi-Instrument Admission-Control Aggregation | Observation (architectural characteristic) | **E2** | 3 instruments + 3 sessions created under same (userId, agentName). Scope: admission only, NOT settlement-time. Note: sessions are NOT bound to instruments at CreatePaymentSession — N+M are independent axes, not paired. |

### Per-test result artifacts

All captured to `reports/round_23/`:
- `acp-001-spend-fragmentation.json`
- `acp-002-session-reset-replay.json`
- `acp-003-402-terms-forgery.json`
- `acp-004-receipt-validation.json`
- `acp-005-audit-trace-intent-surface.json`
- `acp-006-cross-agent-isolation.json`
- `acp-007-bazaar-typosquat.json`
- `acp-008-policy-bypass-chain.json`

---

## Findings (publishable, post-audit + post-feedback calibration)

After audit-correction AND the 2026-05-26 external feedback pass, four characterizations result from this round, organized by what they **affirm** versus what they **observe**:

- **Positive controls verified:** C1 strong input validation present; C2 cross-context instrument isolation holds at data-plane
- **Narrow observations (admission-layer; not confirmed bypasses):** O1 admission-control aggregation gap; O2 Bazaar registry shape (two distinct signals)
- **Operational discovery:** D1 delegated-signing prerequisite

The detail below uses the audit-corrected verdicts and the calibrated framing (positive controls labeled as such; observations bounded to what was measured; near-duplicate vs typosquat language separated).

### O1 — Admission-control aggregation gap (ACP-001 + ACP-008)

**Claim (narrow, defensible):**
AgentCore Payments admission control does NOT aggregate authorized session caps across N parallel sessions under the same (userId, agentName), nor across N instruments under the same (userId, agentName). Each session creation succeeds with its own `maxSpendAmount`; the platform applies no per-principal ceiling at admission time. Operators relying on AgentCore for principal-bound spend governance must layer cumulative spend tracking at the application layer.

**Reproduction (admission-layer only):**
1. Open N parallel sessions under same (userId, agentName), each with cap $X.
2. Observe all N admitted successfully.
3. Cumulative admission-authorized = N × X.
4. Documented per-session ceiling = $10,000 (from boundary validation error). Theoretical max via N parallel sessions = bounded only by AWS rate limits on CreatePaymentSession.

**What this does NOT prove:**
Spend-time enforcement. To prove that processing N × X aggregate spend actually settles (versus being refused at ProcessPayment time by some unobserved principal-bound check), a follow-up test requires Coinbase delegated signing enabled in the CDP project — see "Findings discovered during corrective probing." Until that round runs, the published claim is bounded to admission-layer aggregation only.

**Affected components:** `bedrock-agentcore:CreatePaymentSession`, `bedrock-agentcore:CreatePaymentInstrument`.
**Recommendation:** Operators must implement application-layer cumulative spend tracking keyed by `(userId, agentName)` if principal-bound spend governance is required.

### C1 — Strong input validation observed (ACP-003 — positive control)

**Claim:**
AgentCore Payments performs meaningful client-side validation on x402 payment payloads. 8 crafted payload variants produced 7 distinct error classes across:

| Validation layer | Error semantic |
|---|---|
| Structural | `Required field 'scheme'/'network'/'asset' is missing` |
| EVM-specific structural | `Payment extra.name is required for EVM payments` |
| Network-binding | `Network mismatch 'ETHEREUM' is not supported for paymentNetwork 'fake-chain-vsr01-test'` |
| Amount semantic | `Payment amount must be a positive number. Received: -50000` |
| Address format | `Address format mismatch: Non-EVM address cannot be used with EVM network: base-sepolia` |

**Scope note:** Cap-vs-amount validation was NOT probed in this round — the `semantic_over_budget` variant short-circuited at the upstream `extra.name` structural gate. Independent corrective probing established that ProcessPayment with all structural gates passed next reaches an `AccessDeniedException` requiring Coinbase delegated signing. Cap-vs-amount enforcement, if present, lives beyond that gate.

### C2 — Cross-context instrument isolation verified (ACP-006 — positive control)

**Claim:**
AgentCore Payments enforces (userId, agentName)-scoped visibility on PaymentInstruments at the data-plane layer (not just at the IAM layer). Two instruments created under different (userId, agentName) pairs were each invisible to the other context: `ListPaymentInstruments(userId=A)` did not return instrument B (and vice versa); `GetPaymentInstrument(A's id)` under userId=B returned `ResourceNotFoundException`.

**Ambiguity note (audit-flagged):**
`ResourceNotFoundException` is semantically indistinguishable from the response a non-existent instrument ID would produce. The security property (cross-user isolation) is preserved in either interpretation: (a) genuine data-plane isolation, (b) privacy-preserving uniform-error response, (c) per-user ID namespacing. A future round should add a positive-control GET-as-owner to disambiguate.

### O2 — Bazaar registry shape: two distinct signals (ACP-007)

The CDP x402 Bazaar (`api.cdp.coinbase.com/platform/v2/x402/discovery/resources`) is publicly indexed; 50,560 listings catalogued.

**O2a — Near-duplicate hostname clusters:**
10 hostname clusters detected by Levenshtein-distance ≤ 2 (union-find). Largest cluster: 8 hosts. 28 hosts total in clusters (3.7% of 761 unique hostnames). 0 non-ASCII (homoglyph) hostnames.

**Calibration note (per 2026-05-26 feedback pass):** Levenshtein ≤ 2 is a near-duplicate signal, not by itself proof of deliberate typosquatting — some clusters may be legitimate organizational variants (subdomain conventions, region codes, version suffixes). Manual validation of representative cluster members would be required to characterize the clusters as typosquats vs. benign variants; that validation is deferred to a follow-up round. The published claim is bounded to "near-duplicate clusters detected" with "possible typosquat" reserved for post-validation.

**O2b — Marketplace concentration:**
Top single host accounts for 71.9% of all listings. This is a **marketplace-diversity signal, distinct from the near-duplicate signal.** High concentration indicates one operator dominates the registry, a separate supply-chain consideration with its own failure mode.

Per VS-R01 publishable-artifact rules, aggregate counts only — no naming of individual hostnames.

---

## Findings discovered during corrective probing (separate from the 8 stubs)

**The Coinbase delegated-signing prerequisite.**
During audit-correction work on ACP-004, probing AgentCore with a fully-valid x402 payload (with `extra.name` and `extra.version` set to known USDC Base Sepolia values) revealed a previously undocumented gate:

```
AccessDeniedException: An error occurred (AccessDeniedException) when calling the ProcessPayment operation:
  Delegated signing is not enabled for your Coinbase project.
  Please enable delegated signing in your Coinbase project policies.
```

**Operational implication:** AgentCore Payments preview requires not only the IAM + role + policies + CDP credential provider + payment manager + connector setup chain (which we documented across ~7 IAM gates), but also a CDP-project-level toggle for delegated signing. Operators following the AWS launch documentation may not surface this gate until they attempt their first ProcessPayment call. Worth documenting in any operational guide.

This gate blocked deeper variants of ACP-001 (spend-time aggregation), ACP-002 (cap state across actual spend), ACP-004 (real payment-state idempotency), and ACP-008 (cumulative spend across instruments). All four would need a follow-up round (VS-R02) with delegated signing enabled to extend the findings beyond admission-control characterization.

---

## What's good (positive findings)

- AgentCore's IAM + role + permissions model is straightforward once the iterative gates are documented. The setup script `scripts/vs-r01-env.sh` makes the full chain reproducible.
- The payment APIs follow consistent AWS conventions (clientToken on every write, paymentManagerArn required on every operation, soft-delete-vs-hard-delete model normal).
- Client-side validation (ACP-003) is layered and produces distinct, actionable error messages.
- Cross-context isolation (ACP-006) holds at the data-plane, not just IAM.
- Cleanup hygiene works: every test cleaned up its own resources; 0 leftover after all 8 runs.
- Audit and correction discipline: independent code reviewer flagged 8 issues across 4 BLOCK + 1 FIX + 3 NOTE before any external citation. All applied.

---

## Methods

### Test methodology
White-box code inspection of the harness modules + dynamic execution against the live AgentCore Payments preview. Each stub: scope doc (`~/vault/projects/harness-vs-r01-scope.md`) → implementation in `protocol_tests/agentcore_payments_harness.py` → execution from a Python venv → result captured to `reports/round_23/*.json` → audit + correction cycle.

### Audit methodology
Independent code-reviewer agent invoked with explicit skeptical mandate (find false positives, claim/measurement mismatches, severity miscalibrations, scope creep). Audit ran read-only against the 8 test functions + 8 result JSONs; report at `~/vault/projects/vs-r01-acp-audit-2026-05-26.md`. 4 BLOCK + 1 FIX + 3 NOTE issues identified. All BLOCKs and the FIX were corrected before any external citation; NOTEs are now embedded as scope acknowledgments in the test code and result JSONs.

### Files audited
- `protocol_tests/agentcore_payments_harness.py` (all 8 test functions)
- `reports/round_23/acp-00{1-8}-*.json` (all 8 result captures)
- Cross-reference: commit messages, scope doc, and `details` strings

---

## Self-test status

Per round_23 discipline (`CLAUDE.md`):
- New modules NOT registered in `protocol_tests/cli.py:HARNESSES` (intentional — these are vendor-surface evals, separate test count from internal-QA modules; registration would inflate the 470-tests claim without code-level integration).
- `scripts/count_tests.py` source-of-truth unchanged: 470 tests across 32 modules.
- New tests run via `pytest protocol_tests/agentcore_payments_harness.py::test_<name> -v` from the venv.
- All 8 ACP stubs collect cleanly under `pytest --collect-only`.
- Safety guards (`AGENTCORE_LIVE_NET_OK=1`, `AGENTCORE_TESTNET_WALLET`, `MCP_TUNNEL_PREVIEW_OK=1`, `SANDBOX_TEST_OK=1`) verified firing AND passing.

---

## Maturity assessment

**Narrow but reproducible; payment-settlement layer untested.**

The evidence base from this round is:
- 2 positive controls verified (input validation; cross-context isolation)
- 2 narrow admission-time observations (admission-control aggregation; Bazaar registry shape)
- 1 operational discovery (delegated-signing prerequisite, not a security finding)

What this round does NOT establish:
- Settlement-time behavior on any axis (cap aggregation at spend, cap-vs-amount enforcement, idempotency, replay protection)
- Whether the near-duplicate hostname clusters represent deliberate typosquatting vs. benign organizational variants
- Whether `ResourceNotFoundException` in cross-context get is data-plane isolation, privacy-preserving uniform error, or per-user namespacing

What's working well in this round:
- Audit-and-correct discipline caught 4 BLOCK + 1 FIX + 3 NOTE issues before publication.
- All 8 ACP stubs ran end-to-end with clean cleanup (0 leftover resources).
- Reproducibility is real: any reviewer with their own AWS Bedrock preview + CDP testnet enrollment can re-run from the branch state.
- The reframes (6 of 8 stubs adjusted from scope-doc originals because original attacks required infrastructure out of scope) are documented honestly in code + JSON.

What gates the next round:
- Coinbase delegated signing must be enabled in the CDP project policies before settlement-time variants can run.
- Anthropic MCP Tunnels research-preview access must be requested before Surface 1 stubs can execute.
- Manual hostname-cluster validation must be performed before any "typosquat" claim is published.

This round is publishable for coordinated disclosure. It is not yet strong enough for a bold public security claim — that requires settlement-time evidence from VS-R02.

---

## Recommendations

### Before any external citation
- ☑ Apply all 8 audit corrections — **done in commit `88ecff7`**.
- ☑ Verify cleanup of all AgentCore resources — **done, 0 leftover**.
- ☐ Decide on AWS Bedrock security disclosure path for the admission-control aggregation finding (P2-Medium, but documents an architectural property worth surfacing to AWS).

### Next round (VS-R02 candidate work)
- Enable Coinbase delegated signing in CDP project policies; rerun ACP-001/002/004/008 deeper variants for spend-time enforcement.
- Submit Anthropic MCP Tunnels research-preview access request; implement Surface 1 stubs.
- Add positive-control variants (GET-as-owner for ACP-006, valid-payload for ACP-003 cap-vs-amount probe).
- Probe other AgentCore data-plane operations (`get_resource_payment_token`, `get_payment_instrument_balance`) for cross-API spend tracking.

### Repo / process
- Consider a `reports/round_23/AUDIT.md` companion that summarizes the audit-and-correct cycle inline with the eval — proves the discipline visibly in any external review.
- The audit pattern (independent reviewer with skeptical mandate, before publication) is itself worth memorializing as a playbook artifact.

---

## Cumulative assessment

VS-R01 is the first round in the vendor-surface evaluation lineage. The lineage convention (`R{N}` for internal harness audits, `VS-R{NN}` for vendor surfaces) is codified in memory (`reference_harness_round_lineages.md`) and the disclosure-discipline playbook (`playbook_vendor_surface_disclosure.md`) governs the publication path.

The evaluation program is structured around **disclosure-and-calibration discipline**, not bug-finding. The differentiating practices are: narrow claims tied to specific evidence classes (E1–E5), audit cycles before publication, explicit downgrades of findings after skeptical review, separation of tested vs inferred behavior, and preserved audit lineage on a frozen branch.

Net: VS-R01 ships as **narrow but reproducible** rather than wide-but-overclaimed. Three review cycles (initial execution → independent code audit → external feedback calibration) have been applied before any external citation; each cycle narrowed the published claims and tightened the framing.
