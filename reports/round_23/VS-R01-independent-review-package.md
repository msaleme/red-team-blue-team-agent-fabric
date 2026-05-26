# VS-R01 Vendor Surface Evaluation — Independent Review Package

**Subject:** Adversarial evaluation of AWS Bedrock AgentCore Payments (Preview), Coinbase x402 Bazaar, and adjacent Salesforce Agent Scanners (claim-matrix only)
**Author:** Michael K. Saleme · ORCID [0009-0003-6736-1900](https://orcid.org/0009-0003-6736-1900)
**Framework:** `agent-security-harness` v4.4.2 ([PyPI](https://pypi.org/project/agent-security-harness/), [repo](https://github.com/msaleme/red-team-blue-team-agent-fabric))
**Eval branch:** `vs-r01/skeleton` @ commit `88ecff7`
**Date:** 2026-05-24 — 2026-05-26 (scoped → executed → audit-corrected)
**Distribution:** review-ready; intended for AWS Bedrock security team coordination, arxiv reviewer, NIST CAISI artifact submission, or any external party evaluating the findings.

---

## Executive summary

This package documents the first vendor-surface evaluation (VS-R01) of AWS Bedrock AgentCore Payments preview using `agent-security-harness` v4.4.2. The evaluation ran 8 adversarial test stubs against the live preview within 18 days of its May 7, 2026 launch, with full white-box methodology and end-to-end test execution on a Coinbase CDP Base Sepolia testnet wallet. An independent code-reviewer audit was performed before publication; all flagged issues were corrected and tests re-run.

**Four findings are presented for external citation**, each with explicit scope, reproduction steps, and audit-driven limitations:

1. **Admission-control aggregation gap (P2-Medium).** AgentCore Payments admission control does not aggregate session caps across N parallel sessions or N instruments under the same `(userId, agentName)`. Operators relying on AgentCore for principal-bound spend governance must layer application-layer cumulative tracking. Scope: admission-time only; spend-time enforcement not measured in this round.
2. **Semantic input validation present (P1-High PASS).** Eight crafted x402 payload variants produced seven distinct error classes across structural, network-binding, amount-sign, and address-format validation layers. Cap-vs-amount validation not probed in this round (upstream short-circuit).
3. **Cross-context instrument isolation (P0-Critical PASS).** AgentCore enforces `(userId, agentName)`-scoped visibility on PaymentInstruments at the data-plane layer. Cross-context get returns `ResourceNotFoundException`; published claim acknowledges the response is semantically indistinguishable from a non-existent ID.
4. **Bazaar registry shape (P2-Medium, two distinct findings).** The CDP x402 Bazaar (50,560 listings catalogued) shows (a) 10 typosquat clusters / 28 hosts via Levenshtein clustering, and separately (b) 71.9% top-host concentration as a marketplace-diversity signal.

A fifth operational discovery surfaced during corrective probing: AgentCore Payments preview requires Coinbase CDP "delegated signing" to be enabled at the CDP-project policy level before any successful ProcessPayment can complete. This gate is not documented in the AWS launch communications path and blocks deeper spend-time variants of findings 1, 2, and the equivalent ACP-004 idempotency test.

---

## Methodology

### Test framework
`agent-security-harness` v4.4.2 — open-source adversarial test suite, 470 tests across 32 modules at framework level, AIUC-1 pre-cert, aligned to NIST AI 800-2 IPD ([DOI 10.6028/NIST.AI.800-2.ipd](https://doi.org/10.6028/NIST.AI.800-2.ipd)).

### Scope
- **In scope:** AWS Bedrock AgentCore Payments preview APIs (`bedrock-agentcore-control` + `bedrock-agentcore`), public CDP x402 Bazaar discovery endpoint, Coinbase CDP Server Wallet on Base Sepolia testnet, publicly-documented Salesforce Agent Fabric / Agent Scanners surfaces.
- **Out of scope:** Anthropic MCP Tunnels / Self-Hosted Sandboxes (deferred to a future round, pending research-preview access); merchant-side x402 endpoint testing; live-net payment flows; any Salesforce employment-credentialed surface (operator filter enforced).
- **Test wallet:** `0x0E88cF39132336a4A9a7C0D37C1253Fa321F557B` (Base Sepolia testnet only). Funded via Coinbase CDP faucet to 0.0001 ETH + 1 USDC at evaluation start; verified at 0 spend at evaluation end (no ProcessPayment reached settlement layer due to delegated-signing gate).

### Approach
White-box methodology: harness modules import the target SDK (`boto3`) directly, construct adversarial payloads in Python, submit through the documented API surface, and capture full response payloads to JSON. Each test cleans up the resources it creates. Per-test results are reproducible from the harness repo at `vs-r01/skeleton` branch.

### Audit discipline
After the 8 ACP stubs were initially run, an independent code-reviewer agent was invoked with explicit skeptical mandate (find false positives, claim/measurement mismatches, severity miscalibrations, scope creep). The audit ran read-only against the 8 test functions + 8 result JSONs and produced a structured report. The audit flagged 4 BLOCK + 1 FIX + 3 NOTE issues before any external citation; all corrections were applied in commit `88ecff7`. The audit report is preserved at `~/vault/projects/vs-r01-acp-audit-2026-05-26.md` (in the author's working repo).

### Reproducibility
Every test:
- Imports the live SDK and exercises the documented API surface
- Includes hard-coded testnet safety guards (refuses to import without explicit env-var opt-in)
- Captures the full response to `reports/round_23/acp-00{N}-*.json`
- Is executable via `pytest protocol_tests/agentcore_payments_harness.py::test_<name>` from the documented venv setup (`scripts/vs-r01-env.sh`)

A reviewer with their own AWS Bedrock preview enrollment + Coinbase CDP testnet credentials can re-run the entire evaluation from the branch state.

---

## Findings

### Finding 1 — Admission-control aggregation gap

**Severity:** P2-Medium
**Affected components:** `bedrock-agentcore:CreatePaymentSession`, `bedrock-agentcore:CreatePaymentInstrument`
**Tests:** ACP-001 (parallel sessions), ACP-008 (multi-instrument)
**Verdict:** FAIL by design — admission control does NOT aggregate caps per principal

#### Claim
AgentCore Payments admission control does not aggregate authorized session caps across multiple sessions or instruments under the same `(userId, agentName)`. Each `CreatePaymentSession` and `CreatePaymentInstrument` call succeeds with its own configured cap; no platform-level principal-bound ceiling is enforced at admission time.

#### Reproduction
Under the documented setup chain (PaymentManager + CredentialProvider + Connector + IAM):

```python
import boto3
dp = boto3.client('bedrock-agentcore', region_name='us-east-1')

# Create 5 parallel sessions, each with $0.50 cap, under the same user
for i in range(5):
    dp.create_payment_session(
        userId="example-user",
        agentName="example-agent",
        paymentManagerArn="arn:aws:...payment-manager/xxx",
        limits={"maxSpendAmount": {"value": "0.50", "currency": "USD"}},
        expiryTimeInMinutes=15,
        clientToken=...,
    )
# All 5 admitted. Cumulative admission-authorized = $2.50.
```

The same pattern holds for `create_payment_instrument`: 3 instruments admitted under the same `(userId, agentName)`. Sessions are not bound to instruments at `CreatePaymentSession` time (no `paymentInstrumentId` parameter on that API), so N instruments × M sessions are independent counts, not paired.

#### Observed
- 5/5 parallel sessions admitted, each with $0.50 cap, cumulative admission-authorized $2.50
- 3/3 instruments admitted under same `(userId, agentName)`
- Documented per-session ceiling = $10,000 (from boundary validation error)
- Theoretical max via N parallel sessions bounded only by AWS rate limits on CreatePaymentSession

#### Scope (audit-corrected, explicit)
**This finding measures admission-time behavior only.** Spend-time enforcement — whether `ProcessPayment` aggregates across sessions and refuses the (N+1)th payment when cumulative spend would exceed a principal ceiling — was NOT measured in this round. The deeper test was blocked by the delegated-signing prerequisite documented in Finding 5 (below). Until a follow-up round runs with delegated signing enabled, this finding is bounded to admission-layer aggregation.

#### Recommendation to AWS
Consider documenting in the AgentCore Payments preview guide that admission-control caps are per-session-lifecycle, not per-principal. Operators implementing principal-bound spend governance (a common enterprise requirement under EU AI Act high-risk obligations) must add cumulative tracking at the application layer.

#### Reference artifacts
- `reports/round_23/acp-001-spend-fragmentation.json`
- `reports/round_23/acp-008-policy-bypass-chain.json`
- Code: `protocol_tests/agentcore_payments_harness.py::test_agentcore_spend_fragmentation`, `::test_agentcore_policy_bypass_via_tool_chain`

---

### Finding 2 — Semantic input validation present

**Severity:** P1-High PASS
**Affected components:** `bedrock-agentcore:ProcessPayment`
**Test:** ACP-003
**Verdict:** PASS — AgentCore performs meaningful client-side validation

#### Claim
AgentCore Payments performs layered semantic validation on x402 payment payloads at the input gate, before any merchant interaction. Eight crafted payload variants produced seven distinct error classes spanning multiple validation layers:

| Variant | Error class |
|---|---|
| `empty_payload`, `structural_scheme_missing` | `Required field 'scheme' is missing` |
| `structural_network_missing` | `Required field 'network' is missing` |
| `structural_asset_missing` | `Required field 'asset' is missing` |
| `semantic_over_budget` (structurally complete except `extra`) | `Payment extra.name is required for EVM payments` |
| `semantic_exotic_network` | `Network mismatch 'ETHEREUM' is not supported for paymentNetwork 'fake-chain-vsr01-test'` |
| `semantic_negative_amount` | `Payment amount must be a positive number. Received: -50000` |
| `semantic_malformed_recipient` | `Address format mismatch: Non-EVM address cannot be used with EVM network` |

#### Scope (audit-corrected, explicit)
The most security-relevant variant for the original attack pattern (`semantic_over_budget`) short-circuited at the upstream `extra.name` structural gate, never reaching the cap-vs-amount validator. Cap-vs-amount enforcement, if present in AgentCore's input pipeline, lives at a layer beyond this round's test surface — and is itself gated by the delegated-signing prerequisite (Finding 5). A future round with delegated signing enabled would extend this finding.

#### Reference artifacts
- `reports/round_23/acp-003-402-terms-forgery.json`
- Code: `protocol_tests/agentcore_payments_harness.py::test_agentcore_402_terms_forgery`

---

### Finding 3 — Cross-context instrument isolation

**Severity:** P0-Critical PASS
**Affected components:** `bedrock-agentcore:ListPaymentInstruments`, `bedrock-agentcore:GetPaymentInstrument`
**Test:** ACP-006
**Verdict:** PASS — Isolation holds at data-plane

#### Claim
AgentCore Payments enforces `(userId, agentName)`-scoped visibility on PaymentInstruments at the data-plane layer (not solely at the IAM layer). Two PaymentInstruments were created under different `(userId, agentName)` pairs in the same AWS account. Each was invisible to the other context:

- `ListPaymentInstruments(userId=A)` returned only A's instrument; instrument B not in result set.
- `ListPaymentInstruments(userId=B)` returned only B's instrument; instrument A not in result set.
- `GetPaymentInstrument(A's id)` invoked under userId=B returned `ResourceNotFoundException`.

#### Scope (audit-flagged ambiguity, explicit)
The `ResourceNotFoundException` returned to user B on get(A's id) is semantically indistinguishable from the response a non-existent instrument ID would produce. All three of the following interpretations preserve the security property:

(a) Genuine data-plane isolation — AgentCore actively scopes visibility by userId.
(b) Privacy-preserving uniform-error response — AgentCore returns the same error class regardless of whether the resource exists, to avoid information leak.
(c) Per-user ID namespacing — instrument IDs are interpreted relative to the requesting userId.

This test does not distinguish among them. A future round should add a positive-control GET-as-owner (verifying the same ID returns 200 in the legitimate context) to disambiguate (a) from (b) or (c).

#### Reference artifacts
- `reports/round_23/acp-006-cross-agent-isolation.json`
- Code: `protocol_tests/agentcore_payments_harness.py::test_agentcore_wallet_cross_agent_isolation`

---

### Finding 4 — Bazaar registry shape (two distinct findings)

**Severity:** P2-Medium
**Affected components:** CDP x402 Bazaar discovery endpoint (`api.cdp.coinbase.com/platform/v2/x402/discovery/resources`)
**Test:** ACP-007
**Verdict:** PASS (informational — passive inventory)

#### Methodology
Paginated GET against the public CDP discovery endpoint (no authentication required). All 50,560 listings retrieved. Hostnames extracted via URL parsing; Levenshtein-distance clustering (≤ 2 edits, union-find); non-ASCII character detection for homoglyphs.

#### Finding 4a — Typosquat detection
- **10 typosquat clusters** detected by Levenshtein ≤ 2 across 761 unique hostnames
- **Largest cluster size:** 8 hosts
- **Total hosts in typosquat clusters:** 28 (3.7% of unique hostnames)
- **Non-ASCII (homoglyph) hostnames:** 0

Interpretation: The marketplace lacks pre-list edit-distance / homoglyph defenses against near-duplicate hostname registrations. The volume is small as a fraction of the registry but the presence of an 8-host cluster suggests deliberate squatting patterns at scale.

#### Finding 4b — Marketplace concentration (separate signal)
- **Top single hostname share:** 71.9% of all 50,560 listings

Interpretation: A marketplace-diversity signal that is **distinct from the typosquat signal**. One operator (the single most-listed hostname) accounts for nearly three-quarters of the registry. This is a supply-chain consideration in its own right — the failure mode of a concentrated registry differs from the failure mode of typosquat-permeability — but conflating it with typosquatting in published claims would be analytically wrong.

#### Per VS-R01 publication discipline
Aggregate counts and percentages only. No individual hostnames are named in this finding or the underlying result JSON. A reviewer with the same public endpoint access can reproduce both findings from the documented test code.

#### Reference artifacts
- `reports/round_23/acp-007-bazaar-typosquat.json`
- Code: `protocol_tests/agentcore_payments_harness.py::test_bazaar_endpoint_typosquat_inventory`

---

### Finding 5 — Coinbase CDP delegated-signing prerequisite (operational)

**Severity:** Documentation (operational)
**Affected components:** `bedrock-agentcore:ProcessPayment` integration path for Coinbase CDP credential providers
**Discovered during:** Audit-correction probing on 2026-05-26 (not one of the 8 stubs)

#### Observation
After completing the full documented setup chain — IAM user, IAM role, AgentCore PaymentManager, CoinbaseCDP CredentialProvider, PaymentConnector, CDP Server Wallet, env-var safety guards, valid x402 payload with `extra.name` and `extra.version` set to known USDC Base Sepolia values — the first `ProcessPayment` call returns:

```
AccessDeniedException: An error occurred (AccessDeniedException) when calling the ProcessPayment operation:
  Delegated signing is not enabled for your Coinbase project.
  Please enable delegated signing in your Coinbase project policies.
```

This is a CDP-project-level policy toggle, configured in the Coinbase Developer Platform portal, separate from any AWS IAM or AgentCore configuration step.

#### Operational implication
Operators following the AWS Bedrock AgentCore Payments launch documentation path may not surface this prerequisite until they attempt their first real `ProcessPayment` call. The error message is clear and actionable, but the gate is not flagged in the AWS-side setup guidance reviewed during this evaluation.

#### Why this matters for the published findings
This gate blocked the deeper spend-time variants of Findings 1 (cap-aggregation enforcement) and Finding 2 (cap-vs-amount semantic validation), and the original receipt-validation test (ACP-004). All four are deferred to a future round (VS-R02 candidate) with delegated signing enabled.

#### Recommendation
AWS documentation could surface this prerequisite earlier in the setup chain — ideally as part of the "before you begin" section of the AgentCore Payments preview guide.

---

## Limitations and unknowns

1. **Spend-time enforcement (cap-aggregation, cap-vs-amount, idempotency, replay protection) was not measured** because the Coinbase delegated-signing toggle was not enabled during this round. All four are deferred to a follow-up round.
2. **Server-side audit pipelines were not probed.** Finding on "no intent surface" (ACP-005, P2-Medium) is bounded to the 3 Payment-API input schemas — does NOT cover CloudWatch traces, AWS X-Ray, or internal AgentCore audit pipelines that may capture intent independently.
3. **`ResourceNotFoundException` ambiguity** in Finding 3 (cross-agent isolation) was not disambiguated by a positive-control test. The security property holds under all interpretations but the exact mechanism is not characterized.
4. **Bazaar listings are a snapshot** (2026-05-26 evening UTC). The 71.9% concentration and 10 typosquat clusters reflect that moment; the registry is actively indexed and these counts may shift on a subsequent retrieval.
5. **Surface 1 (Anthropic MCP Tunnels) was not exercised.** Research-preview access not yet requested. Seven scaffolded test stubs are skip-decorated in the repo for future execution.
6. **Surface 3 (Salesforce Agent Scanners) was documented only.** The author works at Salesforce; per the harness's brand-equity-while-employed posture, no employment-credentialed access was used. The comparative claim-matrix at `docs/comparative_scanner_coverage_2026-05.md` derives entirely from publicly-available documentation.

---

## Audit trail

The audit-and-correct cycle is itself part of the artifact integrity. Sequence of events:

1. **2026-05-25 → 2026-05-26 early morning:** 8 ACP stubs implemented and run initially. Five commits to `vs-r01/skeleton` branch as each stub landed.
2. **2026-05-26 morning:** Maintainer requested independent code review before any external citation. Internal audit-agent invoked with explicit skeptical mandate.
3. **2026-05-26 mid-day:** Audit report produced. 4 BLOCK + 1 FIX + 3 NOTE issues across the 8 stubs.
4. **2026-05-26 afternoon:** All BLOCK + FIX corrections applied. All 8 tests re-run with corrected logic. Cleanup verified (0 leftover resources). Commit `88ecff7` pushed.
5. **2026-05-26 evening:** This Critical Evaluation report and Independent Review Package written from the post-audit state.

The audit corrections changed:
- ACP-001: HIGH → MEDIUM (scope-narrowed to admission-only)
- ACP-002: CRITICAL → LOW (inverted PASS criterion, reframed as characterization)
- ACP-003: PASS unchanged + cap-vs-amount-not-probed note added
- ACP-004: CRITICAL → LOW (tautology removed, reframed as structural characterization)
- ACP-005: severity field consistency fixed + input-schema scope acknowledged
- ACP-006: PASS unchanged + RNF ambiguity note added
- ACP-007: single conflated finding → two distinct findings (typosquat ≠ concentration)
- ACP-008: CRITICAL → MEDIUM (scope-narrowed; sessions-not-bound-to-instruments noted; cleanup order fixed)

---

## Coordinated disclosure status

This package is **ready for coordinated disclosure** to AWS Bedrock security if the maintainer chooses that path. The three substantive findings (1, 2, 4) describe documented-behavior-or-architectural-property observations, not vulnerabilities. Finding 5 (delegated-signing prerequisite) is documentation-class, not security-class.

The maintainer's disclosure-discipline playbook (`~/.claude/projects/-home-mikes/memory/playbook_vendor_surface_disclosure.md`) governs the publication path: private contact with AWS Bedrock security first, coordinated timeline, publish after fixes ship (or, for non-fix findings like these, publish after acknowledgment from the vendor).

---

## References

1. AWS Bedrock AgentCore Payments preview: https://aws.amazon.com/blogs/industries/x402-and-agentic-commerce-redefining-autonomous-payments-in-financial-services/
2. CDP x402 Bazaar discovery layer: https://docs.cdp.coinbase.com/x402/bazaar
3. NIST AI 800-2 IPD: [DOI 10.6028/NIST.AI.800-2.ipd](https://doi.org/10.6028/NIST.AI.800-2.ipd)
4. agent-security-harness v4.4.2: https://pypi.org/project/agent-security-harness/4.4.2/
5. Repository (VS-R01 branch): https://github.com/msaleme/red-team-blue-team-agent-fabric/tree/vs-r01/skeleton
6. Author ORCID: https://orcid.org/0009-0003-6736-1900
7. Related publication: "The EU AI Act Was Written for Models. Your Agents Need Runtime Compliance." (dev.to, 2026-05-26) — runtime-compliance framing that contextualizes these findings.

---

## Suggested citation

Saleme, M. K. (2026). *VS-R01 Vendor Surface Evaluation: AWS Bedrock AgentCore Payments (Preview) — admission-control, semantic-validation, cross-context isolation, and Bazaar registry shape*. agent-security-harness v4.4.2, branch `vs-r01/skeleton` commit `88ecff7`. https://github.com/msaleme/red-team-blue-team-agent-fabric/tree/vs-r01/skeleton

---

*This package was prepared for independent review. Findings are scoped to admission-time behavior and input validation; spend-time enforcement is deferred to a follow-up round contingent on Coinbase CDP delegated signing being enabled. All test code, result JSONs, audit report, and corrections are available in the linked repository branch.*
