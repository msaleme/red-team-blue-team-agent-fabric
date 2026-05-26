# VS-R01 Vendor Surface Evaluation — Independent Review Package

**Subject:** Adversarial evaluation of AWS Bedrock AgentCore Payments (Preview) and Coinbase x402 Bazaar
**Author:** Michael K. Saleme · ORCID [0009-0003-6736-1900](https://orcid.org/0009-0003-6736-1900)
**Framework:** `agent-security-harness` v4.4.2 ([PyPI](https://pypi.org/project/agent-security-harness/), [repo](https://github.com/msaleme/red-team-blue-team-agent-fabric))
**Eval branch:** `vs-r01/skeleton` @ commit `88ecff7` (with documentation at `09837f6`+)
**Date:** 2026-05-24 — 2026-05-26 (scoped → executed → audit-corrected)
**Distribution:** review-ready for coordinated disclosure (AWS Bedrock security, arxiv reviewer, NIST CAISI artifact submission). Not yet a public security claim — see Maturity Assessment.

---

## Headline

VS-R01 identifies an **admission-time spend-governance characteristic** and **registry-shape observations** in early AWS Bedrock AgentCore Payments / Coinbase x402 Bazaar infrastructure, while confirming **strong input validation** and **cross-context instrument isolation** at the data-plane layer. Settlement-time behavior was not measured in this round (gated by a Coinbase project policy toggle). Public characterization remains bounded to admission-time observations until settlement-time evidence exists.

## Evidence taxonomy

To keep claims aligned with what was measured, every finding in this package is tagged with one of the following evidence classes:

| Class | Definition |
|---|---|
| **E1** | Static / documentation observation — derived from public docs, schemas, or passive registry inspection |
| **E2** | Admission-time runtime observation — derived from live API calls at the admission/input gate, before any settlement |
| **E3** | Settlement-time runtime observation — derived from calls that actually settled (post-admission) |
| **E4** | Adversarial replay / persistence validated — settlement + replay or persistence behavior characterized |
| **E5** | Cross-context isolation confirmed with positive controls — isolation verified against both negative AND positive controls |

This round produces only E1 and E2 evidence. E3, E4, and E5 are deferred to a follow-up round once Coinbase delegated signing is enabled and positive-control test variants are added. Each finding's class is stated inline below.

---

## Executive summary

This package documents the first vendor-surface evaluation (VS-R01) of AWS Bedrock AgentCore Payments preview using `agent-security-harness` v4.4.2, run within 19 days of the May 7, 2026 preview launch. Eight adversarial test stubs were executed end-to-end against a live Coinbase CDP Base Sepolia testnet wallet, followed by an independent code-reviewer audit and corrective pass before publication.

Four characterizations result from this round, organized by what they affirm versus what they observe:

### Validation observations (positive controls)

- **C1. Strong input validation observed.** [E2 — admission-time] AgentCore's `ProcessPayment` enforces layered semantic checks on x402 payload structure, network–instrument binding, amount sign, and address format. Eight crafted payloads produced seven distinct error classes pre-flight. Cap-vs-amount validation was not exercised in this round (upstream short-circuit).
- **C2. Cross-context instrument isolation observed.** [E2 — admission-time; **E5 deferred**] PaymentInstruments created under different `(userId, agentName)` pairs are mutually invisible at list and get; cross-context get returns `ResourceNotFoundException`. The response is semantically indistinguishable from a non-existent ID, which preserves the security property under either interpretation but was not disambiguated by a positive-control test. Promotion to E5 requires a positive-control GET-as-owner variant in a follow-up round.

### Architectural characteristics (admission-layer observations)

- **O1. Admission-control aggregation characteristic.** [E2 — admission-time] AgentCore Payments does not aggregate authorized session caps across N parallel sessions or N instruments created under the same `(userId, agentName)`. Each admission succeeds with its own configured cap; the platform applies no principal-bound ceiling at admission time. Operators implementing principal-level spend governance need to layer cumulative tracking at the application layer. *Scope:* admission-time only — settlement-time enforcement was not measured this round.
- **O2. Bazaar registry shape: two distinct signals.** [E1 — static/documentation] The CDP x402 Bazaar discovery endpoint catalogues 50,560 listings across 761 unique hostnames. Two separate properties of the registry surfaced: (a) 10 **near-duplicate hostname clusters** by Levenshtein ≤ 2 (signal of near-duplicates; not validated as deliberate typosquatting in this round), and (b) **71.9% top-host concentration** as a marketplace-diversity signal distinct from the near-duplicate signal.

### Operational prerequisite (documentation observation)

- **D1. Coinbase CDP delegated-signing prerequisite.** [E1 — documentation observation surfaced via admission-time call] With the full AWS-documented setup chain in place + a valid x402 payload, the first `ProcessPayment` call returns an `AccessDeniedException` requiring delegated signing to be enabled at the CDP project policy level. This prerequisite is not surfaced in the AWS launch documentation reviewed during this evaluation, and it blocks any settlement-layer testing.

---

## Methodology

### Test framework
`agent-security-harness` v4.4.2 — open-source adversarial test suite for AI agent systems. 470 tests across 32 modules at framework level. AIUC-1 pre-cert. Aligned to NIST AI 800-2 IPD ([DOI 10.6028/NIST.AI.800-2.ipd](https://doi.org/10.6028/NIST.AI.800-2.ipd)) for statistical-reporting practices.

### Scope
- **In scope:** AWS Bedrock AgentCore Payments preview APIs (`bedrock-agentcore-control` + `bedrock-agentcore`), public CDP x402 Bazaar discovery endpoint, Coinbase CDP Server Wallet on Base Sepolia testnet.
- **Out of scope:** Anthropic MCP Tunnels / Self-Hosted Sandboxes (deferred — research-preview access not requested); merchant-side x402 endpoint testing; mainnet payment flows; any vendor-credentialed access outside public documentation. (A separate Salesforce Agent Scanners comparative claim-matrix exists in the repo for completeness but is not part of this review package; see Appendix A.)
- **Test wallet:** `0x0E88cF39132336a4A9a7C0D37C1253Fa321F557B` (Base Sepolia testnet). Funded via Coinbase CDP faucet to 0.0001 ETH + 1 USDC at evaluation start; balance unchanged at evaluation end (no `ProcessPayment` reached settlement due to D1).

### Approach
White-box methodology: harness modules import `boto3` directly, construct adversarial payloads, submit through the documented API surface, and capture full response payloads to JSON. Each test cleans up the resources it creates. Per-test results are reproducible from the harness repo at the named commit.

### Audit discipline (artifact integrity)
After the 8 stubs were initially executed, an independent code-reviewer agent was invoked with an explicit skeptical mandate — find false positives, claim/measurement mismatches, severity miscalibrations, and scope creep. The audit ran read-only against the test functions and result JSONs and produced a structured report (4 BLOCK + 1 FIX + 3 NOTE issues). All BLOCK and FIX corrections were applied before any external citation; NOTEs were embedded as scope acknowledgments in the test code and result JSONs.

The audit corrections changed the severity calibration of four tests (two demoted from CRITICAL claim language to LOW characterization; two demoted from HIGH/CRITICAL to MEDIUM with scope narrowed). The corrected verdicts are the basis for this package.

### Reproducibility
Every test:
- Imports the live SDK and exercises the documented API surface
- Includes hard-coded testnet safety guards (refuses to import without explicit env-var opt-in)
- Captures the full response to `reports/round_23/acp-00{N}-*.json`
- Is executable via `pytest protocol_tests/agentcore_payments_harness.py::test_<name>` from the documented venv setup (`scripts/vs-r01-env.sh`)

A reviewer with their own AWS Bedrock preview enrollment + Coinbase CDP testnet credentials can re-run the entire evaluation from the branch state.

---

## Findings (detail)

### C1 — Strong input validation observed

**Test:** ACP-003 (8 crafted x402 payload variants vs `ProcessPayment`)
**Verdict:** Positive control verified
**Scope:** Pre-flight input validation only. Cap-vs-amount validation untested.

AgentCore Payments performs layered semantic validation on x402 payment payloads before any merchant interaction. Eight crafted payload variants produced seven distinct error classes spanning the following layers:

| Validation layer | Error class observed |
|---|---|
| Structural | `Required field 'scheme'/'network'/'asset' is missing` |
| EVM-specific structural | `Payment extra.name is required for EVM payments` |
| Network–instrument binding | `Network mismatch 'ETHEREUM' is not supported for paymentNetwork 'fake-chain-vsr01-test'` |
| Amount sign | `Payment amount must be a positive number. Received: -50000` |
| Address format | `Address format mismatch: Non-EVM address cannot be used with EVM network` |

**Scope acknowledgment:** The most security-relevant variant for principal-bound spend governance (a structurally complete payload with `maxAmountRequired` exceeding the session cap) short-circuited at the upstream `extra.name` structural gate, never reaching the cap-vs-amount validator. If cap-vs-amount enforcement is present in AgentCore's input pipeline, it lives at a layer beyond this round's test surface — and is itself gated by D1.

**Artifact:** `reports/round_23/acp-003-402-terms-forgery.json`

### C2 — Cross-context instrument isolation verified

**Test:** ACP-006 (cross-(userId, agentName) list + get on PaymentInstruments)
**Verdict:** Positive control verified
**Scope:** Data-plane visibility scoping confirmed. Mechanism not disambiguated.

Two `PaymentInstruments` were created under distinct `(userId, agentName)` pairs in the same AWS account. Each was invisible to the other context:
- `ListPaymentInstruments(userId=A)` returned only A's instrument; B not in the result set.
- `ListPaymentInstruments(userId=B)` returned only B's instrument; A not in the result set.
- `GetPaymentInstrument(A's id)` invoked under userId=B returned `ResourceNotFoundException`.

**Scope acknowledgment:** `ResourceNotFoundException` is semantically indistinguishable from the response a non-existent instrument ID would produce. The security property (cross-context isolation) is preserved under all three plausible implementations:

(a) Genuine data-plane isolation — AgentCore actively scopes visibility by userId.
(b) Privacy-preserving uniform-error response — the same error class is returned regardless of resource existence, to avoid information leak.
(c) Per-user ID namespacing — instrument IDs are interpreted relative to the requesting userId.

A future round should add a positive-control GET-as-owner test (same ID returns 200 in the legitimate context) to disambiguate (a) from (b) or (c). The verdict (isolation holds) is independent of the mechanism.

**Artifact:** `reports/round_23/acp-006-cross-agent-isolation.json`

### O1 — Admission-control aggregation gap

**Tests:** ACP-001 (parallel sessions) + ACP-008 (multi-instrument)
**Verdict:** Observation — narrow architectural property; not a security bypass on the evidence collected this round
**Scope:** Admission-time only — spend-time enforcement not measured this round (gated by D1)

#### What was measured
Under the documented setup chain (PaymentManager + CredentialProvider + Connector + IAM):

```python
# Five parallel sessions under same (userId, agentName), each with $0.50 cap
for i in range(5):
    dp.create_payment_session(
        userId="example-user",
        agentName="example-agent",
        paymentManagerArn="arn:aws:bedrock-agentcore:us-east-1:...payment-manager/xxx",
        limits={"maxSpendAmount": {"value": "0.50", "currency": "USD"}},
        expiryTimeInMinutes=15,
        clientToken=...,
    )
# All 5 admitted. Cumulative admission-authorized = $2.50.
```

The same pattern holds for `create_payment_instrument`: 3 instruments admitted under the same `(userId, agentName)`. Sessions are not bound to instruments at `CreatePaymentSession` time (no `paymentInstrumentId` parameter on that API), so N instruments and M sessions are independent counts rather than paired pairs.

- 5/5 parallel sessions admitted, $0.50 each, cumulative admission-authorized $2.50.
- 3/3 instruments admitted under same `(userId, agentName)`.
- Documented per-session ceiling = $10,000 (from a boundary validation error).
- Theoretical N-session ceiling at admission = bounded only by AWS rate limits on `CreatePaymentSession`.

#### What this observation does and does not establish

This characterizes **admission-time** behavior: AgentCore's session and instrument creation paths do not apply a principal-bound aggregation. Whether this matters depends on whether settlement-time `ProcessPayment` calls aggregate across sessions in a way the admission gate does not. **This round did not test settlement-time behavior** — D1 blocked the path. Until a follow-up round runs with delegated signing enabled, this is an admission-time observation, not a confirmed security bypass.

#### Recommendation
Operators implementing principal-bound spend governance under enterprise compliance frameworks (e.g., EU AI Act high-risk obligations) should layer application-level cumulative spend tracking keyed by `(userId, agentName)`. AWS preview documentation could surface that admission-time caps are session-scoped rather than principal-scoped.

**Artifacts:** `reports/round_23/acp-001-spend-fragmentation.json`, `reports/round_23/acp-008-policy-bypass-chain.json`

### O2 — Bazaar registry shape (two distinct signals)

**Test:** ACP-007 (passive inventory of CDP x402 Bazaar)
**Verdict:** Observation — passive inventory characterization

The CDP x402 Bazaar discovery endpoint (`api.cdp.coinbase.com/platform/v2/x402/discovery/resources`) is publicly indexed. A paginated fetch retrieved 50,560 listings across 761 unique hostnames. Two distinct properties of the registry shape surfaced and are reported separately to avoid conflation.

#### O2a — Near-duplicate hostname clusters

- 10 hostname clusters detected by Levenshtein-distance ≤ 2 (union-find clustering)
- Largest cluster: 8 hosts
- Total hosts in clusters: 28 (3.7% of 761 unique hostnames)
- Non-ASCII (homoglyph) hostnames: 0

**Interpretation:** Near-duplicate hostnames are present in the registry. Levenshtein ≤ 2 is a near-duplicate signal, not by itself a typosquat confirmation — manual validation of representative cluster members would be required to characterize the clusters as deliberate typosquatting vs. legitimate organizational variants (e.g., subdomains, region codes, version suffixes). This round did not perform that manual validation. The published claim is: the registry contains 10 near-duplicate hostname clusters; some may be typosquats and warrant follow-up review by the marketplace operator.

#### O2b — Marketplace concentration (separate signal)

- Top single hostname accounts for **71.9% of all 50,560 listings**

**Interpretation:** A marketplace-diversity signal that is distinct from the near-duplicate signal in O2a. One operator dominates the registry. This is a separate supply-chain consideration — the failure mode of a concentrated registry (single-operator dependency) differs from the failure mode of a near-duplicate-permeable registry (impersonation risk).

#### Publication discipline
Aggregate counts and percentages only. No individual hostnames are named in this finding or the underlying result JSON. A reviewer can reproduce both signals from the public endpoint at any time.

**Artifact:** `reports/round_23/acp-007-bazaar-typosquat.json`

### D1 — Coinbase CDP delegated-signing prerequisite (operational discovery)

**Context:** Discovered during audit-correction probing on 2026-05-26 (not one of the 8 stubs)
**Category:** Documentation gap; not a security finding

After completing the full documented setup chain — IAM user, IAM role, AgentCore PaymentManager, CoinbaseCDP CredentialProvider, PaymentConnector, CDP Server Wallet, env-var safety guards, valid x402 payload with `extra.name` and `extra.version` set to known USDC Base Sepolia values — the first `ProcessPayment` call returns:

```
AccessDeniedException: An error occurred (AccessDeniedException) when calling the ProcessPayment operation:
  Delegated signing is not enabled for your Coinbase project.
  Please enable delegated signing in your Coinbase project policies.
```

This is a CDP-project-level policy toggle, configured in the Coinbase Developer Platform portal, separate from any AWS IAM or AgentCore configuration step.

**Operational implication:** Operators following the AWS Bedrock AgentCore Payments launch documentation path may not surface this prerequisite until they attempt their first settlement-time `ProcessPayment` call. The error message itself is clear and actionable, but the gate is not flagged in the AWS-side setup guidance reviewed during this evaluation. Surfacing it earlier (in a "before you begin" section) would reduce time-to-first-settlement for new operators.

**Why this matters for the published findings:** D1 blocked the settlement-time variants of O1 (cap aggregation at spend time), of C1 (cap-vs-amount semantic validation), and the original receipt-validation / idempotency tests. All four are deferred to a follow-up round (VS-R02 candidate) with delegated signing enabled.

---

## Limitations and unknowns

1. **Settlement-layer behavior was not measured.** All `ProcessPayment` calls in this round were blocked either at structural validation gates or at the `Delegated signing is not enabled` AccessDeniedException (D1). Cap-aggregation at spend time (O1), cap-vs-amount validation (C1), payment-state idempotency, and replay protection are all deferred to a follow-up round.
2. **Server-side audit pipelines were not probed.** A separate test (ACP-005) confirmed no user-controllable intent metadata exists on the three Payment-API input schemas. CloudWatch traces, AWS X-Ray, and any internal AgentCore audit pipeline were NOT examined — they may capture intent independently.
3. **`ResourceNotFoundException` ambiguity** in C2 (cross-context isolation) was not disambiguated by a positive-control test. The security property holds under all three plausible implementations but the exact mechanism is not characterized.
4. **Bazaar listings are a snapshot** (2026-05-26 evening UTC). The 71.9% concentration and 10 near-duplicate clusters reflect that moment; the registry is actively indexed and these counts may shift.
5. **Near-duplicate clusters were not manually validated as typosquats.** O2a reports a near-duplicate signal; deliberate-typosquatting attribution requires hostname-by-hostname review of representative cluster members, deferred to a follow-up round.
6. **Anthropic MCP Tunnels / Self-Hosted Sandboxes** were not exercised (research-preview access not yet requested; 7 scaffolded test stubs are skip-decorated for future execution).

---

## Maturity assessment

**Narrow but reproducible; settlement-layer untested.**

Evidence collected this round: E1 and E2 only.

| Class | Coverage this round |
|---|---|
| E1 | Bazaar registry inventory (O2); operational prerequisite (D1) |
| E2 | Input validation (C1); cross-context isolation (C2, with E5 deferred); admission-control aggregation (O1) |
| E3 | Not collected (gated by D1) |
| E4 | Not collected (gated by D1) |
| E5 | Not collected (positive-control variants deferred to follow-up round) |

The observations and validation results above are reproducible from the linked branch state by any reviewer with their own AWS Bedrock preview + Coinbase CDP testnet enrollment.

The evidence base does NOT yet include settlement-time behavior on any axis. Any characterization beyond admission-time admits / refusals would require a follow-up round with delegated signing enabled (see Recommendation 1 below).

---

## Recommendations

### Immediate (this package)
- Coordinated disclosure of D1 (operational prerequisite documentation gap) and O1 (admission-time architectural characteristic) to AWS Bedrock security through the standard preview-feedback channel. Both are characterized as architectural and documentation observations rather than security vulnerabilities; no embargo timer applies. The disclosure sequence establishes reproducibility, calibration discipline, and good-faith vendor coordination.

### Next round (VS-R02 scope)
1. **Enable Coinbase delegated signing** in the CDP project policies. Re-run the settlement-time variants of O1 (cap aggregation), C1 (cap-vs-amount validation), and the original receipt-validation tests against actual `ProcessPayment` settlements on Base Sepolia testnet.
2. **Add positive-control variants** — GET-as-owner for C2 (disambiguate isolation mechanism), and a fully-valid over-cap payload for C1 (probe the validation layer that lives past `extra.name`).
3. **Manually validate** a representative sample of the 10 near-duplicate hostname clusters in O2a to characterize them as typosquatting vs. legitimate organizational variants.
4. **Request Anthropic MCP Tunnels research-preview access**, implement the 7 scaffolded Surface 1 stubs.

### Publication path
- This package is appropriate for **coordinated disclosure** (AWS Bedrock security; arxiv reviewer as a methodology / characterization paper; NIST CAISI artifact submission).
- Public characterization should remain bounded to admission-time observations (E1, E2) until settlement-time evidence (E3, E4) exists. A broader public characterization should wait for VS-R02 settlement-time evidence to either confirm or refute settlement-layer aggregation.

---

## Audit trail

The audit-and-correct cycle is part of the artifact integrity, not a footnote.

1. **2026-05-25 → 2026-05-26 early morning:** 8 ACP stubs implemented and run initially. Five commits to `vs-r01/skeleton` branch.
2. **2026-05-26 morning:** Maintainer requested independent code review before any external citation. Internal audit-agent invoked with explicit skeptical mandate.
3. **2026-05-26 mid-day:** Audit report produced; 4 BLOCK + 1 FIX + 3 NOTE issues identified across the 8 stubs.
4. **2026-05-26 afternoon:** All BLOCK + FIX corrections applied. All 8 tests re-run with corrected logic. Cleanup verified (0 leftover resources). Commit `88ecff7` pushed.
5. **2026-05-26 evening:** This Independent Review Package + the internal Critical Evaluation written from the post-audit state.

Audit corrections changed:
- Two tests with inverted PASS criteria reframed as characterizations
- Two tests with overclaim scope narrowed to admission-time observations
- One test result's `severity` field reconciled with its `estimated_severity` field
- One test's PASS verdict supplemented with an ambiguity note about its evidence mechanism
- One inventory test split into two semantically distinct findings (near-duplicate vs concentration)
- One test's cleanup order corrected (sessions before instruments)
- One test's "instrument-chain laundering" framing dropped — sessions are not bound to instruments at create time

The audit report is preserved at `~/vault/projects/vs-r01-acp-audit-2026-05-26.md` in the author's working repo and is available on request.

---

## Appendix A — Surface 3 (Salesforce Agent Scanners) comparative claim-matrix

A separate document (`docs/comparative_scanner_coverage_2026-05.md` on the same branch) records what each public agent-security scanner CLAIMS to detect across 34 detection categories. The author works at Salesforce; per the harness's brand-equity-while-employed posture, no employment-credentialed access was used. The matrix derives entirely from publicly-available vendor documentation as of 2026-05-24. It is included in the repo for completeness but is NOT part of the substantive evaluation that this package documents. Reviewers focused on the AgentCore Payments / x402 Bazaar evidence base can disregard Appendix A.

---

## References

1. AWS Bedrock AgentCore Payments preview: https://aws.amazon.com/blogs/industries/x402-and-agentic-commerce-redefining-autonomous-payments-in-financial-services/
2. CDP x402 Bazaar discovery layer: https://docs.cdp.coinbase.com/x402/bazaar
3. NIST AI 800-2 IPD: [DOI 10.6028/NIST.AI.800-2.ipd](https://doi.org/10.6028/NIST.AI.800-2.ipd)
4. agent-security-harness v4.4.2: https://pypi.org/project/agent-security-harness/4.4.2/
5. Repository (VS-R01 branch): https://github.com/msaleme/red-team-blue-team-agent-fabric/tree/vs-r01/skeleton
6. Author ORCID: https://orcid.org/0009-0003-6736-1900
7. Related publication: "The EU AI Act Was Written for Models. Your Agents Need Runtime Compliance." (dev.to, 2026-05-26) — runtime-compliance framing that contextualizes these characterizations.

---

## Suggested citation

Saleme, M. K. (2026). *VS-R01 Vendor Surface Evaluation: AWS Bedrock AgentCore Payments (Preview) — admission-time spend-governance characterization, input-validation positive controls, cross-context isolation, and Bazaar registry shape*. agent-security-harness v4.4.2, branch `vs-r01/skeleton` commit `88ecff7`. https://github.com/msaleme/red-team-blue-team-agent-fabric/tree/vs-r01/skeleton

---

*This package is review-ready for coordinated disclosure. Observations are scoped to admission-time behavior (E2), input validation (E2), cross-context visibility (E2 with E5 deferred), and public registry shape (E1). Settlement-time enforcement (E3, E4) is deferred to a follow-up round contingent on Coinbase CDP delegated signing being enabled. All test code, result JSONs, audit report, and corrections are available in the linked repository branch.*

*This evaluation program emphasizes disclosure-and-calibration discipline: narrow claims tied to specific evidence classes, audit cycles before publication, explicit downgrades of findings after skeptical review, and preserved audit lineage. Adversarial coverage is the input; calibrated evidentiary boundaries are the output.*
