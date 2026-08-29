# Related work

This harness performs executable adversarial testing at the implementation and evidence surface of agent protocols: it sends real adversarial payloads and negative vectors and checks whether an implementation makes the correct accept/reject decision. It is complementary to formal-conformance, capability-binding, and delegation-protocol research, not a substitute for it. This page cites the closest work and states, honestly, where this project overlaps and where it differs.

## Where this sits

Four bodies of work below occupy adjacent layers. Reading them as a stack is more
useful than reading them as competitors, and it is the honest description:

```text
formal invariants          AgentThread / AgentRFC     prove and model protocol
                                                      invariants, localise which
                                                      party owns each control

platform benchmark         AIP-Bench / PCAT           measure named platform
                                                      implementations by
                                                      attack-success rate

endpoint execution         THIS HARNESS               assert protocol semantics
                                                      against an arbitrary target
                                                      and grade the retained
                                                      execution evidence

receipt conformance        Receipt Verifier           check that a verifier
                           Conformance Corpus v0      reproduces expected verdicts
                                                      over a portable corpus

evidence sufficiency       DEMM-Bench                 determine whether retained
                                                      records support the claims
                                                      made from them
```

This project owns one row. It does not compete on formalisation, it is not first
to deterministic agentic-commerce benchmarking, it does not hold the largest
receipt-verifier corpus, and its evidence-class taxonomy is not the only
evidence-sufficiency framework. What it does is send hostile traffic at a live
endpoint and refuse to convert an unanswered request, or an unexposed capability,
into a passing security result.

Added 2026-08-29. If a claim anywhere in this repository reads as owning more than
one row of that stack, it is wrong and should be corrected here first.

## This project's methodology note

The receipt claim-level module (RCL-001..011) is described in a short position-and-methodology note, **"Claim-Level Negative Testing for Agent-Governance Evidence"** (Saleme, 2026): a four-property decomposition of an action receipt (integrity/provenance; execution occurrence and outcome; authorization; check execution and integrity), and executable negative vectors that construct correctly signed but semantically unsupported receipts and show a claim-level verifier rejecting them. Concept DOI: [10.5281/zenodo.21418701](https://doi.org/10.5281/zenodo.21418701). It positions this harness as the executable complement to the formal-conformance and capability-binding work below.

## Formal conformance for agent protocols

- **AgentThread — "Formal Security Analysis of Agent Protocol Composition"** (Shenghan Zheng, Qifan Zhang, Zheng Zhang, Haonan Li, Christophe Hauser; arXiv:2606.28690, 2026), and its predecessor **AgentRFC / AgentConform** (Shenghan Zheng, Qifan Zhang; arXiv:2603.23801, 2026).

  AgentThread compiles protocol specifications into TLA+ models, model-checks them against security invariants, and replays counterexamples against production SDKs through hand-written protocol adapters. It contributes a layered security scope (including an L5 audit/accountability layer), a Responsibility IR that tracks who owns each control and whether the SDK enforces it, 80 implementation tests across five protocols, and composition-only failures.

  **Relationship.** AgentThread is the nearest work and is complementary. It formalizes protocol invariants and localizes responsibility. This harness works one boundary down, at the evidence artifact: it asks what an action *receipt* is entitled to prove. Its receipt-claim decomposition (integrity/provenance, occurrence, authorization, check execution/integrity) and its executable negative vectors — which construct schema-valid, correctly signed receipts whose claims are not semantically supported and show a claim-level verifier rejecting them — could serve as concrete oracle cases for adapter-level tests of audit/provenance continuity. This project does not compete on formalization or protocol coverage.

## Capability binding and delegation

- **Governing Dynamic Capabilities** (Ziling Zhou; arXiv:2603.14332, 2026) — capability integrity, behavioral verifiability, and interaction auditability, with cryptographic instantiations and replay-based verification. Covers much of the capability-binding and behavioral-verification ground; this project does not restate it and claims no priority over it.
- **AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and A2A** (Sunil Prakash; arXiv:2603.24775, 2026) — invocation-bound capability tokens with a 600-attempt adversarial evaluation. AIP is a delegation protocol to be conformance-tested; this harness's vectors are agnostic to the delegation scheme.

## Attack primitives this harness exercises

- **ShareLock: A Stealthy Multi-Tool Threshold Poisoning Attack Against MCP** (arXiv:2606.27027, 2026) — cryptographic secret-sharing of a payload across tool descriptions. MCP-019 implements a *split-payload composition* test **inspired by** ShareLock (readable-fragment reconstruction), not a reproduction of threshold sharing; see the test's docstring for the exact scope.
- **WebMCP Tool Surface Poisoning** (arXiv:2606.06387, 2026) — mid-session tool injection (MSTI) and the case for invocation-time identity checks. MCP-020 is a snapshot-differencing test for one observable class of unbound rebinding; it does not provide invocation-time revalidation.

## Deterministic benchmarks and conformance corpora (closest adjacent work)

Added 2026-08-29 after a prior-art sweep found three items this page should have carried
already. Two of them are closer to the RCL corpus than anything cited above.

- **Receipt Verifier Conformance Corpus v0** — [`luckyPipewrench/agent-egress-bench`](https://github.com/luckyPipewrench/agent-egress-bench),
  `receipts/v0/conformance/`, Apache-2.0.

  **The closest artifact-level prior art to this project's RCL corpus, and it is larger.**
  Its README describes "a vendor-neutral test corpus for receipt verifier implementations",
  where each fixture is a JSON receipt or JSONL chain paired with an `.expect.json` stating
  "the verdict any correct verifier MUST emit". Receipts are Ed25519-signed over
  `SHA-256(canonical-JSON(action_record))` and compose into a chain via `chain_prev_hash`.
  Case counts at 2026-08-29: 22 `golden`, 34 `malicious`, 24 `edge`.

  **Relationship.** The construction is the same shape as `fixtures/rcl/`: a portable corpus,
  expected verdicts declared separately from any implementation, and positive cases that stop a
  reject-everything verifier scoring well. Their `golden` set plays the role this project's
  acceptance controls (`RCL-008`, `RCL-009`) play. Where this project's corpus differs is
  narrower and should be stated as such: it decomposes the *claim* (integrity/provenance,
  occurrence, authorization, check execution/integrity) rather than verifying receipt and
  chain integrity, and it pins `evaluation_time` so freshness-window logic is exercised
  rather than aged out. **This project claims no priority here.** Anyone assessing the RCL
  corpus should read this one first.

- **AIP-Bench / PCAT — "Protocol-Level Attacks on Agentic Commerce Platforms: A Cross-Platform
  Taxonomy, AIP-Bench, and Unified Defense"** (Yedidel Louck, Ariel Cyber Innovation Center,
  Ariel University; [arXiv:2607.21824](https://arxiv.org/abs/2607.21824), 2026-07-23).

  33 findings across CoralOS v1.3.0, Fetch.ai uAgents, and Google AP2 v0.2.0, organised into
  five structural classes (RC-1 registry integrity, RC-2 payment-destination binding, RC-3
  observable credential channel, RC-4 payment TOCTOU, RC-5 authorization scope) plus one
  semantic class (RC-6, description poisoning). Artifacts are released:
  [`yedidel/aip-bench-public`](https://github.com/yedidel/aip-bench-public) carries the
  benchmark loader, scenario files, and a Dockerised PCAT proxy, with a Croissant-typed
  dataset on Hugging Face. Attack locations and PoCs are withheld until coordinated
  disclosure concludes on **2026-10-04**.

  **Relationship, stated plainly.** The paper describes AIP-Bench as "to our knowledge the
  first deterministic benchmark for agentic commerce security". This project does not contest
  that. The instruments measure different objects: AIP-Bench measures *platforms* by
  attack-success rate against three named implementations; this harness is a target-agnostic
  conformance suite asserting protocol semantics against an arbitrary endpoint. Their RC-1,
  RC-2, RC-4 and RC-5 classes have substantial coverage here (see the module docstrings);
  RC-3's URL-path credential case and the LLM-proxy model-override case did not, and are
  tracked as gaps.

- **DEMM-Bench: A Cross-Regime Benchmark for Agent-Runtime Governance-Evidence Sufficiency**
  (Oleg Solozobov; [arXiv:2606.20634](https://arxiv.org/abs/2606.20634), 2026-05-30).

  Grounded in a Decision Evidence Maturity Model, it evaluates whether records across eight
  evidence regimes are sufficient to reconstruct decision-level properties, applying eight
  deterministic degradation conditions across 64 test cases with construction-oracle labels.

  **Relationship.** This is the nearest work to this project's evidence-class taxonomy
  (`docs/EVIDENCE-CLASS-TAXONOMY.md`) rather than to its protocol tests. Both ask whether
  retained evidence is sufficient to support a claim. DEMM-Bench measures sufficiency across
  regimes; this project classifies an individual result by evidence class and independence
  level. Any claim of novelty for the E1-E5 / I0-I2 axes should be checked against it first.

## Static MCP scanners (complementary layer)

Static description scanners (e.g. Invariant MCP-Scan, Cisco MCP Scanner) inspect tool descriptions and configuration. They are a complementary static layer; this harness adds active, wire-protocol adversarial testing and claim-level receipt verification. Use both.
