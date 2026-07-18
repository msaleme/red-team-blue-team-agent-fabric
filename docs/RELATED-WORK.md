# Related work

This harness performs executable adversarial testing at the implementation and evidence surface of agent protocols: it sends real adversarial payloads and negative vectors and checks whether an implementation makes the correct accept/reject decision. It is complementary to formal-conformance, capability-binding, and delegation-protocol research, not a substitute for it. This page cites the closest work and states, honestly, where this project overlaps and where it differs.

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

## Static MCP scanners (complementary layer)

Static description scanners (e.g. Invariant MCP-Scan, Cisco MCP Scanner) inspect tool descriptions and configuration. They are a complementary static layer; this harness adds active, wire-protocol adversarial testing and claim-level receipt verification. Use both.
