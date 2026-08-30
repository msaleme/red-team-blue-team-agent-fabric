# Roadmap

> This is an independent, open-source research project on agent-security verification.
> It is not a commercial product and has no sales motion. Direction below is research-
> and standards-oriented; views are the maintainer's own.

## Strategic Context

**The goal is not to be the most feature-complete agent-security tool. It is to be the independent verification layer the agent-governance ecosystem can cite — the place that produces reproducible evidence that security and governance claims hold under adversarial pressure.**

Tools get replaced. Reproducible evidence and shared methodology compound. The 2026 standards/compliance window (AIUC-1, EU AI Act, NIST AI agent work) is the forcing function, but the endgame is contributing methodology and evidence the community references — not shipping features faster than anyone else.

Agent governance is breaking into visible layers:
- **WHO** — identity and access
- **HOW** — runtime behavior and policy enforcement
- **WHY** — constitutional logic and higher-order governance
- **VERIFICATION** — independent evidence that those claims hold under real and adversarial conditions

This harness is positioned around that fourth layer while pressure-testing the others.

## Positioning

The open lane is **independent behavioral assurance**. Identity/authorization tools answer *who* an agent is and *what* it can access. Governance toolkits shape *how* it behaves. Constitutional work addresses *why* it should act. This project exists to verify whether those claims still hold under adversarial pressure — across MCP, A2A, and emerging payment protocols — and to produce evidence that CI pipelines, security teams, and auditors can use directly.

What makes the position durable is **not** breadth of coverage or test count. It is three research-grade assets that are hard to replicate:

- **A documented research foundation** (seven DOI-citable open-access records, ORCID, public methodology) — prior art that cannot be retro-claimed. These records carry *internal* citation lineage; a 2026-08-02 OpenAlex audit found **zero qualifying independent citations**, and nothing in this project may be presented as third-party scholarly validation.
- **Reproducible adversarial evidence** with explicit evidence classes and confidence intervals — the kind of artifact vendors cannot produce about their own products, and that ad-hoc claims cannot match. Note the word *reproducible*, not *independent*: adjudication here is author-performed. One external party has reproduced one pinned artifact (the RCL oracle fixtures). Independent review of the harness as a whole remains the standing gap, and closing it is a goal rather than a claim.
- **Payment-protocol security testing (x402/L402)** — an under-covered surface where the verification layer above the (now Linux-Foundation-standard) rail is largely vacant.

Coverage breadth and test count are not the moat and are not tracked as goals. The artifact is the **evidence**, not the number of tests.

## Direction

The current priority is producing **settlement-time, reproducible payment-security evidence** (the VS-R02 evaluation line) and contributing it where the standards community works — rather than expanding coverage for its own sake. Concretely: depth and reproducibility on the payment-security surface, then methodology/evidence contributions to legitimate standards venues (OWASP Agentic Security Initiative, NIST, CSA).

### Release history

Dates and themes below are reconciled against `CHANGELOG.md`, which is authoritative.

| Release | Date | Theme | Status |
|---------|------|-------|--------|
| **v3.9 — Adopt in 15 Minutes** | 2026-04-06 | CI integration, developer experience, `--json`, scope docs, GitHub Action | Shipped |
| **v3.10 — Evidence for Auditors** | 2026-04-08 | Evidence-pack format, payment-test depth, behavioral profiling, HTML reports, 2 independent audits | Shipped |
| **v4.1 — Compliance Evidence** | 2026-04-10 | EU AI Act + ISO 42001 crosswalks, AUROC, FRIA, kill-switch, watermark tests | Shipped |
| **v4.2 — Incident-Tested** | 2026-04-12 | Modules mapped to named 2026 security incidents | Shipped |
| **v4.3 — Supply Chain + Corpus** | 2026-04-15 | Skill Security Protocol harness, Decision Behavior Benchmark corpus | Shipped |
| **v4.4 — Accuracy + Infrastructure** | 2026-04-17 | Accuracy sweep, dynamic test counting, supply-chain framework-layer checks (MCP-F) | Shipped |
| **v4.4.2 — Docs Hardening** | 2026-05-24 | Documentation hardening and citation discipline | Shipped |
| **v4.5 — Governance Surfaces** | 2026-06-09 | Skill-security and governance-modification harnesses | Shipped |
| **v4.6–v4.7 — Payment Authority** | 2026-07-01 | AP2 mandate chain, receipt-claim (RCL) verification | Shipped |
| **v4.8 — Merchant Journey** | 2026-07-02 | UCP/ACP merchant journey, card-network agentic tokens | Shipped |
| **v4.9 — Settlement Depth** | 2026-07-05 | Denial-of-settlement finality, Fireblocks x402 hardening | Shipped |
| **v4.10 — Benchmark Integrity** | 2026-07-25 | Benchmark-integrity harness; corpus defensibility | Shipped |
| **v4.11–v4.12 — Corpus Currency** | 2026-08-02 | Decision-governance corpus provenance repair, per-case currency tracking, re-adjudication | Shipped |
| **v4.13.0 — OWASP Agentic v1.1** | 2026-08-02 | T1–T17 commit-pinned coverage mapping, selector tooling, HITL harness (T10/T15) | Shipped |
| **v4.13.1 — HITL correctness** | 2026-08-02 | All 8 HITL tests could record a verdict against a target that never serviced the request; `_serviced()` guard added | Shipped |
| **v4.14.0 — Endpoint provenance** | 2026-08-05 | Removed fabricated default registry/telemetry endpoints pointing at domains this project never owned; both env vars now required; attestation independence claim corrected to "tested with" | Shipped |
| **v4.16.0 — Three target shapes** | 2026-08-30 | A verdict must be able to be wrong AND to be right. Two sweeps join the closed-port one: a permissive sentinel that grants everything and a refusing one that denies everything. Ten modules could not pass a target that refused every request. No test added or removed, count 608 | Shipped |
| **v4.15.0 — Unserviced requests are not passes** | 2026-08-07 | Seven modules recorded a `PASS` when the target never serviced the request; guard promoted to `http_helpers` and applied at each recording path. No test added or removed, count unchanged at 603 | Shipped |
| **Next — Standards & Evidence** | — | Reproducible settlement-time payment evidence; methodology paper; schema as a standards-body informational draft | In progress |

**Known gaps, stated rather than deferred.** T16-S1 (consent-flow manipulation) and T10-S1/T10-S3
(artificial time pressure, trust-mechanism subversion) have no mapped tests. One of the 22 OWASP
mitigation controls is guidance-only. Adjudication across the coverage report and the decision-governance
benchmark is author-performed. These are tracked in
[`docs/coverage/owasp-agentic-v1.1.yaml`](docs/coverage/owasp-agentic-v1.1.yaml) rather than in prose.

## Standards & evidence direction

The next phase is about contributing reproducible methodology and evidence the community can reference — not feature velocity.

### Reproducible adversarial evidence (the thing others can cite)

Independent evaluations with explicit evidence classes (observation → admission-time → settlement-time → replay → isolation) and reproducible, branch-pinned artifacts. Designed so other researchers can re-run them and so the methodology — not just the result — is the contribution. The payment-protocol settlement evaluation (VS-R02) is the current focus.

### A methodology paper (the thing others reference)

A public write-up of the evidence-class methodology and the decision-behavior benchmark, framed so other researchers cite the approach and analysts can use it to reason about behavioral assurance.

- Decision Behavior Benchmark corpus
- Benchmark / methodology paper

### An evidence schema in a standards venue (the thing others adopt)

Submit the attestation/evidence schema to a legitimate standards body (e.g. IETF/OASIS informational draft, OWASP ASI) so the format is shared rather than tool-specific. A schema only one tool uses is a feature; a schema the community adopts is shared infrastructure.

### Research frontier (feeds future publications)

Intent-contract validation, multi-agent interaction security, and memory & continuity security have
**shipped as modules** (`intent-contract` 8 tests, `multi-agent` 18, `memory` 10) and are no longer
frontier items. Having tests is not the same as having a result worth publishing; the open research
work on each is:

- **Intent contracts** — whether a declared intent can be shown to bind execution, rather than merely accompany it.
- **Multi-agent interaction** — composition effects: risk that accumulates across a sequence where no single step violates a rule.
- **Memory & continuity** — cross-session integrity, where the attack is patient rather than loud.

The genuine frontier is the **human-oversight surface**. The T10/T15 harness measures whether an
adversary can create the precondition for reviewer failure; it does not measure reviewer degradation,
because that needs a human subject this project does not have. Closing that gap requires a study
design, not more tests.

## What NOT to do

| Don't | Why |
|-------|-----|
| Treat test count as the goal | Coverage breadth is not the moat. The artifact is reproducible evidence, not a bigger number. Padding the count is noise; infrastructure that unlocks new evidence is not. |
| Add enterprise-platform adapters as the main story | Cannot out-breadth larger vendors. Depth in protocols, evidence, and payments is more defensible. |
| Compete with scanners on speed/ease alone | Larger tools will always be faster for a quick scan. Be the thorough, reproducible verification option. |
| Build a dashboard before the evidence is the thing | The product is the evidence artifact first, not the UI. |
| Chase GitHub stars as the KPI | This is a research/standards project. Citations, reproductions, and standards adoption are the signal — not developer popularity. |
| Bind the work to unverified third-party "standards" | Contribute only to legitimate venues (OWASP ASI, NIST, CSA). Avoid lending credibility to manufactured-consensus efforts. |

## How to contribute

1. Pick a direction above that matches your interests.
2. Open or claim an issue and tag the matching area.
3. Submit PRs referencing the issue number.

Every change should improve the project's ability to produce reproducible evidence of how agents behave under adversarial pressure, and to share that methodology with the wider community.
