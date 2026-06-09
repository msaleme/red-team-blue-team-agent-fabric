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

- **A documented research foundation** (peer-cross-citing DOIs, ORCID, public methodology) — prior art that cannot be retro-claimed.
- **Independent, reproducible adversarial evidence** with explicit evidence classes and confidence intervals — the kind of artifact vendors cannot produce about their own products, and that ad-hoc claims cannot match.
- **Payment-protocol security testing (x402/L402)** — an under-covered surface where the verification layer above the (now Linux-Foundation-standard) rail is largely vacant.

Coverage breadth and test count are not the moat and are not tracked as goals. The artifact is the **evidence**, not the number of tests.

## Direction

The current priority is producing **settlement-time, reproducible payment-security evidence** (the VS-R02 evaluation line) and contributing it where the standards community works — rather than expanding coverage for its own sake. Concretely: depth and reproducibility on the payment-security surface, then methodology/evidence contributions to legitimate standards venues (OWASP Agentic Security Initiative, NIST, CSA).

### Release history

| Release | Theme | Status |
|---------|-------|--------|
| **v3.9 — Adopt in 15 Minutes** | CI integration, developer experience, `--json`, scope docs, GitHub Action | Shipped |
| **v3.10 — Evidence for Auditors** | Evidence-pack format, payment-test depth, behavioral profiling, HTML reports, 2 independent audits | Shipped |
| **v4.1 — Compliance Evidence** | EU AI Act + ISO 42001 crosswalks, AUROC, FRIA, kill-switch, watermark tests | Shipped |
| **v4.2 — Incident-Tested** | Modules mapped to named 2026 security incidents | Shipped |
| **v4.3 — Supply Chain + Corpus** | Skill Security Protocol harness, Decision Behavior Benchmark corpus | Shipped |
| **v4.4 — Accuracy + Infrastructure** | Accuracy sweep, dynamic test counting, supply-chain framework-layer checks (MCP-F) | Shipped |
| **Next — Standards & Evidence** | Reproducible settlement-time payment evidence; methodology paper; schema as a standards-body informational draft | In progress |

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

- Intent-contract validation
- Multi-agent interaction security
- Memory & continuity security

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
