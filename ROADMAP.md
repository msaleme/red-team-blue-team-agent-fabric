# Roadmap

## Strategic Context

**The goal is not to be the best agent security tool. It is to become the verification standard that regulated industries require.**

Tools get replaced. Standards compound. The 2026 compliance window (AIUC-1, EU AI Act, NIST AI Agent Standards) is the forcing function — but the endgame is standard-setting, not feature shipping.

### VRIO Assessment (April 2026)

| Advantage | Type | Window |
|-----------|------|--------|
| Research foundation (5 DOIs, NIST, CSG) | **Sustained** | Permanent — prior art cannot be replicated |
| Payment protocol security (x402/L402) | **Near-sustained** | 12-18 months before funded competitor enters |
| Evidence format adoption | **Potential sustained** | Depends on auditor/standards body acceptance |
| Wire-protocol adversarial testing | Temporary | 6-12 months before major vendors add this |
| Multi-protocol coverage | Temporary | 6-12 months |
| AIUC-1 mapping | Temporary | One release cycle after competitors notice |
| Test corpus depth (342 tests) | Temporary | Must maintain velocity lead |

The strategy sequences investment toward **sustained advantages** while defending temporary ones through speed.

### Category

**Decision Governance for Autonomous Agents.**

Identity and authorization controls answer *who* an agent is and *what* it can access. This harness tests *how* that agent behaves under adversarial pressure — across MCP, A2A, and emerging payment protocols — and produces evidence that CI pipelines, security teams, and auditors can use directly.

### Competitive Landscape (Porter's Five Forces)

| Force | Rating | Implication |
|-------|--------|-------------|
| New entrants | Medium-High | Knowledge barriers real but surmountable. 6-12 month window. |
| Buyer power | High | Early market, many options, low switching costs. Compliance buyers less flexible. |
| Supplier power | Medium | Protocol creators (Anthropic, Google) aligned for now. Risk: security built into protocol layer. |
| Substitutes | Medium-High | Platform-native security and GRC checkboxes threaten to make behavioral testing seem unnecessary. |
| Rivalry | Medium, intensifying | Snyk, Cisco, CrowdStrike all entering. Market growing fast enough for multiple winners — but only in behavioral assurance tier. |

**The existential risk is not a competitor. It is tier collapse** — if Snyk adds behavioral testing to their scanner, or if Anthropic builds security into MCP, the standalone behavioral assurance category narrows. The counter: become the verification layer that regulated industries require regardless of what platforms provide.

## Release Summary

| Release | Theme | Primary Outcomes | Target |
|---------|-------|------------------|--------|
| **v3.9 – Adopt in 15 Minutes** | CI integration and developer experience | `--json` output, error messages, scope docs, GitHub Action | **Shipped** (v3.9.0) |
| **v3.10 – Prove It to Auditors** | Evidence format adoption + payment depth + drift scoring | Evidence packs accepted by auditors, payment tests doubled, behavioral profiling | Before July 2026 |
| **v4.0 – Lock the Category** | Standard-setting: benchmark + schema standardization + registry | Named benchmark corpus, attestation schema to IETF/OASIS, longitudinal registry | H2 2026 |

## v3.9 – Adopt in 15 Minutes ✅ SHIPPED

Released as v3.9.0. All issues closed: #103, #90, #92, #108, #109.

## v3.10 – Prove It to Auditors

**Goal:** A compliance lead can produce evidence that an auditor actually accepts — before the EU AI Act high-risk deadline (August 2, 2026).

This is the release where the project transitions from a testing harness to a **verification standard**.

### Priority Stack (VRIO-informed)

**P0 — Evidence format adoption (the moat-building move)**
Make the evidence pack format the thing auditors accept and GRC platforms import. One auditor using this output in a real engagement is worth more than any feature.

- [#118](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/118) – Audit-ready evidence generation ✅ SHIPPED (v1)
- NEW – Evidence pack format documentation for auditors and GRC platform integration
- NEW – Engage Schellman or equivalent to review evidence format for AIUC-1 audits

**P1 — Payment protocol depth (the blue ocean)**
Double the payment test corpus. Publish the attack taxonomy. Become synonymous with agent payment security before anyone else shows up.

- NEW – Expand x402 test suite (25 → 50+ tests)
- NEW – Expand L402 test suite (14 → 30+ tests)
- NEW – Publish Agent Payment Security Attack Taxonomy (standalone reference doc)
- [#51](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/51) – OATR test fixtures for x402 identity verification

**P1 — Behavioral profiling and drift scoring (the "what scanners miss" story)**
Without this, buyers can't see the difference between your output and a static scan. Drift scoring over time is what no scanner can replicate.

- [#111](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/111) – Behavioral profiling & risk scoring
- NEW – Longitudinal drift comparison (run N, run N+1, show what changed)

**P2 — Protocol coverage and compliance (defend temporary advantages)**

- [#115](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/115) – AIUC-1 compliance test suite ✅ SHIPPED (formalized)
- [#91](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/91) – MCP-014: Tool description injection test
- [#93](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/93) – A2A-009: Agent card limitations field verification

**P3 — Reporting (ship if time allows, don't block P0-P2)**

- [#112](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/112) – HTML reporting dashboard
- [#113](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/113) – Top 10 failure summary

### What moved

| Item | From | To | Why |
|------|------|----|-----|
| Payment test expansion | Not planned | **v3.10 P1** | VRIO: near-sustained advantage with 12-18 month window. Must invest now. |
| Payment attack taxonomy | Not planned | **v3.10 P1** | Publishable reference that establishes authority. |
| #51 OATR fixtures | v4.0 | **v3.10 P1** | Directly supports payment depth strategy. |
| #112 HTML dashboard | v3.10 P2 | **v3.10 P3** | Nice to have but doesn't build moat. |
| #113 Top 10 summary | v3.10 P2 | **v3.10 P3** | Same — defer if it blocks payment or profiling work. |

## v4.0 – Lock the Category

**Goal:** Become the standard others reference — not just a tool others use.

v4.0 is reframed around **standard-setting**, not features. The three moves that convert temporary advantages into sustained ones:

### Move 1: Publish the benchmark (the thing others cite)

A named decision-governance benchmark corpus — the MCPTox analog for behavioral assurance. Publish as a paper before shipping the code. Designed so other researchers cite it, other vendors measure against it, and analysts use it to define the category.

- [#120](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/120) – Decision Behavior Benchmark corpus
- NEW – Benchmark methodology paper (target: 2 more DOIs by end 2026)

### Move 2: Standardize the evidence format (the thing others adopt)

Submit the attestation schema to IETF or OASIS as an informational draft. A schema only one tool uses is a feature. A schema others adopt is a moat.

- NEW – Submit attestation schema to standards body (IETF/OASIS/OWASP)
- NEW – GRC platform integration (ServiceNow, OneTrust import of evidence packs)

### Move 3: Build the longitudinal registry (the thing others can't reproduce)

The attestation registry with cross-org comparative evidence over time. A registry with 6 months of data is an asset no new entrant can replicate on day one.

- NEW – Registry API for cross-org evidence submission
- NEW ��� Drift comparison across deployments (aggregate, anonymized)

### Research frontier (feeds the next publications)

- [#116](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/116) – Intent contract validation tests
- [#117](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/117) – Multi-agent interaction security tests
- [#119](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/119) – Memory & continuity security tests

## What NOT to Do

| Don't | Why |
|-------|-----|
| Add more enterprise platform adapters | Can't out-breadth Snyk/CrowdStrike. Depth in protocols and payments is more defensible than breadth across platforms. |
| Compete with scanners on speed/ease | Snyk and Cisco will always be faster for a quick scan. Be the "thorough" option they can't replace. |
| Build a SaaS dashboard before having paying customers | The product is the evidence artifact, not a dashboard. |
| Chase GitHub stars | Enterprise security tools win on auditor trust, not developer popularity. |

## Sequencing

```
v3.9  ✅ SHIPPED        → "Find dangerous stuff in 15 minutes"
v3.10 (before July)     → "The evidence auditors accept"     ← moat-building release
v4.0  (H2 2026)         → "The standard others reference"    ← category lock
v4.x  (2027)            → Network effects from registry + standard citations
```

## Sustained Advantage Trajectory

```
Now:     Research (5 DOIs)           ← only sustained advantage
v3.10:   + Evidence format adoption  ← if auditors accept it
         + Payment protocol depth    ← if we stay 12mo ahead
v4.0:    + Benchmark others cite     ← if published as paper
         + Schema in standards body  ← if adopted beyond this tool
v4.x:    + Registry network effect   ← if cross-org data compounds
```

Each step converts a temporary advantage into a sustained one. Miss any step and the corresponding moat doesn't form.

---

> **Disclosure:** This roadmap incorporates VRIO analysis and Porter's Five Forces assessment (Claude Code, April 2026). All strategic decisions are the maintainer's own. Competitive assessments based on publicly available information.

This document is updated whenever milestones shift. Contributions aligned with these themes are especially welcome — open an issue or PR and tag the matching milestone.
