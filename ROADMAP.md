# Roadmap

## Strategic Context

**The goal is not to be the best agent security tool. It is to become the verification standard that regulated industries require.**

Tools get replaced. Standards compound. The 2026 compliance window (AIUC-1, EU AI Act, NIST AI Agent Standards) is the forcing function, but the endgame is standard-setting, not feature shipping.

Agent governance is breaking into visible layers:
- **WHO** = identity and access
- **HOW** = runtime behavior and policy enforcement
- **WHY** = constitutional logic and higher-order governance
- **VERIFICATION** = independent evidence that those claims hold under real and adversarial conditions

Our harness is positioned around that fourth layer while pressure-testing the others.

### VRIO Assessment (April 2026)

| Advantage | Type | Window |
|-----------|------|--------|
| Research foundation (5 DOIs, NIST, CSG) | **Sustained** | Permanent - prior art cannot be replicated |
| Payment protocol security (x402/L402) | **Near-sustained** | 12-18 months before funded competitor enters |
| Evidence format adoption | **Potential sustained** | Depends on auditor/standards body acceptance |
| Wire-protocol adversarial testing | Temporary | 6-12 months before major vendors add this |
| Multi-protocol coverage | Temporary | 6-12 months |
| AIUC-1 mapping | Temporary | One release cycle after competitors notice |
| Test corpus depth (466 tests) | Temporary | Must maintain velocity lead |

The strategy sequences investment toward **sustained advantages** while defending temporary ones through speed.

### Category

**Decision Governance for Autonomous Agents.**

Identity and authorization controls answer *who* an agent is and *what* it can access. Governance toolkits increasingly shape *how* it behaves. Constitutional work starts to address *why* it should act. This harness exists to verify whether those claims still hold under adversarial pressure, across MCP, A2A, and emerging payment protocols, and to produce evidence that CI pipelines, security teams, and auditors can use directly.

### Competitive Landscape (Porter's Five Forces)

| Force | Rating | Implication |
|-------|--------|-------------|
| New entrants | Medium-High | Knowledge barriers real but surmountable. 6-12 month window. |
| Buyer power | High | Early market, many options, low switching costs. Compliance buyers less flexible. |
| Supplier power | Medium | Protocol creators aligned for now. Risk: security built into protocol layer. |
| Substitutes | Medium-High | Platform-native security and GRC checkboxes threaten to make behavioral testing seem unnecessary. |
| Rivalry | Medium, intensifying | Snyk, Cisco, CrowdStrike, Microsoft and others are entering. Market growing fast enough for multiple winners, but not if we stay feature-framed. |

**The existential risk is not just a competitor. It is tier collapse** - if platform vendors make behavioral governance look "good enough," the standalone category narrows. The counter is to become the verification layer that regulated industries require regardless of what platforms provide.

## Buyer Motions

| Release | Theme | Primary Outcomes | Target |
|---------|-------|------------------|--------|
| **v3.9 - Adopt in 15 Minutes** | CI integration and developer experience | `--json` output, error messages, scope docs, GitHub Action | **Shipped** (v3.9.0) |
| **v3.10 - Prove It to Auditors** | Evidence format adoption + payment depth + drift scoring | Evidence packs, payment tests doubled, behavioral profiling, HTML dashboards, 2 independent security audits | **Shipped** (v3.10.0) |
| **v4.1 - Compliance Evidence** | EU AI Act + ISO 42001 mapping, AUROC, FRIA, kill-switch, watermark tests | 466 tests, 32 modules, compliance report generator, 31 framework controls mapped | **Shipped** (v4.1.0) |
| **v4.2 - Incident-Tested** | Tests mapped to named April 2026 security incidents | 466 tests, 32 modules | **Shipped** (v4.2.0) |
| **v4.2 - Incident-Tested** | Tests mapped to named April 2026 security incidents | NEXT — 22 new tests mapped to OX Security MCP disclosure, UC Berkeley benchmark hacking, PraisonAI CVEs, lightningzero governance finding, OpenClaw April CVEs. 3 new modules (benchmark integrity, governance modification, PraisonAI adapter). Shared `_utils.py`. |
| **v5.0 - Lock the Category** | Standard-setting: benchmark + schema standardization + registry | H2 2026 — Benchmark corpus (#120), methodology paper (#138), IETF attestation schema (#137), longitudinal registry API, drift comparison. |

## v3.9 - Adopt in 15 Minutes ✅ SHIPPED

Released as v3.9.0. All issues closed: #103, #90, #92, #108, #109.

## v3.10 - Prove It to Auditors ✅ SHIPPED

Released as v3.10.0. Shipped ahead of the EU AI Act high-risk deadline (August 2, 2026).

**Goal:** A compliance lead can produce evidence that an auditor actually accepts.

This is the release where the project transitions from a testing harness to a **verification standard**.

### Priority Stack (VRIO-informed)

**P0 - Evidence format adoption (the moat-building move)**
Make the evidence pack format the thing auditors accept and GRC platforms import. One auditor using this output in a real engagement is worth more than any feature.

- [#118](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/118) - Audit-ready evidence generation
- Evidence pack format documentation for auditors and GRC platform integration
- Auditor review loop for evidence format usefulness and reuse

**P1 - Payment protocol depth (the blue ocean)**
Double the payment test corpus. Publish the attack taxonomy. Become synonymous with agent payment security before anyone else shows up.

- [#136](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/136) - Publish Agent Payment Security Attack Taxonomy
- [#135](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/135) - Expand L402 test suite (14 -> 30+ tests)
- expand x402 depth further from the current base
- [#51](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/51) - OATR test fixtures for x402 identity verification

**P1 - Behavioral profiling and drift scoring (the "what scanners miss" story)**
Without this, buyers cannot see the difference between your output and a static scan. Drift scoring over time is what no scanner can easily replicate.

- [#111](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/111) - Behavioral profiling & risk scoring
- longitudinal drift comparison between runs and target configurations

**P2 - Protocol coverage and compliance (defend temporary advantages)**

- [#115](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/115) - AIUC-1 compliance test suite
- [#91](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/91) - MCP-014: Tool description injection test
- [#93](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/93) - A2A-009: Agent card limitations field verification
- [#144](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/144) - CrewAI CVE reproduction tests

**P3 - Reporting (ship if time allows, do not block P0-P2)**

- [#112](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/112) - HTML reporting dashboard
- [#113](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/113) - Top 10 failure summary

## v4.1 - Compliance Evidence ✅ SHIPPED

Released as v4.1.0. Transforms the harness from a security testing tool into a compliance evidence platform.

**Goal:** A compliance team can generate auditor-ready reports mapped to EU AI Act and ISO 42001 without leaving the CLI.

### What shipped

| Feature | Issue | Tests/Controls |
|---------|-------|----------------|
| AUROC per-module metrics | #155 | Detection effectiveness scoring |
| EU AI Act crosswalk | #156 | 16 controls across Articles 9-72 |
| ISO 42001 crosswalk | #156 | 15 controls across Clauses 5-10 + Annex A |
| Kill-switch compliance (IR-009 to IR-012) | #157 | 4 tests, CA SB 942 + EU AI Act Art 14 |
| FRIA evidence collection | #158 | 6 categories, EU AI Act Article 27 |
| Watermark adversarial tests (WM-001 to WM-005) | #159 | 5 tests, EU AI Act Article 50 |
| HTML compliance report generator | #160 | `--framework all --fria` one-command report |
| Simulate mode expansion | F7 (R33) | MCP, A2A, Identity (39 new simulate tests) |

**Total: 466 tests, 32 modules, 31 framework controls mapped.**

### Independent review

Audit R33 (`docs/AUDIT-R33-INDEPENDENT-REVIEW.md`): 7 findings, all resolved. 19/19 pytest passing. Zero import/compile errors across 32 modules.

### v4.2 — Incident-Tested

Every new module maps to a named security incident from April 2026:

| Module | Tests | Incident Source |
|--------|-------|----------------|
| `benchmark_integrity_harness.py` | BI-001 — BI-007 | UC Berkeley: all 8 AI benchmarks hackable for perfect scores |
| `governance_modification_harness.py` | GM-001 — GM-006 | lightningzero: 9/12 agents disabled own gates within 48h |
| PraisonAI adapter | PA-001 — PA-004 | CVE-2026-40288 (9.8), CVE-2026-40289 (9.1), CVE-2026-39889, CVE-2026-39891 (8.8) |
| MCP SSRF + STDIO | MCP-015 — MCP-017 | OX Security MCP STDIO disclosure, BlueRock 36.7% SSRF finding |
| OpenClaw CVE tests | CVE-009, CVE-010 | CVE-2026-35625 (privilege escalation), CVE-2026-35629 (SSRF) |

Also: shared `_utils.py` (SOLID/DRY), CLI registration, P0 bug fixes.

**Total: 466 tests, 32 modules.**

### v4.3 — Supply Chain + Research

- Skill Security Protocol implementation (`skill_security_harness.py`) from RFC #99 — 341 malicious ClawHub skills
- Publish DOIs #6-7 from #116 (intent contracts), #117 (multi-agent), #119 (memory security) research
- Migrate all remaining harnesses to `_utils.py`
- Dynamic test count in CLI

## v5.0 — Lock the Category

**Goal:** Become the standard others reference, not just a tool others use.

v5.0 is reframed around **standard-setting**, not feature shipping. The three moves that convert temporary advantages into sustained ones:

### Move 1: Publish the benchmark (the thing others cite)

A named decision-governance benchmark corpus - the MCPTox analog for behavioral assurance. Publish as a paper before or alongside the code. Designed so other researchers cite it, other vendors measure against it, and analysts use it to define the category.

- [#120](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/120) - Decision Behavior Benchmark corpus
- [#138](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/138) - Benchmark methodology paper

### Move 2: Standardize the evidence format (the thing others adopt)

Submit the attestation schema to IETF or OASIS as an informational draft. A schema only one tool uses is a feature. A schema others adopt is a moat.

- [#137](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/137) - Submit attestation schema to IETF/OASIS as informational draft
- evidence portability guidance for auditors, GRC platforms, and procurement teams

### Move 3: Build the longitudinal registry (the thing others cannot easily reproduce)

The attestation registry with cross-org comparative evidence over time. A registry with 6 months of data is an asset no new entrant can replicate on day one.

- registry API for cross-org evidence submission
- drift comparison across deployments (aggregate, anonymized)

### Research frontier (feeds next publications)

- [#116](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/116) - Intent contract validation tests
- [#117](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/117) - Multi-agent interaction security tests
- [#119](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/119) - Memory & continuity security tests

## Attestation & Evidence Network

The attestation registry is strategically important: it is where teams can publish decision-behavior evidence once and reuse it across CI gates, procurement reviews, and audits. Upcoming work ties the JSON schema, HTML reports, and signed artifacts directly into that registry so it becomes a shared source of truth, not just a local CLI output.

Strategically, this is how the project moves from "useful tool" toward "verification standard."

## Decision Behavior Benchmark

We are authoring a public corpus that highlights the gaps between metadata scanning and executable decision tests. Track progress in [#120](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/120). The benchmark will include escalation, delegation, collusion, protocol-crossing abuse, memory tampering, and reproducible evidence patterns.

## What NOT to Do

| Don't | Why |
|-------|-----|
| Add more enterprise platform adapters as the main story | Cannot out-breadth larger vendors. Depth in protocols, evidence, and payments is more defensible than breadth across platforms. |
| Compete with scanners on speed/ease alone | Larger vendors will always be faster for a quick scan. Be the thorough verification option they cannot replace. |
| Build a SaaS dashboard before having paying customers or evidence adoption | The product is the evidence artifact first, not the dashboard. |
| Chase GitHub stars as the primary KPI | Enterprise security tools win on auditor trust, not developer popularity. |

## Sequencing

```text
v3.9  → v3.10 → v4.1 (shipped) → v4.2 (next) → v4.3 → v5.0 (H2 2026)
```

## Sustained Advantage Trajectory

```text
Now:     Research (5 DOIs)
v3.10:   + Evidence format adoption
         + Payment protocol depth
v5.0:    + Benchmark others cite
         + Schema in standards body
v5.x:    + Registry network effect
```

Each step converts a temporary advantage into a more durable one. Miss any step and the corresponding moat does not form.

> **Disclosure:** This roadmap incorporates VRIO analysis and Porter's Five Forces assessment. Strategic decisions remain grounded in the maintainer's judgment and public information.

## How to Contribute

1. Pick the buyer motion that aligns with your interests.
2. Claim an issue linked above, or open a new one and tag the matching milestone.
3. Submit PRs referencing the issue number so the roadmap stays current.

Every change should improve our ability to prove how agents behave under pressure and package that proof so security teams can act on it.
