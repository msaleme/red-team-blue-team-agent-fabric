# Roadmap

## Strategic Context

The 2026 compliance window is the forcing function for this roadmap.

AIUC-1 achieved its first certification in March 2026 (UiPath/Schellman). The EU AI Act high-risk deadline is August 2, 2026. NIST launched its AI Agent Standards Initiative in February 2026, and COSAiS SP 800-53 control overlays for AI agents are in active development. Each of these creates buyer urgency for compliance-grade evidence artifacts — the kind this project is uniquely positioned to produce.

The previous roadmap sequenced governance artifacts last (v4.0). This revision pulls the most buyer-critical governance work forward into v3.10 so the project can deliver audit-ready output before the compliance buying wave crests, while keeping deeper research problems in v4.0 where they can receive proper focus.

### Category

**Decision Governance for Autonomous Agents.**

Identity and authorization controls answer *who* an agent is and *what* it can access. This harness tests *how* that agent behaves under adversarial pressure — across MCP, A2A, and emerging payment protocols — and produces evidence that CI pipelines, security teams, and auditors can use directly.

We have not found another open-source tool that combines wire-protocol adversarial testing across MCP, A2A, L402, and x402 with compliance-grade evidence generation. That gap is what this project fills.

## Release Summary

| Release | Theme | Primary Outcomes | Target |
|---------|-------|------------------|--------|
| **v3.9 – Adopt in 15 Minutes** | Make the harness effortless to drop into CI | JSON/CI output, clearer docs/errors, turnkey GitHub Action | Ship fast |
| **v3.10 – Prove It to Auditors** | Deliver governance-ready output before the 2026 compliance window closes | AIUC-1 test suite, signed evidence packs, behavioral profiling, risk scoring, HTML dashboards | Before July 2026 |
| **v4.0 – Lock the Category** | Publish the decision-governance benchmark and deepen multi-agent safety | Named benchmark corpus, intent contracts, multi-agent interaction safety, memory tampering, attestation registry | H2 2026 |

## v3.9 – Adopt in 15 Minutes

**Goal:** A DevSecOps engineer can gate deployments on decision-governance tests within 15 minutes of first install.

**Objectives**
- Provide machine-readable output for CI/CD workflows.
- Improve onboarding transparency (scope, limitations, examples).
- Ship a reference GitHub Action so teams can drop the harness into pipelines in minutes.

**Linked issues**
- [#103](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/103) – Add `--json` output flag to CLI
- [#90](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/90) – Improve error messages when target server is unreachable
- [#92](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/92) – Add "Used by" section with community validators
- [#108](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/108) – Expand Scope & Limitations documentation
- [#109](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/109) – Provide CI-ready GitHub Action example
- [#89](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/89) – Add machine-readable CLI output (legacy task to be closed once #103 lands)
- [#102](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/102) – v3.9 roadmap meta issue
- [#88](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/88) – Legacy v3.9 planning issue (kept for history)

## v3.10 – Prove It to Auditors

**Goal:** A security architect or compliance lead can produce audit-grade evidence of decision-governance testing — before the EU AI Act high-risk deadline (August 2, 2026) and while AIUC-1 adoption is accelerating.

This is the release where the project transitions from a testing harness to a governance tool.

**Objectives**
- Map harness coverage directly to AIUC-1 controls and produce compliance-ready artifacts. The `aiuc1_prep.py` script already provides gap analysis; this release formalizes it into a dedicated test suite.
- Generate signed evidence packages that slot into four contexts without reformatting: CI gate artifact, exception review input, procurement questionnaire attachment, and audit packet exhibit.
- Add behavioral profiling and risk scoring so teams can see drift over time — the core "what static scanners miss" story.
- Expand MCP/A2A protocol coverage (tool description injection, agent card limitations).
- Deliver human-friendly HTML dashboards and automatic "Top 10" failure summaries.

**Linked issues — accelerated from v4.0**
- [#115](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/115) – Create AIUC-1 compliance test suite
- [#118](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/118) – Build audit-ready evidence generation

**Linked issues — originally v3.10**
- [#110](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/110) – v3.10 meta issue
- [#93](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/93) – Add A2A-009: Agent card limitations field verification test
- [#91](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/91) – Add MCP-014: Tool description injection test
- [#111](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/111) – Add behavioral profiling & risk scoring
- [#112](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/112) – Build improved HTML reporting dashboard
- [#113](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/113) – Automate Top 10 failure summary

### Why these items moved forward

AIUC-1 mapping (#115) and signed evidence packs (#118) were previously in v4.0. They are pulled forward because:

1. **AIUC-1's first certification shipped March 2026.** The window to be the testing tool that maps to AIUC-1 is now, not after the standard matures further.
2. **EU AI Act high-risk deadline is August 2, 2026.** Governance artifacts that ship after that date miss the compliance buying wave.
3. **Evidence generation is the single feature that separates a harness from a governance tool.** It is the commercial inflection point for the project.

## v4.0 – Lock the Category

**Goal:** Publish the decision-governance benchmark, deepen multi-agent safety, and turn the attestation registry into a compounding data asset.

**Objectives**
- Publish a named benchmark corpus for decision-governance failures — escalation bypass, unsafe delegation, protocol-crossing abuse, normalization of deviance — designed to become the reference evaluation others cite (the MCPTox analog for behavioral assurance).
- Validate agent intent contracts and multi-agent interaction safety (escalation, tampering, collusion).
- Test long-lived memory stores for tampering and continuity attacks.
- Evolve the attestation registry from point-in-time reports to longitudinal comparative evidence across deployments, creating a data asset that compounds over time.

**Linked issues**
- [#114](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/114) – v4.0 meta issue
- [#116](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/116) – Implement intent contract validation tests
- [#117](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/117) – Add multi-agent interaction security tests
- [#119](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/119) – Add memory & continuity security tests
- [#51](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/51) – OATR test fixtures for x402 identity verification tests

### Why these items stay in v4.0

Intent contracts (#116), multi-agent interaction safety (#117), and memory tampering (#119) are genuinely hard research problems that deserve dedicated focus. They are not yet procurement checkboxes — no buyer is requiring them in RFPs today. Shipping them well matters more than shipping them early.

## Sequencing Rationale

```
v3.9  (ship fast)     → "Find dangerous stuff in 15 minutes"
v3.10 (before July)   → "Prove it to auditors"  ← commercial inflection point
v4.0  (H2 2026)       → "Lock the category with a benchmark and compounding data"
```

The roadmap is organized around three buyer motions, not three engineering milestones:

| Buyer | Pain | Release |
|-------|------|---------|
| DevSecOps engineer | "Can I gate deploys on decision-governance tests?" | v3.9 |
| Security architect / compliance lead | "Give me audit evidence that static scanners cannot produce" | v3.10 |
| CISO / platform team | "Show me behavioral assurance over time, benchmarked against the industry" | v4.0 |

## Competitive Positioning

This project occupies a layer between static scanners and broad enterprise platforms:

| Capability | Static Scanners | This Framework | Enterprise Platforms |
|------------|----------------|----------------|---------------------|
| MCP config/metadata scan | Yes | — | Yes |
| Wire-protocol adversarial testing | — | **Yes** | — |
| Multi-protocol coverage (MCP + A2A + L402 + x402) | — | **Yes** | — |
| Longitudinal behavioral drift | — | **Planned (v3.10+)** | — |
| Compliance-grade evidence packs | — | **Planned (v3.10)** | Partial |
| Decision-governance benchmark | — | **Planned (v4.0)** | — |

We see this as complementary: scan with static tools for configuration issues, test with this framework for behavioral assurance under adversarial conditions. Both layers are necessary.

## Flagship Vertical: Agentic Payments in Regulated Environments

The project's strongest uncontested position is x402/L402 coverage — 39 payment-specific tests, autonomy risk scoring, and facilitator trust checks. We have not found dedicated security testing tooling for agent payment protocols from any other vendor.

Payment teams at fintechs and neobanks integrating x402/USDC settlement into agent workflows face a concrete compliance problem: PSD2 and EU AI Act both require documented governance for automated financial decisions, and existing tools do not produce the evidence their compliance teams need. This vertical is where the project can be *the* answer, not *an* answer.

MCP and A2A remain the breadth story. Payments are the depth wedge.

---

> **Disclosure:** This roadmap revision was developed with AI-assisted strategic analysis (Claude Code, April 2026), including competitive landscape research, market timing assessment, and buyer-motion sequencing. All strategic decisions, prioritization choices, and final editorial judgment are the maintainer's own. The underlying competitive analysis drew on publicly available information including vendor documentation, OWASP publications, NIST announcements, and release notes from named projects.

This document is updated whenever milestones shift. Contributions aligned with these themes are especially welcome — open an issue or PR and tag the matching milestone.
