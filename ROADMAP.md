# Roadmap

## Strategic Context

Decision-layer security is becoming the critical differentiator for autonomous AI systems. Identity and authorization controls answer **who** an agent is and **what** it can access. Our harness focuses on **how** that agent behaves under adversarial pressure across MCP, A2A, and emerging payment protocols. The releases below double down on practical decision governance, from developer experience through compliance-grade evidence.

## Release Summary

| Release | Theme | Primary Outcomes |
|---------|-------|------------------|
| **v3.9 – Usability & Transparency** | Make the harness effortless to adopt and reason about | JSON/CI output, clearer docs/errors, turnkey GitHub Action |
| **v3.10 – Protocol Depth & Insights** | Deepen MCP/A2A coverage and surface richer telemetry | Behavioral profiling, HTML dashboards, failure summaries |
| **v4.0 – Governance & Compliance** | Align with AIUC-1 and enterprise audit needs | Intent contract validation, multi-agent safety, evidence packs |

## v3.9 – Usability & Transparency

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

## v3.10 – Protocol Depth & Insights

**Objectives**
- Expand MCP/A2A protocol coverage (tool description injection, card limitations).
- Add behavioral profiling plus risk scoring so teams can see drift over time.
- Deliver human-friendly HTML dashboards and automatic "Top 10" failure summaries.

**Linked issues**
- [#110](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/110) – v3.10 meta issue
- [#93](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/93) – Add A2A-009: Agent card limitations field verification test
- [#91](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/91) – Add MCP-014: Tool description injection test
- [#111](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/111) – Add behavioral profiling & risk scoring
- [#112](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/112) – Build improved HTML reporting dashboard
- [#113](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/113) – Automate Top 10 failure summary

## v4.0 – Governance & Compliance

**Objectives**
- Map harness coverage directly to AIUC-1 controls and produce compliance-ready artifacts.
- Validate agent intent contracts and multi-agent interaction safety (escalation, tampering, collusion).
- Generate signed evidence packages for auditors and test long-lived memory stores for tampering.

**Linked issues**
- [#114](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/114) – v4.0 meta issue
- [#115](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/115) – Create AIUC-1 compliance test suite
- [#116](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/116) – Implement intent contract validation tests
- [#117](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/117) – Add multi-agent interaction security tests
- [#118](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/118) – Build audit-ready evidence generation
- [#119](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/119) – Add memory & continuity security tests
- [#51](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/51) – OATR test fixtures for x402 identity verification tests

---

This document is updated whenever milestones shift. Contributions aligned with these themes are especially welcome—open an issue or PR and tag the matching milestone.
