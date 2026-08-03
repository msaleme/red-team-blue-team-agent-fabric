# AIUC-1 Crosswalk: Evidence Mapping

This document maps selected [AIUC-1](https://www.aiuc-1.com) requirements to
potentially relevant Agent Security Harness tests. It is a research crosswalk,
not a certification, conformity assessment, or determination that a target
system meets a requirement. Applicability, sufficiency, independence, and
conformity must be determined for the specific target and standard version.

> **Standard currency:** this mapping was built against **v2026-Q1** (reviewed March 2026). AIUC-1 now revises quarterly — **Q2 (April 2026)** added MCP/A2A protocol-security and agent-identity controls; **Q3 (released 2026-07-15)** modified 8 requirements / 41 controls. Requirement-level rows below remain valid (renumbering happened at sub-control level), but see the **Q3-2026 Currency Note** near the end of this document before citing this crosswalk against the current standard. Last currency review: 2026-07-16.

---

## Requirement mapping (19 of 20 testable requirements in the 2026-Q1/Q2 set)

### B. Security (all listed requirements mapped)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **B001** | Third-party adversarial robustness testing | Harness test vectors may support evidence collection for prompt injection, jailbreaks, polymorphic attacks, multi-step chains, and CVE reproduction. See the [test inventory](TEST-INVENTORY.md) and run the count script for the current test-ID total. |
| **B002** | Detect adversarial input | MCP tool injection (MCP-001-010), A2A message spoofing (A2A-001-012), prompt injection via operational data (APP-001-030) |
| **B005** | Real-time input filtering | Filter bypass via encoding tricks, nested injection, polymorphic payloads, context displacement (ADV-001-010) |
| **B009** | Limit output over-exposure | Information leakage detection, output exfiltration tests, API key regex scanning |

### D. Reliability (all listed requirements mapped)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **D003** | Restrict unsafe tool calls | MCP capability escalation, unauthorized tool registration, A2A task hijacking, L402/x402 unauthorized payment execution |
| **D004** | Third-party testing of tool calls | 62 wire-protocol tests (MCP + A2A + L402 + x402) + 83 platform adapter tests across 25 cloud + 20 enterprise platforms |

### C. Safety (mapped subset)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **C001** | Define AI risk taxonomy | Framework provides STRIDE + OWASP Agentic + NIST AI 800-2 risk taxonomy with all 603 tests categorized |
| **C002** | Conduct pre-deployment testing | Entire framework designed for pre-deployment. `pip install agent-security-harness` and run before shipping. |
| **C010** | Third-party testing for harmful outputs | Adversarial test suite validates whether safety controls hold under attack |
| **C011** | Third-party testing for out-of-scope outputs | Protocol-level scope violation tests (MCP-003 capability escalation, A2A unauthorized access) |

### A. Data & Privacy (mapped subset)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **A003** | Limit AI agent data collection | MCP capability escalation, A2A cross-session leakage, enterprise platform data access boundary tests |
| **A004** | Protect IP & trade secrets | Tool discovery poisoning (exfiltration), context displacement DoS, API key leak detection |

### E. Accountability (complementary)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **E004** | Assign accountability | [CSG paper](https://doi.org/10.5281/zenodo.19162104) defines 3-tier governance with explicit accountability. 12 mechanisms, 77 days production evidence. |
| **E006** | Conduct vendor due diligence | A bounded, authorized harness run may contribute technical evidence to a vendor-due-diligence review. It does not replace the review or establish a vendor conclusion on its own. |
| **E015** | Log model activity | JSON reports with full request/response transcripts serve as audit evidence |

### F. Society (mapped subset)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **F001** | Prevent AI cyber misuse | GTG-1002 APT simulation: 17 tests modeling AI-orchestrated cyber espionage (lateral movement, exfiltration, persistence) |

---

## AIUC-1 Mapping Summary

| Principle | Reqs | Mapped | Evidence boundary |
|---|---|---|---|
| B. Security | 4 | **4** | Mapping identifies potentially relevant adversarial-testing vectors; it is not evidence of target performance. |
| D. Reliability | 2 | **2** | Mapping identifies potentially relevant tool-call testing; target configuration and execution evidence remain necessary. |
| C. Safety | 6 | **6** | Mapping identifies relevant CBRN, harmful-output, pre-deployment, and taxonomy artifacts. |
| A. Data & Privacy | 5 | 2 | Mapping identifies agent data-access and IP-leakage artifacts. |
| E. Accountability | 7 | **5** | Mapping identifies incident-response, diligence, and audit-evidence artifacts. |
| F. Society | 2 | **2** | Mapping identifies GTG-1002 and CBRN-prevention artifacts. |

**Not yet covered (3 requirements):** A001 (input data policy - process requirement), A002 (output data policy - process requirement), E005 (cloud vs on-prem assessment - infrastructure decision). Previously tracked gaps now closed: F002 CBRN prevention ([#34](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/34) - resolved with `cbrn` + `aiuc1` harnesses), C003/C004 harmful output ([#33](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/33) - resolved with `harmful-output` + `aiuc1` harnesses), E001-E003 incident response ([#35](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/35) - resolved with `incident-response` + `aiuc1` harnesses).

> **Claim boundary:** a mapped test has a documented relationship to a requirement. It does not establish that the test was executed, that a target passed, that testing was independent, or that a target conforms to AIUC-1. Retain the pinned revision, invocation, inputs, environment, timestamps, and output before making a runtime claim; obtain independent review before representing evidence as third-party reviewed.

> **Use case:** Use this crosswalk to select potentially relevant tests for an authorized target, run a pinned harness revision, and retain the resulting artifacts for review. The harness can support evidence collection relevant to AIUC-1 requirements. Applicability, sufficiency, independence, and conformity must be determined for the specific target and standard version.

---

## Q3-2026 Currency Note (standard revised 2026-07-15)

The Q3-2026 quarterly refresh modified 8 requirements and 41 controls ([changelog](https://www.aiuc-1.com/changelog)). Impact on this crosswalk:

| Q3 change | Impact here |
|---|---|
| **NEW A008** (A008.1–.5) — secrets-leakage prevention, mandatory for **code-generating agents** | Not mapped. This harness tests agent systems; it is not a code-generating product. Treat as out-of-scope pending maintainer review. |
| **NEW B010** (B010.1–.6) — secure patterns in generated code, mandatory for **code-generating agents** | Same as A008 — out-of-scope pending maintainer review. |
| **A003 revised** — sub-controls renumbered to A003.2–A003.3 | Requirement-level row (A003) unaffected; do not cite Q2 sub-control IDs. |
| **B008 revised** — model-access core requirement retired; sub-controls renumbered B008.1–B008.5 | Not mapped at sub-control level here; no row change. |
| **B006.3 extended** — sandboxing now covers agent-executed code alongside first-party MCP servers | Runtime/infrastructure control — attestation-level, not test coverage. |
| **E009 expanded** (+E009.2 anomalous-access alerting) | E-principle rows are complementary/process; no test-coverage claim made or added. |

**Claim discipline:** the "19 of 20 testable requirements" figure is denominated against the **2026-Q1/Q2 requirement set**. Q3 added two requirements scoped to code-generating agents; until the maintainer either maps or formally scopes them out, cite this document as *"evidence mapping against AIUC-1 2026-Q1/Q2; Q3-2026 delta reviewed 2026-07-16, two new codegen-scoped requirements pending scope decision."*

## Standards Alignment

- **AIUC-1 (2026)** - Evidence mapping for 19 of 20 testable requirements (2026-Q1/Q2 set; Q3-2026 delta — see Currency Note above)
- **OWASP Top 10 for Agentic Applications (2026)** - Complete ASI01-ASI10 coverage
- **OWASP LLM Top 10** - LLM01 (Prompt Injection), LLM02, LLM03, LLM04, LLM06, LLM08
- **NIST AI RMF** - GOVERN, MAP, MEASURE, MANAGE functions covered
- **NIST AI 800-2: Benchmark Evaluation Practices (Jan 2026)** - Statistical evaluation protocol follows all 9 practices
- **NIST NCCoE: AI Agent Identity & Authorization (Feb 2026)** - Dedicated test harness covering all 6 focus areas
- **NIST AI Agent Standards Initiative (Feb 2026)** - Aligned with agent security, identity, and interoperability pillars
- **NIST Cyber AI Profile (IR 8596, Dec 2025)** - Maps to Secure, Detect, Respond functions
- **ISA/IEC 62443** - Security Levels 1-4, air-gapped fallback for safety-critical agents
- **EU AI Act** - Transparency, human oversight, audit trail requirements
