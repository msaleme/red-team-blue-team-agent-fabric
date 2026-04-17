# AIUC-1 Crosswalk: Pre-Certification Testing

[AIUC-1](https://www.aiuc-1.com) (v2026-Q1, last reviewed March 2026) is the first AI agent certification standard, requiring **quarterly independent adversarial testing** to validate agent security, safety, and reliability. Built with MITRE, Cisco, Stanford, MIT, and Google Cloud. This framework provides the technical testing that AIUC-1 certification demands.

---

## Full AIUC-1 Requirement Mapping (19 of 20 testable requirements covered)

### B. Security (100% coverage)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **B001** | Third-party adversarial robustness testing | **470 tests** across 4 wire protocols, 32 modules. Prompt injection, jailbreaks, polymorphic attacks, multi-step chains, CVE reproduction. |
| **B002** | Detect adversarial input | MCP tool injection (MCP-001-010), A2A message spoofing (A2A-001-012), prompt injection via operational data (APP-001-030) |
| **B005** | Real-time input filtering | Filter bypass via encoding tricks, nested injection, polymorphic payloads, context displacement (ADV-001-010) |
| **B009** | Limit output over-exposure | Information leakage detection, output exfiltration tests, API key regex scanning |

### D. Reliability (100% coverage)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **D003** | Restrict unsafe tool calls | MCP capability escalation, unauthorized tool registration, A2A task hijacking, L402/x402 unauthorized payment execution |
| **D004** | Third-party testing of tool calls | 62 wire-protocol tests (MCP + A2A + L402 + x402) + 83 platform adapter tests across 25 cloud + 20 enterprise platforms |

### C. Safety (67% coverage)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **C001** | Define AI risk taxonomy | Framework provides STRIDE + OWASP Agentic + NIST AI 800-2 risk taxonomy with all 470 tests categorized |
| **C002** | Conduct pre-deployment testing | Entire framework designed for pre-deployment. `pip install agent-security-harness` and run before shipping. |
| **C010** | Third-party testing for harmful outputs | Adversarial test suite validates whether safety controls hold under attack |
| **C011** | Third-party testing for out-of-scope outputs | Protocol-level scope violation tests (MCP-003 capability escalation, A2A unauthorized access) |

### A. Data & Privacy (67% of testable requirements)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **A003** | Limit AI agent data collection | MCP capability escalation, A2A cross-session leakage, enterprise platform data access boundary tests |
| **A004** | Protect IP & trade secrets | Tool discovery poisoning (exfiltration), context displacement DoS, API key leak detection |

### E. Accountability (complementary)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **E004** | Assign accountability | [CSG paper](https://doi.org/10.5281/zenodo.19162104) defines 3-tier governance with explicit accountability. 12 mechanisms, 77 days production evidence. |
| **E006** | Conduct vendor due diligence | Run the harness against any vendor's agent before procurement. 470 tests as vendor evaluation. |
| **E015** | Log model activity | JSON reports with full request/response transcripts serve as audit evidence |

### F. Society (50% coverage)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **F001** | Prevent AI cyber misuse | GTG-1002 APT simulation: 17 tests modeling AI-orchestrated cyber espionage (lateral movement, exfiltration, persistence) |

---

## AIUC-1 Coverage Summary

| Principle | Reqs | Covered | Key Strength |
|---|---|---|---|
| B. Security | 4 | **4 (100%)** | Adversarial robustness testing is our core capability |
| D. Reliability | 2 | **2 (100%)** | Tool call testing across 4 wire protocols + 45 platforms |
| C. Safety | 6 | **6 (100%)** | CBRN prevention (F002), harmful output (C003/C004), pre-deployment testing, risk taxonomy |
| A. Data & Privacy | 5 | 2 (40%) | Agent data access boundaries, IP leakage prevention |
| E. Accountability | 7 | **5 (71%)** | Incident response (E001-E003), vendor due diligence, audit evidence, CSG governance framework |
| F. Society | 2 | **2 (100%)** | GTG-1002 APT simulation + CBRN prevention |

**Not yet covered (3 requirements):** A001 (input data policy - process requirement), A002 (output data policy - process requirement), E005 (cloud vs on-prem assessment - infrastructure decision). Previously tracked gaps now closed: F002 CBRN prevention ([#34](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/34) - resolved with `cbrn` + `aiuc1` harnesses), C003/C004 harmful output ([#33](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/33) - resolved with `harmful-output` + `aiuc1` harnesses), E001-E003 incident response ([#35](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/35) - resolved with `incident-response` + `aiuc1` harnesses).

> **Note:** "100% coverage" on Security and Reliability means this framework maps to every requirement in those principles. It does not mean exhaustive depth validation of every possible attack vector within each requirement. Coverage indicates breadth of requirement mapping; depth depends on target system complexity and test configuration (use `--trials N` for statistical confidence).

> **Use case:** Run this harness as your pre-certification adversarial testing tool. AIUC-1 requires quarterly third-party testing (B001, C010, D004). This framework satisfies those requirements with 470 executable tests, JSON audit reports, and statistical confidence intervals aligned to [NIST AI 800-2](https://doi.org/10.6028/NIST.AI.800-2).
>
> **Want an expert assessment?** [Book an AIUC-1 Readiness Assessment](https://msaleme.github.io/aiuc1-readiness/) - we run the harness against your deployment and deliver a gap analysis with remediation priorities.

---

## Standards Alignment

- **AIUC-1 (2026)** - Pre-certification testing for 19 of 20 testable requirements
- **OWASP Top 10 for Agentic Applications (2026)** - Complete ASI01-ASI10 coverage
- **OWASP LLM Top 10** - LLM01 (Prompt Injection), LLM02, LLM03, LLM04, LLM06, LLM08
- **NIST AI RMF** - GOVERN, MAP, MEASURE, MANAGE functions covered
- **NIST AI 800-2: Benchmark Evaluation Practices (Jan 2026)** - Statistical evaluation protocol follows all 9 practices
- **NIST NCCoE: AI Agent Identity & Authorization (Feb 2026)** - Dedicated test harness covering all 6 focus areas
- **NIST AI Agent Standards Initiative (Feb 2026)** - Aligned with agent security, identity, and interoperability pillars
- **NIST Cyber AI Profile (IR 8596, Dec 2025)** - Maps to Secure, Detect, Respond functions
- **ISA/IEC 62443** - Security Levels 1-4, air-gapped fallback for safety-critical agents
- **EU AI Act** - Transparency, human oversight, audit trail requirements
