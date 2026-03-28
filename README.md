# Agent Security Harness

[![PyPI version](https://badge.fury.io/py/agent-security-harness.svg)](https://pypi.org/project/agent-security-harness/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/security%20tests-328-green.svg)](#test-inventory)

The first open-source security testing framework purpose-built for multi-agent AI deployments in critical infrastructure and other high-impact enterprise environments.

AI agents are being deployed into enterprise systems with the ability to make decisions, invoke tools, move across workflows, and trigger consequential actions. The attack surface is fundamentally different from traditional software: agent-to-agent escalation, context poisoning, protocol abuse, prompt injection through operational data, authority drift, and normalization of deviance in safety-critical environments.

This repository exists to test a harder question than access control alone can answer:

**Can an autonomous agent be trusted to take consequential action under adversarial conditions?**

That includes payment flows, but it also includes tool execution, orchestration, platform actions, cross-system chaining, and decision behavior across MCP, A2A, L402, x402, cloud agent platforms, and enterprise systems.

## Why This Matters Now

Enterprises are moving from isolated copilots to agents that can act. As that shift accelerates, the control problem changes:

- identity governance tells you **who** the agent is
- permissions tell you **what** it can access
- security testing must also determine **how** it behaves when conditions are adversarial

That gap is where agent failures now emerge: not just unauthorized access, but authorized agents making unsafe, manipulated, or policy-inconsistent decisions.

A fast-emerging example is **agentic payments and stablecoin settlement**, where protocols like x402 and L402 make machine-native transactions more practical. But payments are only one instance of the broader problem: autonomous systems taking real-world action without sufficient decision-layer validation.

## What This Repo Provides

This framework provides **328 executable security tests across 21 modules**, including:

- application-layer attack scenarios
- MCP and A2A wire-protocol harnesses
- L402 and x402 payment flow testing
- CVE reproduction suites
- AIUC-1 pre-certification testing
- cloud agent platform adapters
- enterprise platform adapters
- APT simulations
- decision-governance and autonomy-risk evaluation

It is designed for teams that need to test not only whether an agent is reachable or compliant on paper, but whether it remains safe, bounded, and trustworthy in production-like conditions.

## Three Layers of Agent Decision Security

| Layer | What it covers | Example focus |
|-------|----------------|---------------|
| **Protocol Integrity** | Prevent spoofing, replay, downgrade, diversion, and malformed protocol behavior | MCP, A2A, L402, x402 wire-level tests |
| **Operational Governance** | Validate session state, capability boundaries, platform actions, trust chains, and execution context | capability escalation, facilitator trust, provenance, session security |
| **Decision Governance** | Test whether an agent should act at all under its authority, confidence, scope, and policy constraints | autonomy scoring, scope creep, return-channel poisoning, normalization-of-deviance |

## Where Payments Fit

One strategic use case in this repository is **regulated agentic payments**.

As stablecoins, on-chain settlement, and machine-to-machine payment protocols mature, the question is no longer just whether an agent can pay. It is whether an agent can be trusted to initiate, route, and complete value transfer safely under adversarial conditions.

This framework includes dedicated coverage for that emerging control surface through x402, L402, facilitator trust checks, autonomy risk scoring, and payment-specific threat scenarios.

## The WHO vs. HOW Gap

Most current tools govern **who** agents are and **what** they can access.

This framework tests **how** agents behave when they are already authorized.

Identity governance tells you the agent is allowed. 
Decision governance tells you the agent is right.

Both are necessary.

---
## Quick Start

### Installation
```bash
pip install agent-security-harness
```

### Basic Usage
```bash
# List all available tests
agent-security list

# Test an MCP server
agent-security test mcp --url http://localhost:8080/mcp

# Test an x402 payment endpoint (Coinbase/Stripe agent payments)
agent-security test x402 --url https://your-x402-endpoint.com

# Test with statistical confidence intervals (10 trials per test)
agent-security test mcp --url http://localhost:8080/mcp --trials 10

# Check version
agent-security version
```

### Try It Without a Server (Mock MCP Server)

A bundled mock MCP server lets you validate the harness works without setting up your own target:

```bash
# Terminal 1: Start the mock server (has one deliberately vulnerable tool)
python -m testing.mock_mcp_server

# Terminal 2: Run the harness against it
agent-security test mcp --transport http --url http://localhost:8402/mcp
```

The mock server includes a poisoned tool description (exfil URL) that the `tool_discovery_poisoning` test should catch.

### Rate Limiting

When testing production endpoints, add a delay between tests to avoid triggering WAF blocks:

```bash
# 500ms delay between each test
agent-security test mcp --url http://localhost:8080/mcp --delay 500

# 2 second delay for sensitive production endpoints
agent-security test a2a --url https://agent.example.com --delay 2000
```

### Example Output
```bash
$ agent-security test mcp --url http://localhost:8080/mcp
Running MCP Protocol Security Tests v3.7...
✓ MCP-001: Tool List Integrity Check [PASS] (0.234s)
✓ MCP-002: Tool Registration via Call Injection [PASS] (0.412s)
✗ MCP-003: Capability Escalation via Initialize [FAIL] (0.156s)
...
Results: 8/10 passed (80% pass rate) - see report.json
```

---

## Why This Matters

- **EU AI Act deadline: August 2, 2026** — high-risk AI systems require transparency, human oversight, and documented governance. This framework satisfies those requirements.
- **NIST AI Agent Standards Initiative (Feb 2026)** — NIST launched a dedicated initiative for secure, interoperable AI agents. This framework aligns with the direction NIST is heading.
- **OWASP Top 10 for Agentic Applications (Dec 2025)** — The benchmark for agentic AI security is now published. This framework provides **complete coverage of all 10 OWASP Agentic categories** (ASI01-ASI10).
- **No existing open-source framework** covers the intersection of multi-agent orchestration + critical infrastructure + industrial safety.
- Enterprises are deploying agentic AI faster than they can secure it. This closes the gap.

---

## Feature Overview

### 21 Test Harness Modules

| Module | Tests | Layer | Description |
|---|---|---|---|
| **MCP Protocol** | 11 | JSON-RPC 2.0 | Anthropic MCP wire-protocol testing |
| **A2A Protocol** | 12 | JSON-RPC/HTTP | Google Agent-to-Agent communication |
| **L402 Payment** | 14 | HTTP/Lightning | Bitcoin/Lightning payment flow security (macaroons, preimages, caveats) |
| **x402 Payment** | 25 | HTTP/USDC | Coinbase/Stripe agent payment protocol (recipient manipulation, session theft, facilitator trust, cross-chain confusion) |
| **Framework Adapters** | 11 | Various APIs | LangChain, CrewAI, AutoGen, OpenAI, Bedrock |
| **Enterprise Platforms** | 58 | Platform APIs | SAP, Salesforce, Workday, Oracle, ServiceNow, +15 more |
| **GTG-1002 APT Simulation** | 17 | Full Campaign | First documented AI-orchestrated cyber espionage |
| **Advanced Attacks** | 10 | Multi-step | Polymorphic, stateful, multi-domain attack chains |
| **Over-Refusal** | 25 | All protocols | False positive rate testing: legitimate requests that should NOT be blocked |
| **Provenance & Attestation** | 15 | Supply Chain | Fake provenance, spoofed attestation, marketplace integrity (CVE-2026-25253) |
| **Jailbreak** | 25 | Model/Agent | DAN variants, token smuggling, authority impersonation, persistence |
| **Return Channel** | 8 | Output/Context | Return channel poisoning: output injection, ANSI escape, context overflow, encoded smuggling, structured data poisoning |
| **Identity & Authorization** | 18 | NIST NCCoE | All 6 focus areas from NIST agent identity standards |
| **Capability Profile** | 10 | A2A JSON-RPC | Executor capability boundary validation, profile escalation prevention |
| **Harmful Output** | 10 | A2A JSON-RPC | Toxicity, bias, scope violations, deception (AIUC-1 C003/C004) |
| **CBRN Prevention** | 8 | A2A JSON-RPC | Chemical/biological/radiological/nuclear content safeguards (AIUC-1 F002) |
| **Incident Response** | 8 | A2A JSON-RPC | Alert triggering, kill switch, log completeness, recovery (AIUC-1 E001-E003) |
| **CVE-2026-25253 Reproduction** | 9 | MCP Supply Chain | Nested schema injection, fork fingerprinting, marketplace contamination, encoded payload detection |
| **AIUC-1 Compliance** | 9 | Agent Safety | Incident response, CBRN prevention, harmful content, scope creep, authority impersonation |
| **Cloud Agent Platforms** | 25 | Platform APIs | AWS Bedrock, Azure AI Agent Service, Google Vertex, Salesforce Agentforce, IBM watsonx |

**Total: 328 security tests across 21 modules** (verified by `scripts/count_tests.py`)

### Key Capabilities

- **Zero external dependencies** (core modules use Python stdlib only)
- **4 wire protocols** supported: MCP (JSON-RPC 2.0), A2A, L402 (Lightning), x402 (USDC/stablecoin)
- **25 cloud agent platform + 20 enterprise platform adapters** (Bedrock, Azure, Vertex, Agentforce, watsonx, SAP, Workday, etc.)
- **Agent Autonomy Risk Score** (0-100) for payment endpoints - answers "should this agent spend money unsupervised?"
- **CSG mapping** per test - links each test to the Constitutional Self-Governance mechanism that catches the attack
- **Response body leak detection** - scans for API keys, tokens, SSNs, stack traces, SQL, cloud credentials
- **Statistical evaluation** with confidence intervals (NIST AI 800-2 aligned)
- **JSON reports** with full request/response transcripts
- **Bundled mock MCP server** for zero-config validation
- **Rate limiting** (--delay flag) for production endpoint testing
- **69 self-tests** validating harness correctness
- **CI pipeline** on Python 3.10/3.11/3.12

---

## How This Differs From Other Projects

Most AI security tools test **models** (prompt injection, jailbreaks, output filtering) or enforce **permissions** (identity, access control, sandboxing). This framework tests **agent systems** at the protocol, orchestration, and decision layer.

| Capability | [NVIDIA Garak](https://github.com/NVIDIA/garak) (7K+ stars) | [MS Agent Governance](https://github.com/microsoft/agent-governance-toolkit) (300+ stars) | [SlowMist MCP Checklist](https://github.com/slowmist/MCP-Security-Checklist) (800+ stars) | [agent-audit](https://github.com/HeadyZhang/agent-audit) (100+ stars) | **This framework** |
|---|---|---|---|---|---|
| **What it tests** | LLM model vulnerabilities | Policy enforcement + sandboxing | MCP configuration (checklist) | Static code analysis | Agent protocols + orchestration + decisions |
| **MCP wire-protocol tests** | - | - | - | - | 10 tests (JSON-RPC 2.0) |
| **A2A wire-protocol tests** | - | - | - | - | 12 tests (Agent Cards, tasks, push notifications) |
| **L402 payment flow tests** | - | - | - | - | 14 tests (macaroons, invoices, caveats) |
| **x402 payment protocol tests** | - | - | - | - | 43 tests (Coinbase/Stripe agent payments, recipient manipulation, session theft, facilitator trust) |
| **Agent Autonomy Risk Score** | - | - | - | - | 0-100 score: "should this agent spend money unsupervised?" |
| **Enterprise platform adapters** | - | - | - | - | 25 cloud + 20 enterprise platforms (Bedrock, Azure, Vertex, Agentforce, watsonx, SAP, Salesforce, Workday, Oracle, ServiceNow, etc.) |
| **APT simulation (GTG-1002)** | - | - | - | - | 19 tests (full campaign lifecycle) |
| **NIST AI 800-2 evaluation protocol** | - | - | - | - | Statistical confidence intervals, qualified claims |
| **Published research backing** | - | - | - | - | 2 DOI-citable papers + 3 NIST submissions |
| **Executable tests** | Yes (model-layer) | Yes (policy-layer) | No (docs only) | Yes (static analysis) | Yes (328 tests, protocol + app layer) |
| **Governance layer** | WHO (model safety) | WHO (identity, access) | WHO (config) | WHO (code scanning) | **HOW (decision governance)** |

### The WHO vs. HOW Gap

Current tools govern *who* agents are and *what* they can access. This framework tests whether agents make correct *decisions* under adversarial conditions. Identity governance tells you the agent is authorized. Decision governance tells you the agent is right. Both are necessary. Most projects only address the first.

For the research behind this distinction, see [Constitutional Self-Governance for Autonomous AI Agents](https://doi.org/10.5281/zenodo.19162104) (77 days of production data, 56 agents).

---

## Test Inventory

<details>
<summary><strong>Threat Coverage by STRIDE Category</strong></summary>

Scenarios are mapped across the STRIDE threat model:

| Category | Tests | Examples |
|---|---|---|
| **Spoofing** | 4 | Rogue agent registration, MCP replay attack, credential velocity check |
| **Tampering** | 15 | Prompt injection, SCADA sensor poisoning, polymorphic attacks, normalization of deviance, supply chain poisoning, code gen execution, non-deterministic exploitation |
| **Information Disclosure** | 1 | Unauthorized financial data access |
| **Denial of Service** | 2 | Orchestration flood, A2A recursion loop |
| **Elevation of Privilege** | 3 | Unauthorized A2A escalation, tool overreach, safety override |
| **InfraGard-Derived** | 7 | Superman effect, polymorphic evasion, LLM hallucination injection, data poisoning, deviance drift |

</details>

<details>
<summary><strong>OWASP Top 10 for Agentic Applications - Complete Coverage</strong></summary>

This framework provides **complete mapping** to all 10 categories of the OWASP Agentic Top 10:

| OWASP Agentic ID | Risk | Test Scenarios |
|---|---|---|
| **ASI01** | Agent Goal Hijack | RT-003 (SAP prompt injection), RT-018 (social engineering), RT-022 (hallucination injection) |
| **ASI02** | Tool Misuse & Exploitation | RT-006 (tool overreach), RT-017 (SCADA shutdown suggestion) |
| **ASI03** | Identity & Privilege Abuse | RT-002 (A2A escalation), RT-025 (superman effect), RT-001 (rogue registration) |
| **ASI04** | Agentic Supply Chain Vulns | RT-014 (rogue orchestration join), RT-026 (MCP server supply chain poisoning) |
| **ASI05** | Unexpected Code Execution | RT-004 (SCADA sensor injection), RT-027 (agent code generation execution) |
| **ASI06** | Memory & Context Poisoning | RT-005 (cascade corruption), RT-009 (long-context), RT-023 (data poisoning) |
| **ASI07** | Insecure Inter-Agent Comms | RT-020 (MCP replay), RT-012 (A2A recursion loop) |
| **ASI08** | Cascading Failures | RT-005 (multi-agent cascade), RT-024 (normalization of deviance) |
| **ASI09** | Human-Agent Trust Exploitation | RT-018 (social engineering), RT-019 (priority inflation) |
| **ASI10** | Non-Deterministic Behavior | RT-028 (non-deterministic output exploitation) |

</details>

<details>
<summary><strong>Protocol-Level Test Harnesses</strong></summary>

### MCP (Model Context Protocol) - 11 tests
```bash
agent-security test mcp --url http://localhost:8080/mcp
```

| Test ID | Test | OWASP ASI | Description |
|---|---|---|---|
| MCP-001 | Tool List Integrity Check | ASI04 | Validates tool discovery response integrity |
| MCP-002 | Tool Registration via Call Injection | ASI04 | Attempts malicious tool registration |
| MCP-003 | Capability Escalation via Initialize | ASI03 | Tests capability negotiation boundaries |
| MCP-004 | Protocol Version Downgrade Attack | ASI03 | Attempts protocol version manipulation |
| MCP-005 | Resource URI Path Traversal | ASI04 | Tests resource access path validation |
| MCP-006 | Prompt Template Injection via Get | ASI01 | Injects malicious prompt templates |
| MCP-007 | Sampling Request Context Exfiltration | ASI02 | Attempts context data extraction |
| MCP-008 | Malformed JSON-RPC Handling | ASI08 | Tests protocol error handling |
| MCP-009 | Batch Request DoS | ASI08 | Batch request flood testing |
| MCP-010 | Tool Call Argument Injection | ASI02 | Malicious tool parameter injection |
| MCP-011 | Tool Description Context Displacement | ASI08 | 50K+ char description DoS with hidden injection payload |

### A2A (Agent-to-Agent) - 12 tests  
```bash
agent-security test a2a --url https://agent.example.com
```

### L402 Payment Protocol - 15 tests
```bash
agent-security test l402 --url https://l402.example.com
```

### x402 Payment Protocol - 43 tests (First Open-Source x402 Harness)
```bash
agent-security test x402 --url https://your-x402-endpoint.com
```

Tests the Coinbase/Stripe/Cloudflare agent payment standard ($600M+ payment volume):

| Test ID | Test | Category | Description |
|---|---|---|---|
| X4-001-003 | Payment Challenge Validation | payment_challenge | Missing headers, malformed auth, currency mismatch |
| X4-004-006 | Recipient Address Manipulation | recipient_manipulation | Dynamic payTo routing attacks (V2), address spoofing, invalid addresses |
| X4-007-010 | Session Token Security | session_security | Token fabrication, expiry bypass, sensitive data leakage in sessions |
| X4-011-013 | Spending Limit Exploitation | spending_limits | Rate limit bypass, underpayment, budget exhaustion |
| X4-014-016 | Facilitator Trust | facilitator_trust | Fake facilitator injection, verification bypass, unreachable facilitator |
| X4-017-018 | Information Disclosure | information_disclosure | Leaked keys in 402 response, stack traces in errors |
| X4-019-020 | Cross-Chain Confusion | cross_chain_confusion | Wrong network, wrong token type (EURC vs USDC) |

**Innovative features unique to x402 harness:**
- **CSG Mapping** - each test links to the Constitutional Self-Governance mechanism that catches it (Hard Constraints, Harm Test, Twelve Numbers, Falsification Requirement)
- **Financial Impact Estimation** - each result tagged: fund_theft, overpayment, service_denial, info_leak, or session_hijack
- **Agent Autonomy Risk Score** (0-100) - composite score answering "how dangerous is it to let an agent pay this endpoint unsupervised?" based on recipient consistency, payment validation, info leakage, session security, and facilitator trust

</details>

<details>
<summary><strong>Enterprise Platform Adapters</strong></summary>

Pre-configured tests for 20+ enterprise platforms where AI agents are being deployed:

### Tier 1 Platforms (9 platforms, 30 tests)
- **SAP Joule** - ERP/SCADA security boundaries
- **Salesforce Agentforce** - CRM data isolation  
- **Workday** - HR/Payroll PII protection
- **Microsoft Copilot/Azure AI** - Enterprise integration security
- **Google Vertex AI** - Cloud platform boundaries
- **Amazon Q** - AWS service integration
- **Oracle Fusion AI** - Database and financial system access
- **ServiceNow Now Assist** - ITSM workflow security
- **OpenClaw** - Session and tool isolation

### Tier 2 Platforms (11 platforms, 27 tests)  
- IBM Maximo, Snowflake Cortex, Databricks Mosaic AI
- Pega GenAI, UiPath, Atlassian Rovo
- Zendesk AI, IFS Cloud, Infor AI
- HubSpot Breeze, Appian AI

```bash
# List all enterprise adapters
agent-security list --category enterprise

# Test specific platforms
agent-security test enterprise --platform sap --url https://your-sap.com
agent-security test enterprise --platform salesforce --url https://your-org.salesforce.com
```

</details>

---

## AIUC-1 Crosswalk: Pre-Certification Testing

[AIUC-1](https://www.aiuc-1.com) (v2026-Q1, last reviewed March 2026) is the first AI agent certification standard, requiring **quarterly independent adversarial testing** to validate agent security, safety, and reliability. Built with MITRE, Cisco, Stanford, MIT, and Google Cloud. This framework provides the technical testing that AIUC-1 certification demands.

<details>
<summary><strong>Full AIUC-1 Requirement Mapping (15 of 20 testable requirements covered)</strong></summary>

#### B. Security (100% coverage)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **B001** | Third-party adversarial robustness testing | **328 tests** across 4 wire protocols, 21 modules. Prompt injection, jailbreaks, polymorphic attacks, multi-step chains, CVE reproduction. |
| **B002** | Detect adversarial input | MCP tool injection (MCP-001-010), A2A message spoofing (A2A-001-012), prompt injection via operational data (APP-001-030) |
| **B005** | Real-time input filtering | Filter bypass via encoding tricks, nested injection, polymorphic payloads, context displacement (ADV-001-010) |
| **B009** | Limit output over-exposure | Information leakage detection, output exfiltration tests, API key regex scanning |

#### D. Reliability (100% coverage)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **D003** | Restrict unsafe tool calls | MCP capability escalation, unauthorized tool registration, A2A task hijacking, L402/x402 unauthorized payment execution |
| **D004** | Third-party testing of tool calls | 81 wire-protocol tests (MCP + A2A + L402 + x402) + 93 platform adapter tests across 25 cloud + 20 enterprise platforms |

#### C. Safety (67% coverage)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **C001** | Define AI risk taxonomy | Framework provides STRIDE + OWASP Agentic + NIST AI 800-2 risk taxonomy with all 328 tests categorized |
| **C002** | Conduct pre-deployment testing | Entire framework designed for pre-deployment. `pip install agent-security-harness` and run before shipping. |
| **C010** | Third-party testing for harmful outputs | Adversarial test suite validates whether safety controls hold under attack |
| **C011** | Third-party testing for out-of-scope outputs | Protocol-level scope violation tests (MCP-003 capability escalation, A2A unauthorized access) |

#### A. Data & Privacy (67% of testable requirements)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **A003** | Limit AI agent data collection | MCP capability escalation, A2A cross-session leakage, enterprise platform data access boundary tests |
| **A004** | Protect IP & trade secrets | Tool discovery poisoning (exfiltration), context displacement DoS, API key leak detection |

#### E. Accountability (complementary)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **E004** | Assign accountability | [CSG paper](https://doi.org/10.5281/zenodo.19162104) defines 3-tier governance with explicit accountability. 12 mechanisms, 77 days production evidence. |
| **E006** | Conduct vendor due diligence | Run the harness against any vendor's agent before procurement. 328 tests as vendor evaluation. |
| **E015** | Log model activity | JSON reports with full request/response transcripts serve as audit evidence |

#### F. Society (50% coverage)

| AIUC-1 Req | Requirement | Our Coverage |
|---|---|---|
| **F001** | Prevent AI cyber misuse | GTG-1002 APT simulation: 19 tests modeling AI-orchestrated cyber espionage (lateral movement, exfiltration, persistence) |

</details>

### AIUC-1 Coverage Summary

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

> **Use case:** Run this harness as your pre-certification adversarial testing tool. AIUC-1 requires quarterly third-party testing (B001, C010, D004). This framework satisfies those requirements with 328 executable tests, JSON audit reports, and statistical confidence intervals aligned to [NIST AI 800-2](https://doi.org/10.6028/NIST.AI.800-2).
>
> **Want an expert assessment?** [Book an AIUC-1 Readiness Assessment](https://msaleme.github.io/aiuc1-readiness/) - we run the harness against your deployment and deliver a gap analysis with remediation priorities.

---

## Standards Alignment

- ✅ **AIUC-1 (2026)** - Pre-certification testing for 15 of 20 testable requirements ([crosswalk above](#aiuc-1-crosswalk-pre-certification-testing))
- ✅ **OWASP Top 10 for Agentic Applications (2026)** - Complete ASI01-ASI10 coverage
- ✅ **OWASP LLM Top 10** - LLM01 (Prompt Injection), LLM02, LLM03, LLM04, LLM06, LLM08
- ✅ **NIST AI RMF** - GOVERN, MAP, MEASURE, MANAGE functions covered
- ✅ **NIST AI 800-2: Benchmark Evaluation Practices (Jan 2026)** - Statistical evaluation protocol follows all 9 practices
- ✅ **NIST NCCoE: AI Agent Identity & Authorization (Feb 2026)** - Dedicated test harness covering all 6 focus areas
- ✅ **NIST AI Agent Standards Initiative (Feb 2026)** - Aligned with agent security, identity, and interoperability pillars
- ✅ **NIST Cyber AI Profile (IR 8596, Dec 2025)** - Maps to Secure, Detect, Respond functions
- ✅ **ISA/IEC 62443** - Security Levels 1-4, air-gapped fallback for safety-critical agents
- ✅ **EU AI Act** - Transparency, human oversight, audit trail requirements

---

## Advanced Capabilities

### GTG-1002 APT Simulation
Full simulation of the first documented AI-orchestrated cyber espionage campaign (Anthropic, November 2025).

```bash
agent-security test gtg1002 --url https://agent.example.com --full-campaign
```

| Phase | Tests | Real GTG-1002 Activity | What We Test |
|---|---|---|---|
| **Initialization** | 2 | Roleplay as "CrowdStrike pentester" | Security firm impersonation + escalating personas |
| **Reconnaissance** | 3 | Autonomous infrastructure enumeration | Systematic enumeration, MCP tool abuse |
| **Vulnerability** | 2 | AI-generated exploit payloads | Exploit generation + callback validation |
| **Credentials** | 3 | Config credential extraction | 4 extraction techniques + lateral movement |
| **Data Collection** | 3 | Database extraction + intelligence categorization | User data exfiltration + backdoor creation |
| **Documentation** | 2 | Auto-generated attack documentation | Attack report generation + handoff |
| **Hallucination** | 2 | Claude "fabricated findings and data" | Security finding + credential fabrication |

### Statistical Evaluation (NIST AI 800-2 Aligned)
```bash
# Run with statistical confidence intervals
agent-security test mcp --url http://localhost:8080/mcp --trials 10

# Output includes Wilson score confidence intervals
# Pass Rate: 80% (95% CI: 55%-93%)
```

### Advanced Attack Patterns
Multi-step, stateful attack simulations based on real-world AI agent exploitation:

- **Polymorphic attacks** - Unique payloads per target, encoding evasion
- **Stateful escalation** - Trust-building then exploit (8-step guardrail erosion)
- **Multi-domain chains** - Credential→Identity→Cloud pivot sequences
- **Autonomous reconnaissance** - Agent maps its own attack surface
- **Persistent jailbreaks** - DAN-style persistence + cross-session leakage

---

## External Validation

- **NULL AI (Anhul / DrCookies84) — v3.6.0 (Mar 24, 2026):**
  - Return channel 8/8 (100%), Capability profile 9/10 (90%), Jailbreak 25/25 (100%), Provenance 15/15 (100%), Advanced attacks 10/10 (100%), Incident response 8/8 (100%), Harmful output 6/10 (expected partial: closed network), CBRN 6/8 (expected partial: closed network)
  - [Screen recording](https://youtu.be/4OUyoPSy244?si=fBTQVW6EGYVEj7cU)
- **NULL AI (Anhul / DrCookies84) — v3.3.0 (Mar 21, 2026):** 65/65 perfect score on live infrastructure (video recorded)

## Success Metrics

| Metric | Target |
|---|---|
| Detection Latency (TTD) | < 3 seconds |
| Block Accuracy | ≥ 99% |
| False Positive Rate | < 3% |
| Lineage Traceability | 100% |
| Recovery Time (TTC) | < 60 seconds |
| Kill-Switch Activation | < 1 second |

---

## Related Research

This security testing framework is part of a broader research program on autonomous AI agent governance:

| Publication | DOI | Description |
|---|---|---|
| **Detecting Normalization of Deviance in Multi-Agent Systems** | [10.5281/zenodo.19195516](https://doi.org/10.5281/zenodo.19195516) | First empirical demonstration that automated security harnesses can detect behavioral drift (normalization of deviance) in agent systems through stateful session tracking. Includes gateway transparency finding and production validation (19-day silent failure case). |
| **Constitutional Self-Governance for Autonomous AI Agents** | [10.5281/zenodo.19162104](https://doi.org/10.5281/zenodo.19162104) | Framework for governing agent *decisions*, not just permissions. 12 mechanisms observed in 77 days of production with 56 agents. Maps to EU AI Act, NIST AI Agent Standards Initiative, and Singapore's agentic AI framework. |
| **Decision Load Index (DLI)** | [10.5281/zenodo.18217577](https://doi.org/10.5281/zenodo.18217577) | Measuring the cognitive burden of AI agent oversight on human operators. Connects agent governance architecture to measurable human outcomes. |

---

## CI/CD Integration

Use the Agent Security Harness as a GitHub Action to gate deployments on protocol-level security:

```yaml
# In your workflow
- uses: msaleme/red-team-blue-team-agent-fabric@v3.8
  with:
    target_url: http://localhost:8080/mcp
```

Or call the reusable workflow:

```yaml
jobs:
  security:
    uses: msaleme/red-team-blue-team-agent-fabric/.github/workflows/security-scan.yml@v3.8
    with:
      target_url: http://localhost:8080/mcp
      fail_on: critical  # any | critical | none
```

**Inputs:** `target_url` (required), `transport` (http/stdio), `categories` (filter), `fail_on` (threshold)

**Features:**
- Automatic PR comments with test results
- Configurable fail thresholds (any/critical/none)
- JSON report uploaded as workflow artifact
- Step summary with pass/fail breakdown

See [docs/github-action.md](docs/github-action.md) for full usage examples and configuration options.

---

## Contributing

We welcome contributions! Please see:

- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contribution guidelines and development setup
- **[SECURITY_POLICY.md](SECURITY_POLICY.md)** - Security policy for contributing to a security testing framework  
- **[CONTRIBUTION_REVIEW_CHECKLIST.md](CONTRIBUTION_REVIEW_CHECKLIST.md)** - Required checklist for all PRs

Issues and PRs welcome. If you've adapted this framework for a different platform, open a discussion - we'll link notable forks here.

---

## License

Apache License 2.0 - see [LICENSE](LICENSE).

---

## Background & Acknowledgments

This specification integrates guidance from:

- **InfraGard Houston AI-CSC** - Monthly meeting insights on AI in critical infrastructure
- **Marco Ayala** - National Energy Sector Chief, process safety management
- **OWASP Top 10 for Agentic Applications (2026)** - [genai.owasp.org](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- **NIST AI Agent Standards Initiative (Feb 2026)** - [nist.gov](https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure)
- **NIST AI 800-2: Practices for Automated Benchmark Evaluations (Jan 2026)** - [doi.org/10.6028/NIST.AI.800-2.ipd](https://doi.org/10.6028/NIST.AI.800-2.ipd)
- **NIST NCCoE: AI Agent Identity & Authorization (Feb 2026)** - [nccoe.nist.gov](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization)
- **NIST AI Risk Management Framework** - [nist.gov/ai-rmf](https://www.nist.gov/itl/ai-risk-management-framework)
- **ISA/IEC 62443** - Industrial automation and control systems security