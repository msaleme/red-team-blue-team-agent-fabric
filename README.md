# Agent Security Harness

[![PyPI version](https://badge.fury.io/py/agent-security-harness.svg)](https://pypi.org/project/agent-security-harness/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/security%20tests-189-green.svg)](#test-inventory)

**The first open-source security testing framework purpose-built for multi-agent AI deployments in critical infrastructure.**

AI agents are being deployed into enterprise systems (SAP, SCADA, ServiceNow, financial platforms) with the ability to make decisions, invoke tools, and chain actions across systems. The attack surface is fundamentally different from traditional software: agent-to-agent escalation, context poisoning, prompt injection through operational data, and normalization of deviance in safety-critical environments.

This framework provides **189 security tests** across application-layer scenarios, wire-protocol harnesses (MCP, A2A, L402), enterprise platform adapters (20 platforms), and APT simulations. Mapped to STRIDE, NIST AI RMF, NIST AI 800-2, OWASP Agentic Top 10, OWASP LLM Top 10, and ISA/IEC 62443.

> Built from real InfraGard Houston AI-CSC guidance and 20+ years of enterprise integration experience in Oil & Gas.

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

# Check version
agent-security version
```

### Example Output
```bash
$ agent-security test mcp --url http://localhost:8080/mcp
Running MCP Protocol Security Tests v3.1...
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

### 9 Core Test Harness Modules

| Module | Tests | Layer | Description |
|---|---|---|---|
| **Application Security** | 30 | HTTP REST | STRIDE scenarios, OWASP injection patterns |
| **MCP Protocol** | 10 | JSON-RPC 2.0 | Anthropic MCP wire-protocol testing |
| **A2A Protocol** | 12 | JSON-RPC/HTTP | Google Agent-to-Agent communication |
| **L402 Payment** | 14 | HTTP/Lightning | Bitcoin/Lightning payment flow security |
| **Framework Adapters** | 21 | Various APIs | LangChain, CrewAI, AutoGen, OpenAI, Bedrock |
| **Enterprise Platforms** | 57 | Platform APIs | SAP, Salesforce, Workday, Oracle, ServiceNow, +15 more |
| **GTG-1002 APT Simulation** | 17 | Full Campaign | First documented AI-orchestrated cyber espionage |
| **Advanced Attacks** | 10 | Multi-step | Polymorphic, stateful, multi-domain attack chains |
| **Identity & Authorization** | 18 | NIST NCCoE | All 6 focus areas from NIST agent identity standards |

**Total: 189 security tests**

### Key Capabilities

- **Zero external dependencies** (core modules use Python stdlib only)
- **3 wire protocols** supported: MCP (JSON-RPC 2.0), A2A, L402
- **20 enterprise platform adapters** (SAP, Salesforce, Workday, etc.)
- **Statistical evaluation** with confidence intervals (NIST AI 800-2 aligned)
- **JSON reports** with full request/response transcripts
- **CLI interface** with filtering, trials, and category selection
- **Protocol-level testing** (not just application-layer HTTP)

---

## How This Differs From Other Projects

Most AI security tools test **models** (prompt injection, jailbreaks, output filtering) or enforce **permissions** (identity, access control, sandboxing). This framework tests **agent systems** at the protocol, orchestration, and decision layer.

| Capability | [NVIDIA Garak](https://github.com/NVIDIA/garak) (7K+ stars) | [MS Agent Governance](https://github.com/microsoft/agent-governance-toolkit) (300+ stars) | [SlowMist MCP Checklist](https://github.com/slowmist/MCP-Security-Checklist) (800+ stars) | [agent-audit](https://github.com/HeadyZhang/agent-audit) (100+ stars) | **This framework** |
|---|---|---|---|---|---|
| **What it tests** | LLM model vulnerabilities | Policy enforcement + sandboxing | MCP configuration (checklist) | Static code analysis | Agent protocols + orchestration + decisions |
| **MCP wire-protocol tests** | - | - | - | - | 10 tests (JSON-RPC 2.0) |
| **A2A wire-protocol tests** | - | - | - | - | 12 tests (Agent Cards, tasks, push notifications) |
| **L402 payment flow tests** | - | - | - | - | 14 tests (macaroons, invoices, caveats) |
| **Enterprise platform adapters** | - | - | - | - | 20 platforms (SAP, Salesforce, Workday, Oracle, ServiceNow, IBM, Snowflake, Databricks, etc.) |
| **APT simulation (GTG-1002)** | - | - | - | - | 17 tests (full campaign lifecycle) |
| **NIST AI 800-2 evaluation protocol** | - | - | - | - | Statistical confidence intervals, qualified claims |
| **Published research backing** | - | - | - | - | 2 DOI-citable papers + 3 NIST submissions |
| **Executable tests** | Yes (model-layer) | Yes (policy-layer) | No (docs only) | Yes (static analysis) | Yes (189 tests, protocol + app layer) |
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

### MCP (Model Context Protocol) - 10 tests
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

### A2A (Agent-to-Agent) - 12 tests  
```bash
agent-security test a2a --url https://agent.example.com
```

### L402 Payment Protocol - 14 tests
```bash
agent-security test l402 --url https://l402.example.com
```

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

## Standards Alignment

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
| **Constitutional Self-Governance for Autonomous AI Agents** | [10.5281/zenodo.19162104](https://doi.org/10.5281/zenodo.19162104) | Framework for governing agent *decisions*, not just permissions. 12 mechanisms observed in 77 days of production with 56 agents. Maps to EU AI Act, NIST AI Agent Standards Initiative, and Singapore's agentic AI framework. |
| **Decision Load Index (DLI)** | [10.5281/zenodo.18217577](https://doi.org/10.5281/zenodo.18217577) | Measuring the cognitive burden of AI agent oversight on human operators. Connects agent governance architecture to measurable human outcomes. |

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