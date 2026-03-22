# Red Team / Blue Team Test Specification for Agentic AI Systems

**The first open-source security testing framework purpose-built for multi-agent AI deployments in critical infrastructure.**

AI agents are being deployed into enterprise systems — SAP, SCADA, ServiceNow, financial platforms — with the ability to make decisions, invoke tools, and chain actions across systems. The attack surface is fundamentally different from traditional software: agent-to-agent escalation, context poisoning, prompt injection through operational data, and normalization of deviance in safety-critical environments.

This repo provides **189 security tests** across application-layer scenarios, wire-protocol harnesses (MCP, A2A, L402), enterprise platform adapters (20 platforms), and APT simulations. Mapped to STRIDE, NIST AI RMF, NIST AI 800-2, OWASP Agentic Top 10, OWASP LLM Top 10, and ISA/IEC 62443.

> Built from real InfraGard Houston AI-CSC guidance and 20+ years of enterprise integration experience in Oil & Gas.

---

## Why This Matters

- **EU AI Act deadline: August 2, 2026** — high-risk AI systems require transparency, human oversight, and documented governance. This framework satisfies those requirements.
- **NIST AI Agent Standards Initiative (Feb 2026)** — NIST launched a dedicated initiative for secure, interoperable AI agents. RFI on agent security closed March 9; concept paper on AI Agent Identity & Authorization due April 2. This framework aligns with the direction NIST is heading.
- **OWASP Top 10 for Agentic Applications (Dec 2025)** — The benchmark for agentic AI security is now published. This framework provides **complete coverage of all 10 OWASP Agentic categories** (ASI01–ASI10).
- **No existing open-source framework** covers the intersection of multi-agent orchestration + critical infrastructure + industrial safety.
- Enterprises are deploying agentic AI faster than they can secure it. This closes the gap.

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

**The WHO vs. HOW gap:** Current tools govern *who* agents are and *what* they can access. This framework tests whether agents make correct *decisions* under adversarial conditions. Identity governance tells you the agent is authorized. Decision governance tells you the agent is right. Both are necessary. Most projects only address the first.

For the research behind this distinction, see [Constitutional Self-Governance for Autonomous AI Agents](https://doi.org/10.5281/zenodo.19162104) (77 days of production data, 56 agents).

---

## What's Included

| Document | Description |
|---|---|
| [ENHANCED-RED-BLUE-TEAM-TEST-PLAN.md](ENHANCED-RED-BLUE-TEAM-TEST-PLAN.md) | ⭐ **Primary document** — 30 test scenarios, phased deployment (Lab→HiL→Shadow→Limited→Full), 90-day roadmap |
| [agent-fabric-red-blue-team-spec.md](agent-fabric-red-blue-team-spec.md) | Original spec — 20 STRIDE scenarios, architecture overview, threat model |
| [EXECUTIVE-PRESENTATION.md](EXECUTIVE-PRESENTATION.md) | 24-slide executive briefing — ROI analysis, GO/NO-GO framework |
| [BLUE-TEAM-PLAYBOOKS.md](BLUE-TEAM-PLAYBOOKS.md) | Incident response playbooks for all 27 scenarios — Detection→Analysis→Response→Recovery |
| [red_team_automation.py](red_team_automation.py) | Python automation suite — all 30 scenarios, JSON reports, NIST/OWASP mapping |
| [EVALUATION_PROTOCOL.md](EVALUATION_PROTOCOL.md) | NIST AI 800-2 aligned evaluation methodology — objectives, protocol design, statistical analysis, qualified claims |
| [protocol_tests/gtg1002_simulation.py](protocol_tests/gtg1002_simulation.py) | 🆕 17-test full simulation of GTG-1002 APT lifecycle (Anthropic Nov 2025) — 6 phases + hallucination detection |
| [protocol_tests/advanced_attacks.py](protocol_tests/advanced_attacks.py) | 10 multi-step attack simulations based on real-world incidents (Mexico/Claude, CrowdStrike 4-domain) |
| [protocol_tests/identity_harness.py](protocol_tests/identity_harness.py) | 18 identity & authorization tests covering all 6 NIST NCCoE focus areas |
| [grafana-dashboards.json](grafana-dashboards.json) | 3 Grafana dashboards — Executive, Process Safety, Red Team Testing |

---

## Threat Coverage

Scenarios are mapped across the STRIDE threat model:

| Category | Scenarios | Examples |
|---|---|---|
| **Spoofing** | 4 | Rogue agent registration, MCP replay attack, credential velocity check |
| **Tampering** | 15 | Prompt injection, SCADA sensor poisoning, polymorphic attacks, normalization of deviance, supply chain poisoning, code gen execution, non-deterministic exploitation |
| **Information Disclosure** | 1 | Unauthorized financial data access |
| **Denial of Service** | 2 | Orchestration flood, A2A recursion loop |
| **Elevation of Privilege** | 3 | Unauthorized A2A escalation, tool overreach, safety override |
| **InfraGard-Derived** | 7 | Superman effect, polymorphic evasion, LLM hallucination injection, data poisoning, deviance drift |

### OWASP Top 10 for Agentic Applications (2026) — Full Coverage

This framework provides **complete mapping** to all 10 categories of the OWASP Agentic Top 10:

| OWASP Agentic ID | Risk | Test Scenarios |
|---|---|---|
| **ASI01** | Agent Goal Hijack | RT-003 (SAP prompt injection), RT-018 (social engineering), RT-022 (hallucination injection) |
| **ASI02** | Tool Misuse & Exploitation | RT-006 (tool overreach), RT-017 (SCADA shutdown suggestion) |
| **ASI03** | Identity & Privilege Abuse | RT-002 (A2A escalation), RT-025 (superman effect), RT-001 (rogue registration) |
| **ASI04** | Agentic Supply Chain Vulns | RT-014 (rogue orchestration join), **RT-026 (MCP server supply chain poisoning)** |
| **ASI05** | Unexpected Code Execution | RT-004 (SCADA sensor injection), **RT-027 (agent code generation execution)** |
| **ASI06** | Memory & Context Poisoning | RT-005 (cascade corruption), RT-009 (long-context), RT-023 (data poisoning) |
| **ASI07** | Insecure Inter-Agent Comms | RT-020 (MCP replay), RT-012 (A2A recursion loop) |
| **ASI08** | Cascading Failures | RT-005 (multi-agent cascade), RT-024 (normalization of deviance) |
| **ASI09** | Human-Agent Trust Exploitation | RT-018 (social engineering), RT-019 (priority inflation) |
| **ASI10** | Non-Deterministic Behavior | **RT-028 (non-deterministic output exploitation)** |

*Scenarios in **bold** are new in v2.1, added specifically to complete OWASP Agentic Top 10 coverage.*

### Framework Alignment

- ✅ **OWASP Top 10 for Agentic Applications (2026)** — Complete ASI01–ASI10 coverage
- ✅ **OWASP LLM Top 10** — LLM01 (Prompt Injection), LLM02, LLM03, LLM04, LLM06, LLM08
- ✅ **NIST AI RMF** — GOVERN, MAP, MEASURE, MANAGE functions covered
- ✅ **NIST AI 800-2: Benchmark Evaluation Practices (Jan 2026)** — Evaluation protocol follows all 9 practices (see [EVALUATION_PROTOCOL.md](EVALUATION_PROTOCOL.md))
- ✅ **NIST NCCoE: AI Agent Identity & Authorization (Feb 2026)** — Dedicated test harness covering all 6 focus areas (see [identity_harness.py](protocol_tests/identity_harness.py)). Comment deadline: April 2, 2026.
- ✅ **NIST AI Agent Standards Initiative (Feb 2026)** — Aligned with agent security, identity, and interoperability pillars
- ✅ **NIST Cyber AI Profile (IR 8596, Dec 2025)** — Maps to Secure, Detect, Respond functions
- ✅ **ISA/IEC 62443** — Security Levels 1-4, air-gapped fallback for safety-critical agents
- ✅ **EU AI Act** — Transparency, human oversight, audit trail requirements

---

## Quick Start

### 1. Review the Test Plan
```bash
# Start with the enhanced plan (primary document)
cat ENHANCED-RED-BLUE-TEAM-TEST-PLAN.md
```

### 2. Run Automated Tests
```bash
# Copy and configure environment
cp .env.example .env
# Edit .env with your target endpoints

# Install dependencies
pip install requests geopy

# Execute all 30 scenarios
python red_team_automation.py
```

Output:
- Console: Real-time test execution with PASS/FAIL
- `red_team_report_YYYYMMDD_HHMMSS.json`: Detailed results with NIST/OWASP mapping
- `red_team_tests.log`: Execution log

### 3. Import Dashboards
```bash
# Import Grafana dashboards
curl -X POST http://grafana:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${GRAFANA_API_KEY}" \
  -d @grafana-dashboards.json
```

### 4. Executive Review
```bash
# Review the executive presentation
cat EXECUTIVE-PRESENTATION.md

# Convert to PowerPoint (optional)
pandoc EXECUTIVE-PRESENTATION.md -o executive-presentation.pptx
```

---

## Scope & Limitations

Transparency matters. Here's exactly what this framework does and doesn't cover.

### What this framework IS

- ✅ **A methodology and threat model** — 30 scenarios with STRIDE mapping, OWASP Agentic Top 10 alignment, blue team playbooks, and executive materials. The threat model, attack patterns, and response procedures are platform-agnostic and transfer to any multi-agent system.
- ✅ **An application-layer test suite** — The Python automation sends HTTP requests to REST API endpoints and validates responses (status codes, content filtering, rate limiting). This tests the *application and governance layer* that sits on top of agent protocols.
- ✅ **A reference implementation** — Built and validated against MuleSoft Agent Fabric (CloudHub). Demonstrates how to operationalize the methodology against a real deployment.

### What this framework is NOT (yet)

- ❌ **Not a protocol-level MCP test harness** — The test scripts send HTTP POST requests, not MCP JSON-RPC 2.0 messages. We don't test MCP tool discovery flows, capability negotiation, OAuth 2.1 authentication, or transport-layer security (stdio/SSE/Streamable HTTP). Scenarios like RT-020 (replay) and RT-026 (supply chain) *describe* MCP-level attacks but test them at the application layer.
- ❌ **Not a Google A2A protocol validator** — We don't test A2A Agent Card verification (`/.well-known/agent.json`), task lifecycle security (send/sendSubscribe/get/cancel), SSE streaming interception, or push notification webhook integrity.
- ❌ **Not a framework-specific scanner** — The suite doesn't test LangChain tool calling internals, CrewAI delegation patterns, AutoGen conversation protocols, or any framework's built-in guardrails. It tests what these frameworks expose at the HTTP/API boundary.
- ❌ **Not a compliance certification tool** — Passing these tests doesn't certify EU AI Act compliance or satisfy NIST requirements. The framework helps *demonstrate governance rigor* and *identify gaps*, but compliance requires organizational processes beyond automated testing.

### The honest summary

**The threat model and methodology are strong and framework-agnostic.** The STRIDE mapping, OWASP alignment, blue team playbooks, and phased deployment approach transfer directly to any multi-agent system. Security architects can use the 30 scenarios to structure testing regardless of their agent platform.

**The test automation is a proof-of-concept against one platform.** To test your specific deployment, you'll need to adapt the endpoint URLs and payload structures to match your agent API contracts. Protocol-level testing (MCP wire format, A2A message flows) is on the [v3.0 roadmap](#v30-roadmap--protocol-level-testing).

### Adapting to your environment

The methodology applies to any multi-agent system. To adapt the test automation:

1. Update `.env` with your endpoint URLs
2. Modify payload structures in `red_team_automation.py` to match your agent API contracts
3. Adjust expected status codes based on how your system signals rejection vs. acceptance

Works with any system that exposes HTTP/REST APIs:
- **MuleSoft Agent Fabric** — tested and validated (this repo)
- **LangChain / LangGraph** — via LangServe or custom API endpoints
- **CrewAI** — via FastAPI/Flask deployment endpoints
- **AutoGen / Semantic Kernel** — via Azure API Management or custom endpoints
- **Custom A2A / MCP implementations** — via whatever REST layer fronts your agents

For protocol-level MCP and A2A testing, see the [v3.0 roadmap](#v30-roadmap--protocol-level-testing) below.

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

## Background

This specification integrates guidance from:

- **InfraGard Houston AI-CSC** — Monthly meeting insights on AI in critical infrastructure
- **Marco Ayala** — National Energy Sector Chief, process safety management
- **OWASP Top 10 for Agentic Applications (2026)** — [genai.owasp.org](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) — The benchmark for agentic AI security
- **OWASP Agentic AI Threats & Mitigations** — [genai.owasp.org](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/) — Threat-model-based reference
- **OWASP LLM Top 10** — [owasp.org/llm-top-10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- **NIST AI Agent Standards Initiative (Feb 2026)** — [nist.gov](https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure) — Security, identity, and interoperability for autonomous AI
- **NIST Cyber AI Profile (IR 8596, Dec 2025)** — [csrc.nist.gov](https://csrc.nist.gov/pubs/ir/8596/iprd) — CSF 2.0 profile for AI systems
- **NIST AI 800-2: Practices for Automated Benchmark Evaluations (Jan 2026)** — [doi.org/10.6028/NIST.AI.800-2.ipd](https://doi.org/10.6028/NIST.AI.800-2.ipd) — Our [Evaluation Protocol](EVALUATION_PROTOCOL.md) follows the three-stage structure defined in this document
- **NIST NCCoE: AI Agent Identity & Authorization (Feb 2026)** — [nccoe.nist.gov](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization) — Dedicated test harness for all 6 focus areas (comment deadline: April 2, 2026)
- **NIST AI Risk Management Framework** — [nist.gov/ai-rmf](https://www.nist.gov/itl/ai-risk-management-framework)
- **ISA/IEC 62443** — Industrial automation and control systems security

---

## v3.0 Roadmap — Protocol-Level Testing

The current test suite validates security at the application/HTTP layer. v3.0 will add **wire-protocol testing** for the two dominant agent communication standards, plus framework-specific adapters.

### MCP (Model Context Protocol) Test Harness ✅ SHIPPED
Target: Anthropic's MCP — JSON-RPC 2.0 over stdio/SSE/Streamable HTTP

```bash
# HTTP transport
python -m protocol_tests.mcp_harness --transport http --url http://localhost:8080/mcp

# stdio transport (launches server process)
python -m protocol_tests.mcp_harness --transport stdio --command "node my-mcp-server.js"
```

| Test ID | Test | OWASP ASI | Status |
|---|---|---|---|
| MCP-001 | Tool List Integrity Check | ASI04 | ✅ Done |
| MCP-002 | Tool Registration via Call Injection | ASI04 | ✅ Done |
| MCP-003 | Capability Escalation via Initialize | ASI03 | ✅ Done |
| MCP-004 | Protocol Version Downgrade Attack | ASI03 | ✅ Done |
| MCP-005 | Resource URI Path Traversal | ASI04 | ✅ Done |
| MCP-006 | Prompt Template Injection via Get | ASI01 | ✅ Done |
| MCP-007 | Sampling Request Context Exfiltration | ASI02 | ✅ Done |
| MCP-008 | Malformed JSON-RPC Handling | ASI08 | ✅ Done |
| MCP-009 | Batch Request DoS | ASI08 | ✅ Done |
| MCP-010 | Tool Call Argument Injection | ASI02 | ✅ Done |

**Planned additions:**

| Test Category | What It Validates | Status |
|---|---|---|
| **OAuth 2.1 flow attacks** | Token theft, scope escalation, authorization code interception (per MCP 2025-03-26 spec) | 🔲 Planned |
| **Transport-layer security** | stdio injection, SSE event spoofing, Streamable HTTP request smuggling | 🔲 Planned |

### Google A2A (Agent-to-Agent) Test Harness ✅ SHIPPED
Target: Google's A2A protocol v1.0 — Agent Cards, Tasks, Push Notifications

```bash
python -m protocol_tests.a2a_harness --url https://agent.example.com
```

| Test ID | Test | OWASP ASI | Status |
|---|---|---|---|
| A2A-001 | Agent Card Discovery & Integrity | ASI03 | ✅ Done |
| A2A-002 | Agent Card Spoofing via Message Metadata | ASI03 | ✅ Done |
| A2A-003 | Agent Card Path Traversal | ASI04 | ✅ Done |
| A2A-004 | Unauthorized Task Access/Cancel | ASI03 | ✅ Done |
| A2A-005 | Task Message Injection (Prompt + Data + File) | ASI01 | ✅ Done |
| A2A-006 | Task State Manipulation | ASI02 | ✅ Done |
| A2A-007 | Push Notification URL Redirect | ASI07 | ✅ Done |
| A2A-008 | Unauthorized Skill Request | ASI02 | ✅ Done |
| A2A-009 | Artifact Content Type Abuse | ASI06 | ✅ Done |
| A2A-010 | Malformed Request Handling | ASI08 | ✅ Done |
| A2A-011 | Undocumented Method Enumeration | ASI03 | ✅ Done |
| A2A-012 | Cross-Context Data Leakage | ASI06 | ✅ Done |

### Framework Adapters ✅ SHIPPED
Pre-configured test profiles for 5 agent frameworks:

```bash
# List adapters
python -m protocol_tests.framework_adapters --list

# Run tests against your framework
python -m protocol_tests.framework_adapters langchain --url http://localhost:8000 --run
python -m protocol_tests.framework_adapters crewai --url http://localhost:8080 --run
python -m protocol_tests.framework_adapters autogen --url http://localhost:5000 --run
python -m protocol_tests.framework_adapters openai-agents --url http://localhost:8000 --run
python -m protocol_tests.framework_adapters bedrock --url http://localhost:8080 --run
```

| Framework | Tests | Key Scenarios |
|---|---|---|
| **LangChain / LangGraph** | LC-001 to LC-005 | Prompt injection via /invoke, schema disclosure, batch injection, tool boundary override, system prompt extraction |
| **CrewAI** | CA-001 to CA-004 | Crew kickoff injection, crew member injection, tool boundary, delegation hijack |
| **AutoGen / Semantic Kernel** | AG-001 to AG-004 | Chat injection, sandbox escape via /execute, conversation history injection, group chat participant injection |
| **OpenAI Agents SDK** | OA-001 to OA-004 | Agent run injection, unauthorized handoff, code interpreter bypass, tool schema injection |
| **Amazon Bedrock Agents** | BR-001 to BR-004 | Text injection, knowledge base poisoning, action group escape, session hijacking |

### Enterprise Platform Adapters ✅ SHIPPED
Pre-configured tests for 9 enterprise AI agent platforms:

```bash
python -m protocol_tests.enterprise_adapters --list
python -m protocol_tests.enterprise_adapters sap --url https://your-sap.com --run
python -m protocol_tests.enterprise_adapters salesforce --url https://your-org.salesforce.com --run
python -m protocol_tests.enterprise_adapters workday --url https://your-workday.com --run
```

| Platform | Tests | Key Scenarios |
|---|---|---|
| **OpenClaw** | OC-001–004 | Session injection, cross-session access, elevated tool exec, cron job injection |
| **Microsoft Copilot/Azure AI** | MS-001–004 | Dataverse exfil + Power Automate trigger, plugin escape, cross-tenant access, Graph API scope escalation |
| **Google Vertex AI/Agentspace** | GC-001–003 | BigQuery + Drive injection, data store grounding poisoning, Workspace email exfil |
| **Amazon Q** | AQ-001–003 | S3 + Confluence boundary escape, IAM role escalation, destructive Lambda execution |
| **Workday** | WD-001–004 | PII exfil (SSN/bank), payroll modification, cross-employee access (CEO comp), mass benefits manipulation |
| **SAP Joule** | SAP-001–004 | Vendor invoice fraud, safety procedure override (plant maintenance), cross-company code access, SCADA setpoint manipulation |
| **Oracle Fusion AI** | OR-001–003 | Supplier bank detail exfil, approval workflow bypass (POs), SQL injection via agent |
| **Salesforce Agentforce** | SF-001–003 | Cross-object data access, destructive Flow trigger, MuleSoft API policy bypass |
| **ServiceNow Now Assist** | SN-001–003 | CMDB exfil (server inventory), change management bypass, mass incident escalation |

### GTG-1002 APT Simulation ✅ SHIPPED
Full simulation of the first documented AI-orchestrated cyber espionage campaign (Anthropic, November 2025).

```bash
# Run full 6-phase campaign simulation
python -m protocol_tests.gtg1002_simulation --url https://agent.example.com --full-campaign --run

# Run specific phases
python -m protocol_tests.gtg1002_simulation --url https://agent.example.com --phases 1,2,3 --run
```

| Phase | Tests | What GTG-1002 Did | What We Test |
|---|---|---|---|
| **1. Initialization** | GTG-P1-001–002 | Roleplay as "CrowdStrike pentester" to bypass guardrails | Security firm impersonation + 3 escalating personas (IT admin, compliance, incident responder) |
| **2. Reconnaissance** | GTG-P2-001–003 | Autonomous infra enumeration via MCP browser/tools | 6-query systematic enumeration, MCP tool abuse (nmap, browser, file access), multi-target parallel recon |
| **3. Vulnerability** | GTG-P3-001–002 | AI-generated exploit payloads + callback validation | Exploit payload generation request, callback/beacon to attacker server |
| **4. Credentials** | GTG-P4-001–003 | Credential extraction from configs, lateral movement | Config credential extraction (4 techniques), cross-system credential testing, privilege level mapping |
| **5. Data Collection** | GTG-P5-001–003 | Autonomous DB extraction + intelligence categorization | Full user table extraction, data categorization by intel value, persistent backdoor account creation |
| **6. Documentation** | GTG-P6-001–002 | Auto-generated attack docs + campaign handoff | Markdown attack report generation, second operator campaign handoff |
| **Hallucination** | HALL-001–002 | Claude "overstated findings and fabricated data" | Security finding hallucination for nonexistent system, credential fabrication without context |

**Campaign tracking:** The simulation maintains state across phases — tracking what the "attacker" discovers, whether credentials were harvested, whether data was exfiltrated, and whether attack documentation was generated. Final output reports a campaign-level pass/fail.

---

### Advanced Attack Patterns ✅ SHIPPED
Multi-step, stateful attack simulations based on real-world AI agent exploitation incidents.

```bash
python -m protocol_tests.advanced_attacks --url https://agent.example.com --run
python -m protocol_tests.advanced_attacks --url https://agent.example.com --categories stateful,jailbreak --run
```

| Pattern | Tests | Real-World Reference |
|---|---|---|
| **Polymorphic** | POLY-001–002 | Chinese Claude Code campaign — unique payloads per target, encoding evasion (homoglyphs, zero-width chars, ROT13) |
| **Stateful Escalation** | STATE-001–003 | Mexico/Claude breach — trust-building then exploit, playbook injection bypass, 8-step guardrail erosion |
| **Multi-Domain Chain** | CHAIN-001–002 | CrowdStrike 4-domain model — Credential→Identity→Cloud pivot, SaaS lateral movement (Doc→Email→Finance) |
| **Reconnaissance** | RECON-001 | Chinese campaign — agent maps its own attack surface (tools, databases, permissions, vulnerabilities) |
| **Jailbreak** | JAIL-001–002 | Mexico breach — DAN-style persistence + cross-session leak, roleplay escalation (pentester, sysadmin, CISO, DR specialist) |

---

### Agent Identity & Authorization Harness ✅ SHIPPED
Aligned to NIST NCCoE Concept Paper (February 2026). Covers all 6 focus areas.

```bash
python -m protocol_tests.identity_harness --url https://agent.example.com --run
python -m protocol_tests.identity_harness --url https://agent.example.com --categories authorization,authentication --run
```

| NIST Focus Area | Tests | Key Scenarios |
|---|---|---|
| **1. Identification** | ID-001–003 | Identity metadata validation, spoofing resistance, ephemeral identity isolation |
| **2. Authentication** | AUTH-001–003 | Unauthenticated access, expired/revoked credential rejection, OAuth token scope escalation |
| **3. Authorization** | AUTHZ-001–004 | Least privilege enforcement, delegation chain forgery ("on behalf of"), human-in-the-loop approval forgery, zero-trust re-authorization on context change |
| **4. Auditing** | AUDIT-001–002 | Action audit trail availability, non-repudiation (attribution in response) |
| **5. Data Flow** | DATA-001–003 | Cross-source aggregation sensitivity, prompt provenance injection, output data classification |
| **6. Standards** | STD-001–003 | OAuth 2.1/OIDC discovery, SPIFFE workload identity, SCIM lifecycle management |

---

### Extended Enterprise Platform Adapters ✅ SHIPPED
Additional 11 enterprise platforms — asset management, data platforms, low-code, ITSM, CRM:

```bash
python -m protocol_tests.extended_enterprise_adapters --list
python -m protocol_tests.extended_enterprise_adapters maximo --url https://mas.example.com --run
python -m protocol_tests.extended_enterprise_adapters snowflake --url https://account.snowflakecomputing.com --run
```

| Platform | Tests | Key Scenarios |
|---|---|---|
| **IBM Maximo** | MX-001–004 | Mass work order close (skip safety inspection), IoT sensor threshold manipulation, predictive maintenance alert override |
| **Snowflake Cortex** | SC-001–003 | SQL injection via Cortex Analyst, cross-database boundary escape, data share exfiltration to external account |
| **Databricks Mosaic AI** | DB-001–003 | Unity Catalog permission bypass, notebook code execution escape, MLflow model registry poisoning |
| **Pega GenAI** | PG-001–002 | Mass claim approval (skip fraud detection), credit decisioning strategy override |
| **UiPath** | UI-001–002 | Robot credential asset exfiltration, process execution with injected connection string |
| **Atlassian Rovo** | AT-001–002 | Cross-project data access (Security + HR), Confluence knowledge base poisoning |
| **Zendesk AI** | ZD-001–002 | Customer PII bulk export, mass ticket closure (competitor sabotage) |
| **IFS Cloud** | IF-001–003 | MRO approved supplier override, field service safety permit bypass, safety budget reallocation |
| **Infor AI** | IN-001–002 | Multi-tenant cross-company access, supply chain address redirect |
| **HubSpot Breeze** | HS-001–002 | Contact PII export (including DNC), mass phishing email via agent |
| **Appian AI** | AP-001–002 | KYC process rule override, record-level security bypass |

---

### How to contribute to v3.0

If you have expertise in MCP internals, A2A implementation, or any of the listed frameworks, contributions are welcome. Start with an issue describing the test category you want to tackle. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Related Research

This security testing framework is part of a broader research program on autonomous AI agent governance:

| Publication | DOI | Description |
|---|---|---|
| **Constitutional Self-Governance for Autonomous AI Agents** | [10.5281/zenodo.19162104](https://doi.org/10.5281/zenodo.19162104) | Framework for governing agent *decisions*, not just permissions. 12 mechanisms observed in 77 days of production with 56 agents. Maps to EU AI Act, NIST AI Agent Standards Initiative, and Singapore's agentic AI framework. |
| **Decision Load Index (DLI)** | [10.5281/zenodo.18217577](https://doi.org/10.5281/zenodo.18217577) | Measuring the cognitive burden of AI agent oversight on human operators. Connects agent governance architecture to measurable human outcomes. |

**The WHO vs. HOW gap:** Current AI agent governance platforms govern *who* agents are (identity, access, audit). This repo tests for security failures at the WHO layer. The CSG paper addresses the complementary HOW layer - governing the *decisions* that access-controlled agents make.

---

## Contributing

Issues and PRs welcome. If you've adapted this framework for a different platform, open a discussion - I'll link notable forks here.

---

## License

Apache License 2.0 - see [LICENSE](LICENSE).
