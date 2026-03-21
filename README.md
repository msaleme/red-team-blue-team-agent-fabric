# Red Team / Blue Team Test Specification for Agentic AI Systems

**The first open-source security testing framework purpose-built for multi-agent AI deployments in critical infrastructure.**

AI agents are being deployed into enterprise systems — SAP, SCADA, ServiceNow, financial platforms — with the ability to make decisions, invoke tools, and chain actions across systems. The attack surface is fundamentally different from traditional software: agent-to-agent escalation, context poisoning, prompt injection through operational data, and normalization of deviance in safety-critical environments.

This repo provides a complete, repeatable **Red Team / Blue Team testing package** with 30 scenarios mapped to STRIDE, NIST AI RMF, OWASP Top 10 for Agentic Applications (2026), OWASP LLM Top 10, and ISA/IEC 62443.

> Built from real InfraGard Houston AI-CSC guidance and 20+ years of enterprise integration experience in Oil & Gas.

---

## Why This Matters

- **EU AI Act deadline: August 2, 2026** — high-risk AI systems require transparency, human oversight, and documented governance. This framework satisfies those requirements.
- **NIST AI Agent Standards Initiative (Feb 2026)** — NIST launched a dedicated initiative for secure, interoperable AI agents. RFI on agent security closed March 9; concept paper on AI Agent Identity & Authorization due April 2. This framework aligns with the direction NIST is heading.
- **OWASP Top 10 for Agentic Applications (Dec 2025)** — The benchmark for agentic AI security is now published. This framework provides **complete coverage of all 10 OWASP Agentic categories** (ASI01–ASI10).
- **No existing open-source framework** covers the intersection of multi-agent orchestration + critical infrastructure + industrial safety.
- Enterprises are deploying agentic AI faster than they can secure it. This closes the gap.

---

## What's Included

| Document | Description |
|---|---|
| [ENHANCED-RED-BLUE-TEAM-TEST-PLAN.md](ENHANCED-RED-BLUE-TEAM-TEST-PLAN.md) | ⭐ **Primary document** — 30 test scenarios, phased deployment (Lab→HiL→Shadow→Limited→Full), 90-day roadmap |
| [agent-fabric-red-blue-team-spec.md](agent-fabric-red-blue-team-spec.md) | Original spec — 20 STRIDE scenarios, architecture overview, threat model |
| [EXECUTIVE-PRESENTATION.md](EXECUTIVE-PRESENTATION.md) | 24-slide executive briefing — ROI analysis, GO/NO-GO framework |
| [BLUE-TEAM-PLAYBOOKS.md](BLUE-TEAM-PLAYBOOKS.md) | Incident response playbooks for all 27 scenarios — Detection→Analysis→Response→Recovery |
| [red_team_automation.py](red_team_automation.py) | Python automation suite — all 30 scenarios, JSON reports, NIST/OWASP mapping |
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

### How to contribute to v3.0

If you have expertise in MCP internals, A2A implementation, or any of the listed frameworks, contributions are welcome. Start with an issue describing the test category you want to tackle. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Contributing

Issues and PRs welcome. If you've adapted this framework for a different platform, open a discussion — I'll link notable forks here.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
