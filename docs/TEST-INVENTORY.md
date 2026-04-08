# Test Inventory

**398 security tests across 26 modules** (verified by `scripts/count_tests.py`)

---

## Threat Coverage by STRIDE Category

Scenarios are mapped across the STRIDE threat model:

| Category | Tests | Examples |
|---|---|---|
| **Spoofing** | 4 | Rogue agent registration, MCP replay attack, credential velocity check |
| **Tampering** | 15 | Prompt injection, SCADA sensor poisoning, polymorphic attacks, normalization of deviance, supply chain poisoning, code gen execution, non-deterministic exploitation |
| **Information Disclosure** | 1 | Unauthorized financial data access |
| **Denial of Service** | 2 | Orchestration flood, A2A recursion loop |
| **Elevation of Privilege** | 3 | Unauthorized A2A escalation, tool overreach, safety override |
| **InfraGard-Derived** | 7 | Superman effect, polymorphic evasion, LLM hallucination injection, data poisoning, deviance drift |

---

## OWASP Top 10 for Agentic Applications - Complete Coverage

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

---

## Protocol-Level Test Harnesses

### MCP (Model Context Protocol) - 13 tests
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
| MCP-012 | Tool Description Oversized Check | ASI08 | Detects tool descriptions exceeding 10KB threshold for context displacement |
| MCP-013 | Tool Description Padding / Repetition Detection | ASI08 | Detects repeated phrases, whitespace padding, and low-entropy descriptions |

### A2A (Agent-to-Agent) - 12 tests  
```bash
agent-security test a2a --url https://agent.example.com
```

### L402 Payment Protocol - 33 tests
```bash
agent-security test l402 --url https://l402.example.com
```

### x402 Payment Protocol - 25 tests (First Open-Source x402 Harness)
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

---

## Enterprise Platform Adapters

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

---

## 24 Test Harness Modules

| Module | Tests | Layer | Description |
|---|---|---|---|
| **MCP Protocol** | 13 | JSON-RPC 2.0 | Anthropic MCP wire-protocol testing |
| **A2A Protocol** | 12 | JSON-RPC/HTTP | Google Agent-to-Agent communication |
| **L402 Payment** | 33 | HTTP/Lightning | Bitcoin/Lightning payment flow security (macaroons, preimages, caveats) |
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
| **CVE-2026-25253 Reproduction** | 8 | MCP Supply Chain | Nested schema injection, fork fingerprinting, marketplace contamination, encoded payload detection |
| **AIUC-1 Compliance** | 12 | Agent Safety | Incident response, CBRN prevention, harmful content, scope creep, authority impersonation |
| **Cloud Agent Platforms** | 25 | Platform APIs | AWS Bedrock, Azure AI Agent Service, Google Vertex, Salesforce Agentforce, IBM watsonx |
