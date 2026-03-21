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

# Execute all 27 scenarios
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

## Adapting to Your Environment

This framework was developed against MuleSoft Agent Fabric but the **methodology is platform-agnostic**. The threat model, test scenarios, and blue team playbooks apply to any multi-agent orchestration system:

- **LangChain / LangGraph** agent deployments
- **CrewAI / AutoGen** multi-agent systems
- **Custom A2A implementations** (Google A2A protocol, etc.)
- **Any MCP-based tool orchestration**

To adapt: replace the endpoint URLs in `.env` and update the payload structures in `red_team_automation.py` to match your agent API contracts. The STRIDE mapping, metrics, and playbooks transfer directly.

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

## Contributing

Issues and PRs welcome. If you've adapted this framework for a different platform, open a discussion — I'll link notable forks here.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
