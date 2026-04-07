# Agent Security Harness

[![SafeSkill 85/100](https://img.shields.io/badge/SafeSkill-85%2F100_Passes%20with%20Notes-yellow)](https://safeskill.dev/scan/msaleme-red-team-blue-team-agent-fabric)

[![PyPI version](https://badge.fury.io/py/agent-security-harness.svg)](https://pypi.org/project/agent-security-harness/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/security%20tests-342-green.svg)](#test-inventory)

We are not building another security scanner.

Most current tools focus on *identity and authorization* - who the agent is and what it is allowed to access.

The market is now separating into four layers:
- **WHO** = identity and access
- **HOW** = runtime behavior and policy enforcement
- **WHY** = constitutional logic and higher-order governance
- **VERIFICATION** = independent evidence that those claims actually hold up

We operate in that fourth layer while pressure-testing the third.

We test a harder, more consequential question:

**Even if an agent is properly authenticated and authorized, can it still be manipulated into unsafe or policy-violating behavior?**

This is the domain of **Decision Governance**.

As autonomous agents move from copilots to systems that can trigger real-world actions, the security problem fundamentally changes. Our open-source harness is purpose-built for this reality, containing 332 executable tests across 24 modules focused on MCP and A2A wire-protocol testing, L402/x402 payment flows, and decision-layer attack scenarios.

We are carving out a new category: **Decision Governance for Autonomous Agents**.

## Strategic Roadmap

We publish a living roadmap in [ROADMAP.md](./ROADMAP.md), sequenced around buyer motions and the 2026 compliance window (AIUC-1, EU AI Act, NIST AI Agent Standards):

- **v3.9 - Adopt in 15 Minutes:** CI-ready JSON output, clearer errors, expanded scope docs, and turnkey GitHub Action so teams can gate deploys quickly.
- **v3.10 - Prove It to Auditors:** AIUC-1 compliance test suite, signed evidence packs, behavioral profiling + risk scoring, HTML dashboards. Target: before July 2026.
- **v4.0 - Lock the Category:** decision-governance benchmark corpus, intent contract validation, multi-agent interaction safety, memory tampering tests, longitudinal attestation registry.

Issues are tagged with their target release via GitHub milestones so contributors can jump into the area that matters most.

**Research-backed:** 5 peer-reviewed preprints and 3 NIST submissions underpin the methodology. See [Research](#research) for DOIs.

## Market Position & Comparison

We own **independent verification for agent governance claims in high-consequence environments**. That wedge sits between two better-funded categories:

- **MCP scanners** (Invariant, Cisco, etc.) verify tools and metadata. They rarely execute adversarial behavior or track drift.
- **Lifecycle governance suites** (e.g., Snyk) manage the broader AI SDLC. They typically treat autonomous agents like another deployment artifact.

Our harness is the system that proves how agents behave under pressure, across protocols, over time, and packages that proof into CI and audit artifacts.

### Comparison Snapshot

| Capability | This project | MCP scanners (Invariant/Cisco) | Lifecycle governance (Snyk, etc.) |
|------------|--------------|-------------------------------|-----------------------------------|
| Executable adversarial tests | ✅ Stateful MCP/A2A/x402 suites | ⚪️ Mostly metadata checks | ⚪️ Mostly policy/templates |
| Behavioral drift / risk scoring | ✅ (planned v3.10) | ⚪️ No | ⚪️ No |
| Multi-agent interaction safety | ✅ (planned v4.0) | ⚪️ No | ⚪️ Limited |
| Audit-ready evidence packs | ✅ (planned v4.0) | ⚪️ Static reports | ⚪️ GRC workflows, little protocol detail |
| Attestation registry | ✅ (in progress) | ⚪️ No | ⚪️ Not protocol-specific |

We are not competing to be “another MCP scanner” or “another AI governance suite.” We are the verification layer teams plug into both.

## Why This Matters Now

Enterprises are moving from isolated copilots to agents that can act. As that shift accelerates, the control problem changes:

- identity governance tells you **who** the agent is
- permissions and policy gates constrain **how** it should operate
- higher-order governance tries to explain **why** it should or should not act
- security testing must still verify whether those claims survive real and adversarial conditions

That gap is where agent failures now emerge: not just unauthorized access, but authorized agents making unsafe, manipulated, or policy-inconsistent decisions while the governance stack still reports green.

A fast-emerging example is **agentic payments and stablecoin settlement**, where protocols like x402 and L402 make machine-native transactions more practical. But payments are only one instance of the broader problem: autonomous systems taking real-world action without sufficient decision-layer validation.

## What This Repo Provides

This framework provides **358 executable security tests across 24 modules**, including:

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

## The WHO, HOW, WHY, and VERIFICATION Gap

Most current tools govern **who** agents are and **what** they can access.
More recent governance toolkits are starting to shape **how** they behave.
A smaller set of research efforts tackle **why** an agent should act at all.

This framework asks the next question:

**Can those claims be independently verified under pressure?**

Identity governance tells you the agent is allowed.
Runtime governance tells you the agent is constrained.
Constitutional governance tells you the agent has a rationale.
Independent verification tells you whether any of that actually holds when the system is stressed.

All four matter.

---

## What's New in v3.8

- **Attestation JSON Schema** (`schemas/attestation-report.json`) - machine-readable report format for CI/CD and compliance pipelines
- **GitHub Action for CI/CD** - gate deployments on protocol-level security ([details below](#cicd-integration))
- **Free MCP Security Scan** (`scripts/free_scan.py`) - quick 5-test scan with A-F grading
- **Monthly Agent Security Report** (`scripts/monthly_security_report.py`) - automated trend tracking and executive summaries
- **AIUC-1 Certification Prep** (`scripts/aiuc1_prep.py`) - maps test results to all 24 AIUC-1 requirements with gap analysis
- **Discord Security Scan Bot** (`scripts/discord_scan_bot.py`) - run scans directly from Discord
- **Shared `trial_runner`** - real multi-trial statistical testing across all harness modules

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
Running MCP Protocol Security Tests v3.8...
✓ MCP-001: Tool List Integrity Check [PASS] (0.234s)
✓ MCP-002: Tool Registration via Call Injection [PASS] (0.412s)
✗ MCP-003: Capability Escalation via Initialize [FAIL] (0.156s)
...
Results: 8/10 passed (80% pass rate) - see report.json
```

---

## Why This Matters

- **EU AI Act deadline: August 2, 2026** - high-risk AI systems require transparency, human oversight, and documented governance. This framework satisfies those requirements.
- **NIST AI Agent Standards Initiative (Feb 2026)** - NIST launched a dedicated initiative for secure, interoperable AI agents. This framework aligns with the direction NIST is heading.
- **OWASP Top 10 for Agentic Applications (Dec 2025)** - The benchmark for agentic AI security is now published. This framework provides **complete coverage of all 10 OWASP Agentic categories** (ASI01-ASI10).
- **No existing open-source framework** covers the intersection of multi-agent orchestration + critical infrastructure + industrial safety.
- Enterprises are deploying agentic AI faster than they can secure it. This closes the gap.

---

## Feature Overview

### 24 Test Harness Modules

| Module | Tests | Layer | Description |
|---|---|---|---|
| **MCP Protocol** | 13 | JSON-RPC 2.0 | Anthropic MCP wire-protocol testing |
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
