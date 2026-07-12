# Documentation Index

This directory contains detailed documentation for the Agent Security Harness framework.

## Core Documentation

| Document | Description |
|---|---|
| [../README.md](../README.md) | **Main project README** - Overview, installation, quick start |
| [../EVALUATION_PROTOCOL.md](../EVALUATION_PROTOCOL.md) | **NIST AI 800-2 aligned evaluation methodology** - Objectives, protocol design, statistical analysis |
| [../ENHANCED-RED-BLUE-TEAM-TEST-PLAN.md](../ENHANCED-RED-BLUE-TEAM-TEST-PLAN.md) | **Primary test plan** - 30 test scenarios, phased deployment, 90-day roadmap |
| [../BLUE-TEAM-PLAYBOOKS.md](../BLUE-TEAM-PLAYBOOKS.md) | **Incident response playbooks** - Detection→Analysis→Response→Recovery for all scenarios |

## Governance & Process

| Document | Description |
|---|---|
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | **Contribution guidelines** - How to contribute, code style, development setup |
| [../SECURITY_POLICY.md](../SECURITY_POLICY.md) | **Security policy** - Threat model, responsible disclosure, AI-generated code policy |
| [../CONTRIBUTION_REVIEW_CHECKLIST.md](../CONTRIBUTION_REVIEW_CHECKLIST.md) | **Review checklist** - Required checklist that every PR must complete |

## Technical Specifications

| Document | Description |
|---|---|
| [../agent-fabric-red-blue-team-spec.md](../agent-fabric-red-blue-team-spec.md) | **Original specification** - 20 STRIDE scenarios, architecture overview, threat model |
| [CASE_STUDY_FALSE_PASS.md](CASE_STUDY_FALSE_PASS.md) | **False pass case study** - Analysis of security testing failure modes |

## Executive Materials  

| Document | Description |
|---|---|
| [../EXECUTIVE-PRESENTATION.md](../EXECUTIVE-PRESENTATION.md) | **24-slide executive briefing** - ROI analysis, GO/NO-GO framework |

## Quick Navigation

### Getting Started
1. Read the [main README](../README.md) for project overview and installation
2. Follow the [Quick Start guide](../README.md#quick-start) for basic usage
3. Review the [EVALUATION_PROTOCOL](../EVALUATION_PROTOCOL.md) for testing methodology

### For Contributors
1. Read [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines
2. Review [SECURITY_POLICY.md](../SECURITY_POLICY.md) for security requirements  
3. Use [CONTRIBUTION_REVIEW_CHECKLIST.md](../CONTRIBUTION_REVIEW_CHECKLIST.md) for PR submissions

### For Security Teams
1. Review [BLUE-TEAM-PLAYBOOKS.md](../BLUE-TEAM-PLAYBOOKS.md) for incident response
2. Study [CASE_STUDY_FALSE_PASS.md](CASE_STUDY_FALSE_PASS.md) for testing pitfalls
3. Reference [ENHANCED-RED-BLUE-TEAM-TEST-PLAN.md](../ENHANCED-RED-BLUE-TEAM-TEST-PLAN.md) for comprehensive testing

### For Executives
1. Start with [EXECUTIVE-PRESENTATION.md](../EXECUTIVE-PRESENTATION.md)
2. Review the competitive differentiation in [README.md](../README.md#how-this-differs-from-other-projects)
3. See standards alignment in [README.md](../README.md#standards-alignment)

---

## Framework Architecture

The harness spans 37 test-bearing modules. A representative subset (protocol
harnesses) is shown below; see [TEST-INVENTORY.md](TEST-INVENTORY.md) for the
complete per-module breakdown:

```
agent-security-harness/
├── protocol_tests/           # Core test harnesses
│   ├── mcp_harness.py       # MCP (JSON-RPC 2.0) - 18 tests
│   ├── a2a_harness.py       # A2A (Agent-to-Agent) - 13 tests  
│   ├── l402_harness.py      # L402 (Payment protocol) - 33 tests
│   ├── x402_harness.py      # x402 (Payment protocol) - 52 tests
│   ├── framework_adapters.py # LangChain, CrewAI, AutoGen - 15 tests
│   ├── enterprise_adapters.py # SAP, Salesforce, etc. - 31 tests
│   ├── gtg1002_simulation.py # GTG-1002 APT campaign - 17 tests
│   ├── advanced_attacks.py  # Multi-step attack patterns - 10 tests
│   └── identity_harness.py  # NIST NCCoE identity/auth - 18 tests
└── docs/                    # Documentation (this directory)
```

**Total: 540 security tests across 37 modules** (verified 2026-07-12 via `scripts/count_tests.py`)

---

For questions or clarifications on any documentation, please open an issue or refer to the [Contributing Guidelines](../CONTRIBUTING.md).