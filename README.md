# Agent Security Harness

[![SafeSkill 85/100](https://img.shields.io/badge/SafeSkill-85%2F100_Passes%20with%20Notes-yellow)](https://safeskill.dev/scan/msaleme-red-team-blue-team-agent-fabric)
[![PyPI version](https://badge.fury.io/py/agent-security-harness.svg)](https://pypi.org/project/agent-security-harness/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Apache 2.0 License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/security%20tests-461-green.svg)](#three-layers-of-agent-decision-security)

**Even if an agent is properly authenticated and authorized, can it still be manipulated into unsafe or policy-violating behavior?**

461 executable security tests across 31 modules. MCP + A2A + L402 + x402 wire-protocol testing. Decision-layer attack scenarios. One `pip install` away.

```
$ agent-security test mcp --url http://localhost:8080/mcp
Running MCP Protocol Security Tests v3.10...
 MCP-001: Tool List Integrity Check [PASS] (0.234s)
 MCP-002: Tool Registration via Call Injection [PASS] (0.412s)
 MCP-003: Capability Escalation via Initialize [FAIL] (0.156s)
...
Results: 8/10 passed (80% pass rate) - see report.json
```

## Quick Start

```bash
pip install agent-security-harness

# If 'agent-security' is not found, add ~/.local/bin to your PATH:
export PATH="$HOME/.local/bin:$PATH"
```

```bash
# See it work immediately — no server needed:
agent-security test mcp --simulate

# Then test your real MCP server:
agent-security test mcp --url http://localhost:8080/mcp

# Test an x402 payment endpoint
agent-security test x402 --url https://your-x402-endpoint.com
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for mock server setup, rate limiting, MCP server mode, and CI/CD integration.

---

## Three Layers of Agent Decision Security

| Layer | What it covers | Example focus |
|-------|----------------|---------------|
| **Protocol Integrity** | Prevent spoofing, replay, downgrade, diversion, and malformed protocol behavior | MCP, A2A, L402, x402 wire-level tests |
| **Operational Governance** | Validate session state, capability boundaries, platform actions, trust chains, and execution context | capability escalation, facilitator trust, provenance, session security |
| **Decision Governance** | Test whether an agent should act at all under its authority, confidence, scope, and policy constraints | autonomy scoring, scope creep, return-channel poisoning, normalization-of-deviance |

---

## How This Differs From Other Projects

| Capability | [Invariant MCP-Scan](https://github.com/invariantlabs-ai/mcp-scan) (2K stars) | [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) (865 stars) | [Snyk Agent Scan](https://github.com/snyk/agent-scan) (2K stars) | [NVIDIA Garak](https://github.com/NVIDIA/garak) (7K stars) | **This framework** |
|---|---|---|---|---|---|
| **What it does** | Scans installed MCP configs for tool poisoning | YARA + LLM-as-judge for malicious tools | Scans agent configs for MCP/skill security | LLM model vulnerability testing | Active protocol exploitation + decision governance |
| **Approach** | Static analysis | Static + LLM classification | Config scanning | Model-layer probing | **Wire-protocol adversarial testing** |
| **MCP coverage** | Tool descriptions, config files | Tool descriptions, YARA rules | Config files | - | **14 tests: real JSON-RPC 2.0 attacks** |
| **A2A coverage** | - | - | - | - | **13 tests** |
| **L402/x402 coverage** | - | - | - | - | **85 tests** |
| **Enterprise platforms** | - | - | - | - | **25 cloud + 20 enterprise** |
| **APT simulation** | - | - | - | - | **GTG-1002 (17 tests)** |
| **Jailbreak/over-refusal** | - | - | - | Yes | **50 tests (25 + 25 FPR)** |
| **AIUC-1 certification** | - | - | - | - | **Maps to all 24 requirements** |
| **Research backing** | - | Cisco blog | - | Papers | **5 DOIs + 3 NIST submissions** |
| **MCP server mode** | - | - | - | - | **Yes - invoke from any AI agent** |
| **Statistical testing** | - | - | - | - | **Wilson CIs, multi-trial** |
| **Total tests** | Pattern matching | YARA rules | Config checks | Model probes | **461 active tests** |

**Use both.** Scan with [Invariant MCP-Scan](https://github.com/invariantlabs-ai/mcp-scan) or [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) for static analysis. Test with this framework for active exploitation. They're complementary layers.

---

## Research

Five peer-reviewed preprints and three NIST submissions underpin the methodology:

| Publication | DOI |
|---|---|
| **Constitutional Self-Governance for Autonomous AI Agents** — 12 governance mechanisms, 77 days production data, 56 agents | [10.5281/zenodo.19162104](https://doi.org/10.5281/zenodo.19162104) |
| **Detecting Normalization of Deviance in Multi-Agent Systems** — First empirical demonstration that automated harnesses detect behavioral drift | [10.5281/zenodo.19195516](https://doi.org/10.5281/zenodo.19195516) |
| **Decision Load Index (DLI): A Quantitative Framework for Agent Autonomy Risk** — Measuring cognitive burden of AI agent oversight | [10.5281/zenodo.18217577](https://doi.org/10.5281/zenodo.18217577) |
| **Normalization of Deviance in Autonomous Agent Systems** — Foundational research on behavioral drift patterns | [10.5281/zenodo.15105866](https://doi.org/10.5281/zenodo.15105866) |
| **Cognitive Style Governance for Multi-Agent Deployments** — Governance mechanisms for managing cognitive style across multi-agent systems | [10.5281/zenodo.15106553](https://doi.org/10.5281/zenodo.15106553) |

---

## Documentation

| Resource | Link |
|---|---|
| Expanded Quick Start | [docs/QUICKSTART.md](docs/QUICKSTART.md) |
| Full Test Inventory (461 tests) | [docs/TEST-INVENTORY.md](docs/TEST-INVENTORY.md) |
| AIUC-1 Crosswalk | [docs/AIUC1-CROSSWALK.md](docs/AIUC1-CROSSWALK.md) |
| Advanced Capabilities | [docs/ADVANCED.md](docs/ADVANCED.md) |
| MCP Server | [docs/mcp-server.md](docs/mcp-server.md) |
| CI/CD GitHub Action | [docs/github-action.md](docs/github-action.md) |
| Payment Attack Taxonomy | [docs/PAYMENT-ATTACK-TAXONOMY.md](docs/PAYMENT-ATTACK-TAXONOMY.md) |
| Comparison (detailed) | [docs/COMPARISON.md](docs/COMPARISON.md) |
| Privacy & Telemetry | [docs/PRIVACY.md](docs/PRIVACY.md) |

---

## Roadmap

**v3.10 -- Prove It to Auditors** ✅ Shipped. **v4.1 -- Compliance Evidence** ✅ Shipped. 461 tests, 31 modules, AUROC metrics, EU AI Act + ISO 42001 crosswalks, FRIA evidence, kill-switch compliance, watermark adversarial tests, HTML compliance report generator. **v4.2 -- Incident-Tested** (next). 22 new tests mapped to OX Security, UC Berkeley, PraisonAI CVEs, lightningzero, OpenClaw April CVEs. **v5.0 -- Lock the Category** (H2 2026): benchmark corpus, schema standardization, longitudinal registry. Full details in [ROADMAP.md](ROADMAP.md).

---

## Used By

| Who | Use Case |
|-----|----------|
| [FransDevelopment / Open Agent Trust Registry](https://github.com/FransDevelopment/open-agent-trust-registry) | OATR SDK v1.2.0 test fixtures (X4-021 through X4-030) -- Ed25519 attestation verification |

*Using the harness? Open a PR to add yourself, or tag us in your project.*

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines, [SECURITY_POLICY.md](SECURITY_POLICY.md) for security policy, and [CONTRIBUTION_REVIEW_CHECKLIST.md](CONTRIBUTION_REVIEW_CHECKLIST.md) for the PR checklist.

## License

Apache License 2.0 -- see [LICENSE](LICENSE).
