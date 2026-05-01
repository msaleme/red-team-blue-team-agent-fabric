---
name: agent-security-harness
description: 470 executable security tests for AI agent systems — MCP, A2A, L402, x402 wire-protocol testing, decision governance, AIUC-1 compliance, NIST AI 800-2 aligned.
license: Apache-2.0
metadata:
  source: "https://github.com/msaleme/red-team-blue-team-agent-fabric"
  version: "4.4.0"
  openclaw:
    emoji: "🛡️"
    requires:
      bins:
        - agent-security
      python: ">=3.10"
    install:
      - id: pip
        kind: pip
        package: agent-security-harness
        bins:
          - agent-security
        label: "Install agent-security-harness (pip)"
---

# Agent Security Harness

470 executable security tests for AI agent systems. MCP + A2A + L402 + x402 wire-protocol testing. Decision-layer attack scenarios. AIUC-1 compliance mapping. One `pip install` away.

## Purpose

Answer the question every operator needs answered before going to production:

> Even if an agent is properly authenticated and authorized, can it still be manipulated into unsafe or policy-violating behavior?

## When to use

- Security testing an MCP server before deployment
- Red-teaming an A2A multi-agent pipeline
- Validating L402/x402 payment endpoint behavior under adversarial conditions
- Running AIUC-1 pre-certification checks
- CI/CD gate for agent system changes

## Quick Start

```bash
pip install agent-security-harness

# Simulate immediately — no server needed:
agent-security test mcp --simulate

# Test a real MCP server:
agent-security test mcp --url http://localhost:8080/mcp

# Test an x402 payment endpoint:
agent-security test x402 --url https://your-x402-endpoint.com
```

If `agent-security` is not found after install, add `~/.local/bin` to your PATH:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## What it covers

| Layer | Scope | Tests |
|-------|-------|-------|
| MCP Protocol | JSON-RPC 2.0 attacks, tool injection, capability escalation | 18 |
| A2A Protocol | Agent-to-agent trust, delegation, provenance | 13 |
| L402 Payment | WWW-Authenticate flow, token replay, downgrade | 33 |
| x402 Payment | Payment challenge crafting, validation bypass | 52 |
| Decision Governance | Autonomy scoring, scope creep, policy constraint testing | 8+ |
| Jailbreak / Over-Refusal | 25 jailbreak + 25 false-positive rate tests | 50 |
| GTG-1002 APT Simulation | 17 nation-state pattern reproductions | 17 |
| Enterprise Platforms | 25 cloud + 20 enterprise platform tests | 45+ |
| AIUC-1 Compliance | Maps to 19 of 20 testable AIUC-1 requirements | 12 |

Full inventory: [docs/TEST-INVENTORY.md](docs/TEST-INVENTORY.md)

## Safety & Credentials

**Non-destructive by default.** All tests are read-only protocol probes. No writes, no mutations, no side effects on the target system.

**Do NOT run against production systems without explicit written authorization.** Use isolated staging environments or test accounts. This tool sends adversarial protocol messages; production systems may log or rate-limit them.

**Credentials:** Most tests require only a URL. Enterprise platform tests and payment endpoint tests may require API keys — documented per-module in [docs/ADVANCED.md](docs/ADVANCED.md). No credentials are stored or transmitted outside the test target.

**Source verification:**
- PyPI: https://pypi.org/project/agent-security-harness/
- GitHub: https://github.com/msaleme/red-team-blue-team-agent-fabric

## Research backing

Five peer-reviewed preprints and three NIST submissions underpin the methodology. See [README.md](README.md) for full DOI list.

## CI/CD integration

```yaml
# GitHub Actions
- uses: msaleme/red-team-blue-team-agent-fabric@v4.4.0
  with:
    target-url: ${{ secrets.MCP_TEST_URL }}
    suite: mcp,a2a
```

Full guide: [docs/github-action.md](docs/github-action.md)

## MCP server mode

The harness exposes itself as an MCP server — invoke security tests from any AI agent or orchestrator:

```bash
agent-security serve --port 8090
```

Full guide: [docs/mcp-server.md](docs/mcp-server.md)
