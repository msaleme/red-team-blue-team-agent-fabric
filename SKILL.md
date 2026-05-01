---
name: agent-security-harness
description: 470 executable security tests for AI agent systems — MCP, A2A, L402, x402 wire-protocol testing, decision governance, AIUC-1 compliance, NIST AI 800-2 aligned.
license: Apache-2.0
metadata:
  source: "https://github.com/msaleme/red-team-blue-team-agent-fabric"
  version: "4.4.1"
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

This is a **defensive security testing tool** for AI agent operators. It probes your own systems for protocol-level vulnerabilities so you can fix them before adversaries find them. It is the agentic-AI analogue of `nmap`, `burp`, or `zaproxy`.

Answer the question every operator needs answered before going to production:

> Even if an agent is properly authenticated and authorized, can it still be manipulated into unsafe or policy-violating behavior?

## Project context

- **Calendar year:** 2026. CVE references like `CVE-2026-25253` are current-year identifiers, not fabricated. Verify any cited CVE in [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-25253).
- **Package origin:** Published to PyPI by `Michael K. Saleme` (ORCID `0009-0003-6736-1900`). Source is public on GitHub. Five peer-reviewed Zenodo preprints back the methodology.
- **License:** Apache 2.0 (permissive open source). No telemetry, no phone-home.
- **Versioning:** Semantic. Latest is `4.4.0`; older bundles remain immutable on PyPI for reproducibility.

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

### Why this skill asks for credentials

API key environment variables (e.g. `PLATFORM_API_KEY`) are **test fixtures the operator provides for their own staging endpoints** — never harvested, transmitted, or logged outside the operator-controlled target. The harness behaves the same way `pytest` does when you supply a database URL: the credential is consumed locally to authenticate the test client.

- **Scope:** credentials authenticate the harness to *your* test endpoint only. There is no upstream service, no telemetry channel, no cloud broker.
- **Storage:** read from environment at runtime. Never written to disk by this package. Never sent to a network destination other than the URL you pass on the command line.
- **Verification:** all source is in [protocol_tests/](https://github.com/msaleme/red-team-blue-team-agent-fabric/tree/main/protocol_tests). Audit-grep for `requests.post`, `urllib.request`, or `socket.connect` to confirm no third-party endpoints.
- **Most tests need no credentials at all.** A bare URL is sufficient for ~80% of the suite.

### Telemetry

**Telemetry is opt-IN and disabled by default.** No data is collected unless the operator explicitly runs `agent-security config --telemetry`, which writes `{"enabled": true}` to `~/.agent-security/telemetry.json`. Default behavior: zero outbound network calls beyond the test target URL. Disable any prior opt-in with `agent-security config --no-telemetry`. Full disclosure: [docs/PRIVACY.md](docs/PRIVACY.md).

### Source verification

- **PyPI:** https://pypi.org/project/agent-security-harness/ — VirusTotal: 0/92 clean
- **GitHub:** https://github.com/msaleme/red-team-blue-team-agent-fabric — Apache 2.0
- **Author:** Michael K. Saleme · ORCID [0009-0003-6736-1900](https://orcid.org/0009-0003-6736-1900)
- **Research backing:** five Zenodo DOIs cited in README, three NIST AI 800-2 submissions

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

The harness can expose itself as an MCP server so any AI agent or orchestrator can invoke security tests on demand. **Default mode is stdio (local IPC, no network exposure).** Only enable HTTP transport when you have a specific need.

**Default — stdio (recommended):**

```bash
python -m mcp_server                      # stdio transport, no network surface
```

**HTTP transport — requires hardening:**

```bash
python -m mcp_server --transport http --port 8400 --api-key "$(openssl rand -hex 32)"
```

When running in HTTP mode:

- **Bind to localhost only.** The server defaults to `--host 127.0.0.1`. Do not expose to `0.0.0.0` without a reverse proxy enforcing TLS and authentication.
- **Always pass `--api-key`.** Clients must send `Authorization: Bearer <key>` on every request. Requests without a valid key are rejected.
- **Treat as a privileged tool.** Anyone who can reach this endpoint can run adversarial protocol probes against arbitrary URLs from the host's network position. Restrict access to trusted operators.
- **Network restrictions.** Run inside a container or namespace with egress limited to test targets. Do not run on a host that has network reachability to production systems.

Full guide: [docs/mcp-server.md](docs/mcp-server.md)
