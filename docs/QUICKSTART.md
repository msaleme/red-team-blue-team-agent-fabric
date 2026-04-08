# Quick Start Guide

## Installation

```bash
pip install agent-security-harness
```

## Basic Usage

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

---

## Try It Without a Server (Mock MCP Server)

A bundled mock MCP server lets you validate the harness works without setting up your own target:

```bash
# Terminal 1: Start the mock server (has one deliberately vulnerable tool)
python -m testing.mock_mcp_server

# Terminal 2: Run the harness against it
agent-security test mcp --transport http --url http://localhost:8402/mcp
```

The mock server includes a poisoned tool description (exfil URL) that the `tool_discovery_poisoning` test should catch.

---

## Rate Limiting

When testing production endpoints, add a delay between tests to avoid triggering WAF blocks:

```bash
# 500ms delay between each test
agent-security test mcp --url http://localhost:8080/mcp --delay 500

# 2 second delay for sensitive production endpoints
agent-security test a2a --url https://agent.example.com --delay 2000
```

---

## JSON Output for CI

```bash
# Structured JSON output for pipelines
agent-security test mcp --url http://localhost:8080/mcp --json > report.json
```

Works in single-run and multi-trial modes.

---

## Free MCP Security Scan

Quick 5-test scan with A-F grading:

```bash
python scripts/free_scan.py --url http://server:port/mcp --format markdown
```

---

## AIUC-1 Certification Prep

```bash
python scripts/aiuc1_prep.py --url http://your-agent --simulate
```

Maps results to all 24 AIUC-1 requirements with gap analysis.

---

## MCP Server Mode

Use the harness as an MCP tool that any AI agent can call:

```bash
# Install with MCP support
pip install agent-security-harness[mcp-server]

# stdio mode (for Cursor, Claude Desktop, IDE integration)
python -m mcp_server

# HTTP mode (for remote/production use)
python -m mcp_server --transport http --port 8400
```

**Add to Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "agent-security": {
      "command": "python",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/red-team-blue-team-agent-fabric"
    }
  }
}
```

**Available tools:** `scan_mcp_server` (quick 5-test scan), `full_security_audit` (398 tests), `aiuc1_readiness` (certification prep), `get_test_catalog` (list tests), `validate_attestation` (schema validation).

See [mcp-server.md](mcp-server.md) for full documentation.

---

## CI/CD Integration

Gate deployments on decision-governance tests. Drop this into any GitHub Actions workflow:

```yaml
name: Agent Security Gate
on: [pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Start your MCP server (replace with your setup)
      - name: Start MCP server
        run: |
          npm start &
          sleep 5

      # Run the security harness
      - name: Agent Security Harness
        id: security
        uses: msaleme/red-team-blue-team-agent-fabric@v3.8
        with:
          target_url: http://localhost:8080/mcp
          fail_on: critical  # any | critical | none

      # Use results in downstream steps
      - name: Check results
        if: always()
        run: |
          echo "Passed: ${{ steps.security.outputs.passed }}/${{ steps.security.outputs.total_tests }}"
          echo "Critical failures: ${{ steps.security.outputs.critical_failures }}"
```

**Inputs:** `target_url` (required), `transport` (http/stdio), `categories` (filter), `fail_on` (any/critical/none), `harness_version` (pin a specific release)

**Outputs:** `report_path` (JSON report), `total_tests`, `passed`, `failed`, `critical_failures`

**Features:**
- Automatic PR comments with test results
- Configurable fail thresholds (any/critical/none)
- JSON report uploaded as workflow artifact (30-day retention)
- Step summary with pass/fail breakdown

Or use the CLI directly in any CI system:

```bash
pip install agent-security-harness
agent-security test mcp --url http://localhost:8080/mcp --json > report.json
```

See [github-action.md](github-action.md) for full usage examples including service containers, reusable workflows, and output handling.
