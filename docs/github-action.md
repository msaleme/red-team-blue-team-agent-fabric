# GitHub Action: Agent Security Harness

Run protocol-level security tests against your MCP, A2A, L402, or x402 agent endpoints as a CI/CD security gate.

## Two Ways to Use

### 1. Composite Action (recommended for most users)

Reference the action directly from your workflow:

```yaml
name: Security Gate
on: [pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Start your MCP server (example)
      - name: Start MCP server
        run: |
          npm start &
          sleep 5

      - name: Run Agent Security Harness
        uses: msaleme/red-team-blue-team-agent-fabric@v3.8
        with:
          target_url: http://localhost:8080/mcp
```

### 2. Reusable Workflow

Call the reusable workflow from your own workflow:

```yaml
name: Security Gate
on: [pull_request]

jobs:
  security:
    uses: msaleme/red-team-blue-team-agent-fabric/.github/workflows/security-scan.yml@v3.8
    with:
      target_url: http://localhost:8080/mcp
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `target_url` | Yes | - | MCP server URL to test |
| `transport` | No | `http` | Transport type: `http` or `stdio` |
| `categories` | No | *(all)* | Comma-separated test categories to run |
| `fail_on` | No | `critical` | Fail threshold: `any`, `critical`, or `none` |
| `python_version` | No | `3.12` | Python version for the runner |
| `harness_version` | No | *(latest)* | Pin a specific PyPI version |

## Outputs (Composite Action)

| Output | Description |
|--------|-------------|
| `report_path` | Path to the JSON report file |
| `total_tests` | Total number of tests executed |
| `passed` | Number of passed tests |
| `failed` | Number of failed tests |
| `critical_failures` | Number of critical test failures |

## Fail Thresholds

| `fail_on` | Behavior |
|-----------|----------|
| `any` | Fail the workflow if **any** test fails |
| `critical` | Fail only if tests with `severity: critical` fail (default) |
| `none` | Never fail - report only, useful for monitoring |

## Examples

### Basic - fail on critical issues

```yaml
- uses: msaleme/red-team-blue-team-agent-fabric@v3.8
  with:
    target_url: http://localhost:8080/mcp
```

### Strict - fail on any issue

```yaml
- uses: msaleme/red-team-blue-team-agent-fabric@v3.8
  with:
    target_url: http://localhost:8080/mcp
    fail_on: any
```

### Run specific categories only

```yaml
- uses: msaleme/red-team-blue-team-agent-fabric@v3.8
  with:
    target_url: http://localhost:8080/mcp
    categories: tool_discovery,capability_negotiation
```

### Monitor mode (never fail the build)

```yaml
- uses: msaleme/red-team-blue-team-agent-fabric@v3.8
  with:
    target_url: http://localhost:8080/mcp
    fail_on: none
```

### Pin a specific harness version

```yaml
- uses: msaleme/red-team-blue-team-agent-fabric@v3.8
  with:
    target_url: http://localhost:8080/mcp
    harness_version: '3.8.0'
```

### Use outputs in subsequent steps

```yaml
- name: Run security scan
  id: security
  uses: msaleme/red-team-blue-team-agent-fabric@v3.8
  with:
    target_url: http://localhost:8080/mcp
    fail_on: none

- name: Check results
  run: |
    echo "Total: ${{ steps.security.outputs.total_tests }}"
    echo "Passed: ${{ steps.security.outputs.passed }}"
    echo "Failed: ${{ steps.security.outputs.failed }}"
    echo "Critical: ${{ steps.security.outputs.critical_failures }}"

    if [ "${{ steps.security.outputs.critical_failures }}" -gt 0 ]; then
      echo "Critical failures detected - notifying team"
      # Add your notification logic here
    fi
```

### Full CI pipeline with service container

```yaml
name: CI with Security Gate
on: [pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      mcp-server:
        image: your-org/mcp-server:latest
        ports:
          - 8080:8080

    steps:
      - uses: actions/checkout@v4

      - name: Wait for MCP server
        run: |
          for i in $(seq 1 30); do
            curl -sf http://localhost:8080/health && break
            sleep 1
          done

      - name: Unit tests
        run: npm test

      - name: Security scan
        uses: msaleme/red-team-blue-team-agent-fabric@v3.8
        with:
          target_url: http://localhost:8080/mcp
          fail_on: critical
```

## What Gets Tested

The harness runs protocol-level security tests including:

- **Tool Discovery** - enumeration abuse, hidden tool exposure
- **Capability Negotiation** - downgrade attacks, version manipulation
- **Input Validation** - malformed JSON-RPC, oversized payloads, injection
- **Session Security** - replay attacks, session fixation, token manipulation
- **Authorization** - privilege escalation, capability boundary violations
- **Protocol Compliance** - spec conformance, error handling

See the full [test inventory](../README.md#test-inventory) for details.

## PR Comments

When used in a pull request workflow, the reusable workflow automatically posts (and updates) a summary comment on the PR with test results:

```
## 🛡️ Agent Security Harness Results

| Metric | Count |
|--------|-------|
| Total Tests | 11 |
| ✅ Passed | 9 |
| ❌ Failed | 2 |
| 🚨 Critical | 1 |

### Failed Tests
| Test | Severity | Details |
|------|----------|---------|
| `MCP-003` | critical | Server accepted downgraded protocol version |
| `MCP-007` | medium | Large payload not rejected within timeout |
```

## Artifacts

The JSON report is uploaded as a workflow artifact (`security-report`) with 30-day retention, available for download from the Actions tab.
