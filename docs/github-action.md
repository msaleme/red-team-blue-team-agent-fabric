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
| `critical_failures` | Number of failed tests whose severity is critical |
| `inconclusive` | Number of INCONCLUSIVE / NOT_EXECUTED tests (reported, never gated on) |

### How a row is counted

Both the composite action and the reusable workflow count the report with
`python -m protocol_tests.report_gate`, which classifies each result row with
`protocol_tests.http_helpers.row_outcome`, the same function the harness's own
`summary` block is computed with. The Action and the harness cannot disagree
about what a FAIL is.

| Row | Counted as |
|-----|------------|
| `not_evaluated: true` or `informational: true`, or `details` beginning `INCONCLUSIVE - ` (this includes the MCP harness's NOT_EXECUTED rows when its handshake is refused) | **INCONCLUSIVE**: neither a pass nor a failure, whatever `passed` says |
| otherwise `passed: true` | PASS |
| otherwise `passed: false` | **FAIL** |
| no `passed` field, `status: "PASS"` / `"FAIL"` / `"INCONCLUSIVE"` | that status (no harness in this repository writes this shape; it is honoured for compatibility) |

A FAIL is **critical** when its `severity` is `P0-Critical` (the MCP and most other
harnesses), `critical` or `CRITICAL`. A row with no severity is never critical: it
counts toward `fail_on: any`, not `fail_on: critical`.

Counts are recomputed from the rows, not copied from the report's `summary`, because
several harness writers still put INCONCLUSIVE rows in their own summary's `failed`.
A report whose rows are not JSON objects (a `--trials` report currently serialises
each row as a string) cannot be classified and fails the step rather than being
counted either way. So does a missing or unparseable report.

The composite action imports the gate from its own checkout (`GITHUB_ACTION_PATH`),
so it matches the action ref you pinned even when `harness_version` pins an older
package. The reusable workflow has no such checkout and imports it from the installed
harness; if that harness predates the gate, the workflow fails with an error (unless
`fail_on: none`) rather than report `critical_failures=0` it cannot vouch for.

Before this change (2026-09-24), `critical_failures` was computed from a `status`
field no harness writes, compared against the spelling `critical` where the MCP
harness writes `P0-Critical`, so `fail_on: critical` (the default) never failed a
build.

## Fail Thresholds

| `fail_on` | Behavior |
|-----------|----------|
| `any` | Fail the workflow if **any** test FAILs (INCONCLUSIVE rows do not count) |
| `critical` | Fail only if a test with critical severity FAILs (default) |
| `none` | Never fail on results - report only, useful for monitoring |

Any other value is an error; it used to be accepted and silently never failed.
The Action does not gate on `inconclusive`. To treat "nothing established" as a
failure in your own pipeline, check the output:

```yaml
- if: steps.security.outputs.inconclusive != '0'
  run: exit 1
```

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
    echo "Inconclusive: ${{ steps.security.outputs.inconclusive }}"

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
### Security Harness Results

| Metric | Count |
|--------|-------|
| Total Tests | 11 |
| Passed | 8 |
| Failed | 2 |
| Critical Failures | 1 |
| Inconclusive (not counted as failures) | 1 |

| Test | Severity | Details |
|------|----------|---------|
| MCP-003 | P0-Critical | Server accepted downgraded protocol version |
| MCP-007 | P2-Medium | Large payload not rejected within timeout |
```

## Artifacts

The JSON report is uploaded as a workflow artifact (`security-report`) with 30-day retention, available for download from the Actions tab.
