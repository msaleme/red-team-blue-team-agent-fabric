# Monthly Agent Security Report Pipeline

Automated pipeline that scans a fleet of MCP servers on a regular cadence and produces a combined monthly security report with executive summary, per-server breakdowns, and trend tracking.

## Purpose

Security posture isn't a one-time check. The monthly report pipeline provides:

- **Continuous visibility** into MCP server security across your fleet
- **Executive summaries** suitable for leadership and compliance reviews
- **Trend tracking** to show improvement (or regression) over time
- **Failure pattern analysis** to prioritize remediation efforts

## Architecture

```
configs/monthly_targets.yaml    -->  monthly_security_report.py  -->  reports/monthly/YYYY-MM.md
(server list)                        (runs full MCP harness)          (markdown report)
```

## Usage

### Run with defaults

```bash
python scripts/monthly_security_report.py
```

This reads `configs/monthly_targets.yaml` and writes to `reports/monthly/YYYY-MM.md` (current month).

### Custom config and month

```bash
python scripts/monthly_security_report.py \
    --config configs/production_targets.yaml \
    --month 2026-03 \
    --output-dir reports/monthly/
```

## Configuration

### `configs/monthly_targets.yaml`

```yaml
targets:
  - name: "Production MCP Gateway"
    url: "https://mcp.prod.example.com/mcp"

  - name: "Staging Environment"
    url: "http://staging-mcp.internal:8080/mcp"

  - name: "Partner Integration"
    url: "https://partner.example.com:8443/mcp"
```

Each target needs:
- `name` - Human-readable label (appears in report tables)
- `url` - Streamable HTTP endpoint for the MCP server

## Report Structure

The generated markdown report includes:

### 1. Executive Summary
- Number of servers tested
- Total tests executed
- Average pass rate across all servers
- Top 3 most common failures across the fleet

### 2. Per-Server Results Table
Quick-glance table showing pass/fail counts and rates for each server.

### 3. Detailed Results
Full test-by-test breakdown for each server with test IDs, names, status, and failure details.

### 4. Trends
Comparison with previous month's results. Currently stubbed - will auto-populate once two or more monthly reports exist in the output directory.

### 5. Methodology
Documents the test suite version, approach, and links to the repo for transparency.

## Automation

### Cron job (monthly)

```bash
# Run on the 1st of every month at 06:00 UTC
0 6 1 * * cd /path/to/repo && python scripts/monthly_security_report.py
```

### GitHub Actions

```yaml
name: Monthly Security Report
on:
  schedule:
    - cron: '0 6 1 * *'
  workflow_dispatch:

jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: python scripts/monthly_security_report.py
      - uses: actions/upload-artifact@v4
        with:
          name: monthly-report
          path: reports/monthly/*.md
```

## Dependencies

- Python 3.10+
- PyYAML (recommended, but a built-in fallback parser handles the simple config format)
- No other external dependencies

## Full Harness Tests

The monthly pipeline runs ALL available MCP tests, not just the 5 in the free scan. This includes:

| ID | Test |
|----|------|
| MCP-001 | Tool Discovery Poisoning |
| MCP-002 | Tool Description Injection |
| MCP-003 | Capability Escalation |
| MCP-004 | Protocol Version Downgrade |
| MCP-005 | Resource Path Traversal |
| MCP-006 | Prompt Injection via Get |
| MCP-007 | Sampling Hijack |
| MCP-008 | Malformed JSON-RPC |
| MCP-009 | Batch Bomb (DoS) |
| MCP-010 | Tool Argument Injection |
| MCP-011 | Tool Description Context Displacement |
| ... | Additional tests as the harness evolves |

## Report Archive

Reports are saved to `reports/monthly/` with filenames like `2026-03.md`. Over time this directory becomes a historical record of your security posture.

```
reports/monthly/
  2026-01.md
  2026-02.md
  2026-03.md
```

See also: [Free Scan documentation](./free-scan.md) for the lightweight 5-test quick assessment.
