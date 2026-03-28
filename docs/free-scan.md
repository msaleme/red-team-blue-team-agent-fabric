# Free MCP Security Scan

A lightweight, self-contained script that runs 5 critical MCP protocol-level security tests against any Streamable HTTP MCP server and produces a graded report.

## Purpose

The free scan is designed as a quick first-pass assessment - think of it as a "smoke test" for MCP server security. It covers the highest-impact attack vectors in under a minute and gives server operators an immediate A-F grade with actionable recommendations.

This script is designed to be wrapped by a web API endpoint for a public "Free Scan" offering.

## Tests Included

| Test ID | Name | What It Checks |
|---------|------|----------------|
| MCP-001 | Tool Discovery Poisoning | Can a client inject fake tools into the server's tool list? |
| MCP-003 | Capability Escalation | Can a client claim capabilities it shouldn't have during init? |
| MCP-004 | Protocol Downgrade | Can a client force an older protocol version to bypass security? |
| MCP-008 | Malformed JSON-RPC | Does the server properly reject malformed messages? |
| MCP-010 | Tool Argument Injection | Can malicious arguments be injected into tool calls? |

## Usage

### Basic scan (JSON output)

```bash
python scripts/free_scan.py --url http://localhost:8080/mcp
```

### Markdown report

```bash
python scripts/free_scan.py --url http://localhost:8080/mcp --format markdown
```

### Save to file

```bash
python scripts/free_scan.py --url http://localhost:8080/mcp --format markdown -o report.md
```

### With email notification (stubbed)

```bash
python scripts/free_scan.py --url http://localhost:8080/mcp --email security@company.com
```

The `--email` flag currently prints a stub message. To enable actual email delivery, integrate with your SMTP or SES provider in the `send_email_stub()` function.

## Output Formats

### JSON

Returns a structured object with:

```json
{
  "scan_type": "free_mcp_security_scan",
  "target_url": "http://...",
  "timestamp": "2026-03-28T15:00:00+00:00",
  "tests_run": 5,
  "tests_passed": 4,
  "tests_failed": 1,
  "grade": "B",
  "recommendation": "The scan detected 1 issue(s)...",
  "results": [
    {"id": "MCP-001", "name": "Tool Discovery Poisoning", "status": "PASS", "detail": "..."},
    ...
  ]
}
```

### Markdown

Produces a human-readable report with a results table, grade, and recommendation paragraph.

## Grading Scale

| Grade | Pass Rate | Meaning |
|-------|-----------|---------|
| A | 100% | All tests passed - solid baseline security |
| B | 80-99% | Minor issues detected |
| C | 60-79% | Significant concerns - remediation needed |
| D | 40-59% | Major vulnerabilities present |
| F | 0-39% | Critical security failures |

## Exit Code

- `0` if all 5 tests pass
- `1` if any test fails or errors

This makes the script usable in CI/CD pipelines.

## Web API Integration

The script is designed to be called programmatically. Example Flask wrapper:

```python
from flask import Flask, request, jsonify
from scripts.free_scan import run_free_scan

app = Flask(__name__)

@app.route("/api/free-scan", methods=["POST"])
def api_free_scan():
    url = request.json.get("url")
    if not url:
        return jsonify({"error": "url is required"}), 400
    report = run_free_scan(url)
    return jsonify(report)
```

## Requirements

- Python 3.10+
- No external dependencies (uses only the stdlib and `protocol_tests.mcp_harness`)
- The target server must support MCP over Streamable HTTP

## Full Assessment

The free scan covers 5 of 20+ tests in the full harness. For a comprehensive assessment including DoS resilience, sampling hijack, path traversal, context displacement, and more, run:

```bash
python -m protocol_tests.mcp_harness --transport http --url http://server:port/mcp
```

See the [main README](../README.md) for full harness documentation.
