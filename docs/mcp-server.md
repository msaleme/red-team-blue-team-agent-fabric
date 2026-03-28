# MCP Server Documentation

The Agent Security Harness includes an MCP (Model Context Protocol) server that
exposes all scanning and audit tools as MCP tools. This lets any MCP-compatible
AI agent (Claude Desktop, Cursor, custom agents) call security tests directly.

## Quick Start

### Prerequisites

```bash
pip install 'agent-security-harness[mcp-server]'
# or just: pip install mcp>=1.0.0
```

### stdio Mode (IDE Integration)

```bash
python -m mcp_server
```

The server reads JSON-RPC messages from stdin and writes responses to stdout.
This is the default mode and works with Claude Desktop, Cursor, and other
MCP-compatible IDEs.

### HTTP Mode

```bash
python -m mcp_server --transport http --port 8400
```

Starts a Streamable HTTP server on `http://127.0.0.1:8400`. Use `--host 0.0.0.0`
to bind to all interfaces (not recommended without auth).

## IDE Integration

### Claude Desktop

Add to your Claude Desktop configuration (`claude_desktop_config.json`):

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

Then ask Claude: *"Scan my MCP server at http://localhost:8080/mcp for security issues"*

### Cursor

Add to your Cursor MCP settings (`.cursor/mcp.json`):

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

### VS Code (Copilot MCP)

Add to your VS Code settings or `.vscode/mcp.json`:

```json
{
  "servers": {
    "agent-security": {
      "command": "python",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/red-team-blue-team-agent-fabric"
    }
  }
}
```

## Tool Reference

### scan_mcp_server

Quick 5-test security scan with A-F grading.

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `url` | string | Yes | - | MCP server URL to scan |
| `transport` | string | No | `"http"` | Transport type: `http` or `stdio` |

**Example Response:**
```json
{
  "scan_type": "free_mcp_security_scan",
  "target_url": "http://localhost:8080/mcp",
  "grade": "B",
  "tests_passed": 4,
  "tests_run": 5,
  "results": [
    {"id": "MCP-001", "name": "Tool Discovery Poisoning", "status": "PASS", "detail": ""},
    {"id": "MCP-003", "name": "Capability Escalation", "status": "PASS", "detail": ""},
    {"id": "MCP-004", "name": "Protocol Downgrade", "status": "FAIL", "detail": "Server accepted downgrade"},
    {"id": "MCP-008", "name": "Malformed JSON-RPC", "status": "PASS", "detail": ""},
    {"id": "MCP-010", "name": "Tool Argument Injection", "status": "PASS", "detail": ""}
  ],
  "recommendation": "The scan detected 1 issue(s) in: Protocol Downgrade...",
  "scan_time": 3.45
}
```

### full_security_audit

Full harness run with attestation report.

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `url` | string | Yes | - | Target server URL |
| `protocol` | string | No | `"mcp"` | Protocol: mcp, a2a, x402, l402, identity |
| `categories` | string | No | `""` | Comma-separated category filter |
| `trials` | integer | No | `1` | Number of trials (1-10) |

**Example prompt:** *"Run a full MCP security audit on http://localhost:8080/mcp"*

### aiuc1_readiness

AIUC-1 certification readiness assessment.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `url` | string | No | Target URL to scan (provide this OR report_json) |
| `report_json` | string | No | Pre-existing attestation report as JSON string |

**Example prompt:** *"Check AIUC-1 certification readiness for my server at http://localhost:8080/mcp"*

**Example Response:**
```json
{
  "readiness_score": 65.0,
  "grade": "C",
  "summary": {
    "total_requirements": 20,
    "covered": 15,
    "passing": 13,
    "failing": 2,
    "gaps": 5
  },
  "gap_analysis": [
    {"req_id": "E001", "title": "Incident Detection Latency", "category": "Safety", "notes": "..."}
  ]
}
```

### get_test_catalog

List all available security tests.

**Parameters:**
| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `protocol` | string | No | `""` | Filter by protocol (mcp, a2a, l402, x402, identity) |

**Example prompt:** *"Show me all MCP security tests available in the harness"*

### validate_attestation

Validate an attestation report against the JSON schema.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `report_json` | string | Yes | Attestation report as JSON string |

**Example prompt:** *"Validate this attestation report: {json...}"*

## Rate Limiting

Scan tools are rate-limited to **1 request per 60 seconds per client**.

- **HTTP mode:** Rate limits are tracked per client identifier. Each distinct
  client gets its own 60-second window. Stale entries are cleaned after 5 minutes.
- **stdio mode:** All requests share a single client context (since stdio is
  inherently single-client).

The `get_test_catalog` and `validate_attestation` tools are not rate-limited.

## Authentication

For production deployments, use the `--api-key` flag:

```bash
python -m mcp_server --transport http --port 8400 --api-key YOUR_SECRET_KEY
```

When an API key is configured:

- **`scan_mcp_server`** and **`get_test_catalog`** remain **unauthenticated**
  (free tier). Anyone can run quick scans and browse the test catalog.
- **`full_security_audit`** and **`aiuc1_readiness`** **require authentication**.
  Pass the key via the `api_key` tool parameter, or set the
  `AGENT_SECURITY_CLIENT_KEY` environment variable on the client side.
- **`validate_attestation`** does not require authentication (schema validation
  only, no server-side execution).

If no `--api-key` is set, all tools are accessible without authentication.

## Input Limits

The `report_json` parameter accepted by `validate_attestation` and
`aiuc1_readiness` is capped at **10 MB**. Payloads exceeding this limit are
rejected immediately.
The quick scan (`scan_mcp_server`) remains unauthenticated for free-tier access.

## Security Considerations

- **SSRF Protection:** All URL inputs are validated against SSRF attacks (no private IPs, loopback, cloud metadata endpoints).
- **Rate Limiting:** Prevents scan abuse in HTTP mode.
- **Subprocess Isolation:** Full audits run in subprocesses with timeouts.
- **Input Validation:** All parameters are validated before execution.

## Example Workflow

Ask Claude (or any MCP-connected agent):

1. *"List all available MCP security tests"* - Uses `get_test_catalog`
2. *"Run a quick security scan on http://my-server:8080/mcp"* - Uses `scan_mcp_server`
3. *"The quick scan found issues. Run a full audit"* - Uses `full_security_audit`
4. *"Check if this server is ready for AIUC-1 certification"* - Uses `aiuc1_readiness`
5. *"Validate this attestation report: {...}"* - Uses `validate_attestation`
