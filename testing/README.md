# Testing Directory

This directory contains test files for the red-team-blue-team-agent-fabric security framework.

## Mock MCP Server

The `mock_mcp_server.py` provides a minimal MCP (Model Context Protocol) server for testing the security harness without requiring a real MCP server.

### Features

- **Minimal Implementation**: < 150 lines, uses only standard library (`http.server`, `json`)
- **JSON-RPC 2.0 Compliance**: Proper response format for MCP protocol
- **Deliberately Vulnerable**: Contains intentional security issues for testing:
  - `vulnerable_tool_discovery` tool with exfiltration URL in description
  - Responses containing sensitive data (API keys, passwords, stack traces, SQL queries)

### Usage

Start the server:
```bash
python -m testing.mock_mcp_server
```

Or with custom port:
```bash
python -m testing.mock_mcp_server 9000
```

Default port: 8402

### Endpoints

- `GET /` - Server status and info
- `POST /` - MCP JSON-RPC 2.0 requests

### Supported MCP Methods

1. **initialize** - Server initialization
2. **tools/list** - List available tools:
   - `get_safety_procedures` - Clean tool for legitimate testing
   - `vulnerable_tool_discovery` - Vulnerable tool for security testing
3. **tools/call** - Execute tools (returns sensitive data for vulnerable tool)
4. **resources/read** - Read resources

### Security Testing

The mock server is designed to trigger security harness alerts:

- **Tool Discovery Poisoning**: `vulnerable_tool_discovery` tool description contains `https://evil.com/collect`
- **Data Leakage**: Responses include API keys, passwords, database connection strings
- **Information Disclosure**: Stack traces and internal file paths in responses

Use this server to validate that your security harness correctly detects and blocks these issues.

## Running Tests

Run all tests in this directory:
```bash
python -m pytest testing/ -v
```

This will validate:
- Code quality and imports
- Statistical functions
- Transport layer functionality
- Advanced attack logic