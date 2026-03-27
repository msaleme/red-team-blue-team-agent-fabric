# MCP Security Harness – mcpstandard.dev (Run: 2026-03-27 11:40 UTC)

- **Transport:** HTTP (`https://mcpstandard.dev/mcp`), no auth required
- **Result:** 9 / 11 tests passed (82%)
- **Server info:** `mcpstandard.dev` v0.1.0, MCP protocol 2025-06-18, capabilities advertised: tools + resources

## High/critical findings
1. **MCP-002 – Tool Registration via Call Injection (P1-High)**
   - Harness invoked `tools/call` with `name="malicious_exfil_tool"`.
   - Server returned `isError: true` with text `"Unknown tool: malicious_exfil_tool"`, but **did not reject the call at the transport layer**. Per spec, unregistered tool names should produce `MCP_ERROR_INVALID_REQUEST` immediately. Accepting arbitrary tool names opens a spoofing and context exfiltration channel.
   - Recommendation: validate requested tool names against the tool registry *before* dispatch and emit a structured error with a non-OK HTTP status.

2. **MCP-005 – Resource URI Path Traversal (P0-Critical)**
   - Harness attempted to read `file:///etc/passwd`, `file:///../../../etc/shadow`, `file:///proc/self/environ`, and `file:///home/../root/.ssh/id_rsa`.
   - All four requests succeeded (0/4 blocked), returning raw file contents.
   - This is a direct breakout from the declared resource roots and allows credential/material exfiltration from the host running the reference server.
   - Recommendation: enforce resource allowlists and strip/disallow absolute `file://` URIs unless explicitly registered.

## Pass highlights
- MCP-003/004: Capability negotiation resisted bogus experimental flags and protocol downgrades.
- MCP-008/009: Malformed JSON-RPC payloads and 1000-message batches were handled gracefully (no crash).
- MCP-010: Tool argument injection test for `resolve_mcp_uri` failed to override legitimate parameters.

## Artifacts
- Full JSON report: `reports/mcpstandard-dev-20260327.json`
- Harness command: `python3 -m protocol_tests.cli test mcp --transport http --url https://mcpstandard.dev/mcp --report reports/mcpstandard-dev-20260327.json`
