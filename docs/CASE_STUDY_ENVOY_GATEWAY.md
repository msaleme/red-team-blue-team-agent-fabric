# Case Study: Envoy Gateway + Agent Security Harness

## Architecture

```
Red Team Suite --> Envoy Proxy (ports 8081-8088) --> 8 Mock Backend Containers
├── Rate limiting (50 req/min on broker)
├── Payload size limit (100KB on app1)
└── Passthrough on other ports
```

## Results

- Legacy Suite: 18/25 passed (72%)
- MCP Protocol Harness: 6/10 passed (60%)

## Key Finding: Gateway-Layer Defense Masking

RT-012 (A2A Recursion Loop) revealed that gateway-layer defenses can mask application-layer vulnerabilities. The Envoy rate limiter returned 429 before the backend could evaluate the circular dependency. The recursion bug exists in the backend, but it's invisible because the rate limiter catches the request volume first.

**Implication:** Defense-in-depth can create blind spots. If the rate limit is later tuned up (e.g., during load testing or capacity expansion), the underlying recursion vulnerability re-emerges with no warning. Organizations should test at both the gateway layer AND directly against backends with gateway bypassed.

## Finding: JSON-RPC Bypasses Gateway HTTP Policies

MCP protocol tests (JSON-RPC 2.0 payloads) pass through standard HTTP proxies unmodified. Envoy's rate limiting and payload size policies operate at the HTTP level - they don't understand MCP semantics. Only application-layer MCP validation catches protocol-specific attacks like tool discovery poisoning (MCP-001), protocol version downgrade (MCP-004), and resource URI traversal (MCP-005).

**Implication:** Running MCP servers behind a reverse proxy provides HTTP-level protection but zero protocol-level security. Organizations need MCP-aware security controls in addition to standard gateway defenses.

## Finding: Normalization of Deviance Goes Undetected

RT-024 tested for gradual drift in agent behavior (the Challenger disaster pattern). The system accepted a 19.3% parameter drift without triggering any alert. This confirms that threshold-based monitoring misses slow, incremental behavioral changes.

**Implication:** Static thresholds don't catch normalization of deviance. Systems need trend analysis or behavioral baseline comparison to detect gradual drift.

## Defense Layer Analysis

| Attack | Expected Block Layer | Actual Block Layer | Result |
|---|---|---|---|
| RT-009 Long-Context | Gateway (payload size) | Envoy 100KB limit (413) | PASS - gateway caught it |
| RT-008 Orchestration Flood | Gateway (rate limit) | Envoy rate limiter (429) | PASS - 55% throttled |
| RT-012 A2A Recursion | Application (loop detect) | Envoy rate limiter (429) | Masked - gateway hid app vulnerability |
| MCP-001 Tool Poisoning | Application (MCP validation) | Application | PASS - gateway can't see MCP semantics |
| MCP-004 Version Downgrade | Application (MCP validation) | Neither | FAIL - no layer caught it |
| RT-024 Deviance Drift | Application (monitoring) | Neither | FAIL - 19.3% drift undetected |

## Test Environment

- Gateway: Envoy Proxy with rate limiting (50 req/min) and payload size limits (100KB)
- Backends: 8 mock containers with basic security controls (allowlists, keyword filters, auth)
- Harness: agent-security-harness v3.2.0
- Date: 2026-03-23

## Relevance to AIUC-1

This test run produces evidence relevant to AIUC-1 certification requirements:
- B001 (adversarial robustness): 25 adversarial tests executed with full request/response logs
- D003 (restrict unsafe tool calls): MCP tool injection and capability escalation tested
- D004 (third-party testing of tool calls): 10 MCP protocol-level tests executed

The gateway-masking finding (RT-012) is directly relevant to AIUC-1 auditors evaluating defense-in-depth architectures: a passing gateway test does not guarantee the underlying application is secure.

## Reports

- red_team_report_20260323_155553.json (122KB)
- mcp_via_gateway_report.json (9KB)

---
_Generated from a live test run against Envoy Gateway + mock backends, 2026-03-23._