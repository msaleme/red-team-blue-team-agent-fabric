# Standard API Gateways Can't See Agent Protocol Attacks: A Quantitative Analysis

**Michael Saleme** | Signal Ops  
**Published:** 2026-03-28  
**Repository:** [red-team-blue-team-agent-fabric](https://github.com/msaleme/red-team-blue-team-agent-fabric)

---

## TL;DR

We ran a 10-test MCP protocol security harness against an Envoy Gateway + mock backend architecture two ways: through the gateway proxy and directly against the backend. The results were identical - 8/10 passed both ways. The gateway didn't catch a single additional MCP attack. Standard HTTP API gateways provide zero additional protection for agent protocol attacks because they operate at the transport layer, not at the protocol-semantic layer where these attacks live.

---

## Background: The Enterprise Security Assumption That Doesn't Hold

The Model Context Protocol (MCP) is becoming the default interface between AI agents and the tools they invoke. Anthropic released MCP as an open standard in late 2024, and adoption has been rapid: major cloud providers, IDE makers, and enterprise platforms now support MCP endpoints. Google's Agent-to-Agent (A2A) protocol handles multi-agent coordination. Together, they form the emerging backbone of agentic AI infrastructure.

Enterprise security teams, reasonably, assume their existing API gateway infrastructure provides defense-in-depth for these new protocols. The logic goes: "MCP runs over HTTP, our gateway inspects HTTP, therefore our gateway protects MCP." This assumption is wrong, and we can now prove it quantitatively.

The problem is structural. MCP uses JSON-RPC 2.0 payloads transported over HTTP. A standard API gateway like Envoy, Kong, or AWS API Gateway operates on HTTP headers, paths, query parameters, rate limits, and payload sizes. It doesn't parse the JSON-RPC body. It doesn't understand what `tools/call` means. It can't distinguish a legitimate tool invocation from a tool poisoning attack, because both look like valid HTTP POST requests with well-formed JSON bodies.

This isn't a configuration gap. It's an architectural limitation. And as enterprises deploy MCP servers behind reverse proxies and assume they're protected, the real attack surface goes unmonitored.

## Methodology

### Test Architecture

We deployed a controlled test environment with two access paths to the same backend:

```
                                    ┌─────────────────┐
  Harness ──► Envoy Proxy :8088 ──►│                  │
                                    │  Mock MCP Backend│
  Harness ──► Direct      :8402 ──►│  (8 containers)  │
                                    └─────────────────┘
```

**Gateway configuration:**
- Envoy Proxy with rate limiting (50 req/min on broker endpoint)
- Payload size limits (100KB on application endpoints)
- Standard passthrough on remaining ports
- TLS termination and header normalization enabled

**Backend configuration:**
- 8 mock containers implementing MCP JSON-RPC 2.0 endpoints
- Application-layer security controls: tool allowlists, keyword filters, authentication
- No MCP-specific proxy or middleware between the gateway and the backend

### Security Harness

We used the [Agent Security Harness](https://pypi.org/project/agent-security-harness/) v3.6.0, an open-source framework purpose-built for testing multi-agent AI deployments. The full harness includes 367 tests across 21 modules; for this study, we isolated the 10-test MCP Protocol Security suite, which targets protocol-layer attacks specific to MCP's JSON-RPC 2.0 wire format.

Each test was executed twice in sequence:
1. **Via Gateway** - routed through Envoy on port 8088
2. **Direct** - sent directly to the backend on port 8402, bypassing the gateway entirely

All other variables (payload content, timing, backend state) were held constant.

### What the Tests Cover

The MCP harness tests 10 distinct attack vectors that target the protocol semantics of MCP, not HTTP transport properties. These include tool discovery manipulation, capability boundary violations, protocol version downgrades, and resource path traversal - all of which are invisible at the HTTP layer.

## Results

| Test ID | Attack Category | Via Gateway (8088) | Direct (8402) | Gateway Delta |
|---------|----------------|-------------------|---------------|---------------|
| MCP-001 | Tool List Integrity (Poisoning) | **PASS** | **PASS** | None |
| MCP-002 | Tool Capability Escalation | **PASS** | **PASS** | None |
| MCP-003 | Cross-Origin Tool Injection | **PASS** | **PASS** | None |
| MCP-004 | Protocol Version Downgrade | FAIL | FAIL | None |
| MCP-005 | Resource URI Path Traversal | FAIL | FAIL | None |
| MCP-006 | Tool Schema Manipulation | **PASS** | **PASS** | None |
| MCP-007 | Session Hijacking via Context | **PASS** | **PASS** | None |
| MCP-008 | Prompt Injection via Tool Response | **PASS** | **PASS** | None |
| MCP-009 | Unauthorized Resource Access | **PASS** | **PASS** | None |
| MCP-010 | Tool Invocation Replay | **PASS** | **PASS** | None |

**Pass rate via Gateway:** 8/10 (80%)  
**Pass rate Direct:** 8/10 (80%)  
**Gateway additional protection:** 0/10 (0%)

The "Gateway Delta" column is the key finding. Across all 10 tests, the gateway provided zero additional defense. Every test that passed through the gateway also passed when sent directly. Every test that failed through the gateway also failed directly. The Envoy proxy was, from the MCP protocol's perspective, invisible.

## Analysis: Why Gateways Fail

The failure isn't about Envoy specifically. It's about the fundamental mismatch between what HTTP gateways inspect and where agent protocol attacks operate.

### Layer Mismatch

Standard API gateways enforce policies at **OSI Layer 7 (HTTP)**:
- Rate limiting by IP, path, or header
- Payload size enforcement
- TLS termination and certificate validation
- Header-based routing and authentication
- IP allowlisting and geo-blocking

MCP protocol attacks operate at what we call the **protocol-semantic layer** - a sublayer within the HTTP body:
- Tool discovery returns a poisoned tool list (MCP-001)
- A `tools/call` request references a tool outside the declared capability set (MCP-002)
- The protocol version field in the JSON-RPC payload is downgraded to bypass newer security features (MCP-004)
- A resource URI in the request body traverses to unauthorized paths (MCP-005)

From the gateway's perspective, all of these are valid HTTP POST requests with `Content-Type: application/json` and a well-formed body under 100KB. There is nothing to block.

### The JSON-RPC Transparency Problem

MCP wraps its protocol semantics inside JSON-RPC 2.0 envelopes. A tool poisoning attack and a legitimate tool discovery response have identical HTTP-layer signatures:

```
POST /mcp HTTP/1.1
Content-Type: application/json
Content-Length: 247

{"jsonrpc": "2.0", "method": "tools/list", "id": 1}
```

The attack happens in the *response* semantics - what tools are returned, what capabilities they claim, what URIs they reference. No amount of HTTP header inspection can catch this.

### Defense Masking

Our broader test suite (25 legacy tests run alongside the MCP harness) revealed an even more concerning pattern: **gateway-layer defenses can mask application-layer vulnerabilities**. In test RT-012 (A2A Recursion Loop), Envoy's rate limiter returned 429 before the backend could process the circular dependency. The recursion vulnerability exists in the backend, but it's invisible because the rate limiter catches the request volume first. If the rate limit is later increased - during a capacity expansion, load test, or traffic spike - the underlying vulnerability re-emerges with no warning.

This isn't defense-in-depth. It's defense-as-obstruction-of-visibility.

## What Would Work Instead

If standard gateways can't see these attacks, what can?

### 1. MCP-Aware Proxy

A proxy that understands MCP semantics could parse JSON-RPC payloads and enforce protocol-level policies: tool allowlists, capability boundary validation, version pinning, resource URI restrictions. This is analogous to how a WAF understands SQL syntax to catch injection, but applied to MCP's tool invocation protocol. No production-grade MCP-aware proxy exists today; this is an open infrastructure gap.

### 2. Protocol Inspection Controls (PIC-Style Guards)

Inline guards that sit between the agent and the MCP server, inspecting each request and response for semantic violations. These could enforce invariants like "this agent may only call tools X, Y, Z" or "resource URIs must match pattern P." The key is that these guards must operate on the deserialized MCP payload, not the HTTP envelope.

### 3. Attestation-Based Trust

Rather than trying to inspect every request in real-time, attestation shifts the model to pre-deployment verification. Our [attestation schema](https://github.com/msaleme/red-team-blue-team-agent-fabric/blob/main/schemas/attestation-report.json) (proposed as an interoperability standard) provides a machine-readable format for recording security test results. An MCP server that publishes an attestation report is saying: "Here's what was tested, here's what passed, here's what failed." Consumers can make trust decisions based on this evidence. This complements real-time inspection - attestation covers the known attack surface; runtime guards catch novel threats.

### 4. Decision-Layer Governance

Some agent security failures aren't protocol-level at all. Our research on the Decision Load Index [1] and Normalization of Deviance [2] shows that agents can fail through gradual behavioral drift even when every individual request is protocol-compliant. Detecting this requires stateful session tracking and trend analysis - capabilities that are architecturally impossible in a stateless HTTP gateway.

## Conclusion

The quantitative evidence is clear: standard API gateways provide zero additional protection for MCP protocol attacks. This isn't a misconfiguration. It's a structural limitation of inspecting HTTP transport properties when attacks live inside JSON-RPC protocol semantics.

As enterprise adoption of MCP accelerates, security teams need to update their threat models. Putting an MCP server behind Envoy, Kong, or an AWS API Gateway does not make it secure against protocol-level attacks. Organizations need MCP-aware security controls - whether inline proxies, attestation systems, or both.

The full test harness, attestation schema, and methodology are open source:

- **Repository:** [msaleme/red-team-blue-team-agent-fabric](https://github.com/msaleme/red-team-blue-team-agent-fabric)
- **PyPI:** [agent-security-harness](https://pypi.org/project/agent-security-harness/)
- **Attestation Schema:** [schemas/attestation-report.json](https://github.com/msaleme/red-team-blue-team-agent-fabric/blob/main/schemas/attestation-report.json)

We welcome contributions, especially from teams building MCP-aware proxies or integrating attestation into agent registries.

---

## References

1. Saleme, M. (2026). "Decision Load Index: A Quantitative Framework for Agent Autonomy Risk." Zenodo. [https://doi.org/10.5281/zenodo.18217577](https://doi.org/10.5281/zenodo.18217577)
2. Saleme, M. (2026). "Normalization of Deviance in Autonomous Agent Systems." Zenodo. [https://doi.org/10.5281/zenodo.15105866](https://doi.org/10.5281/zenodo.15105866)
3. Saleme, M. (2026). "Cognitive Style Governance for Multi-Agent Deployments." Zenodo. [https://doi.org/10.5281/zenodo.15106553](https://doi.org/10.5281/zenodo.15106553)
4. CVE-2026-25253. "MCP Tool Injection via Compromised Upstream Server." [https://nvd.nist.gov/vuln/detail/CVE-2026-25253](https://nvd.nist.gov/vuln/detail/CVE-2026-25253)
5. AIUC-1. "AI Use Case 1: Pre-Certification Requirements for Autonomous Agent Systems." [https://aiuc.dev](https://aiuc.dev)
6. Anthropic. "Model Context Protocol Specification." [https://spec.modelcontextprotocol.io](https://spec.modelcontextprotocol.io)
7. Google. "Agent-to-Agent Protocol." [https://google.github.io/A2A](https://google.github.io/A2A)

---

*This post is based on live test runs against Envoy Gateway + mock backends conducted on 2026-03-23 and 2026-03-25. Raw test reports are available in the repository.*
