# Scope: what the harness tests, and what it does not

The harness sends adversarial traffic to an agent-facing **protocol surface** and grades what
the target serviced: an MCP server over stdio or Streamable HTTP, an A2A endpoint, an x402 or
L402 payment endpoint, and the other harness targets listed in
[TEST-INVENTORY.md](TEST-INVENTORY.md). Each test is written against the protocol, so it applies
to any implementation of that surface.

This page records surfaces that are deliberately **out of scope**, so that a gap is a stated
decision rather than an omission. A surface listed here can move in scope later; the decision
and its reason are recorded with it.

## Out of scope: vendor gateway control planes

**Decided 2026-11-18.** The management APIs of specific MCP gateway products (registering and
updating upstream servers, creating adapters and tools, tenancy and naming) are not tested by
the harness.

**Why.** Each control plane is a product-specific API, not a protocol. Testing one needs a
per-vendor adapter (and, for Kubernetes-backed gateways, a cluster fixture), so coverage would
grow one vendor at a time and would have to track each vendor's API changes. That turns a
protocol tester into a per-product scanner. What *is* in scope is the traffic those gateways
proxy: an MCP server reached through a gateway is tested like any other MCP server.

**The risk patterns are real.** Two November 2026 disclosures show what an operator should check
in their own gateway, outside this harness:

| Pattern | Example | What to check |
|---|---|---|
| **A registry trusts the address it is given.** An authenticated registrant sets an upstream on the internal network and the gateway requests it (SSRF from the control plane). | CVE-2026-125926, `mcp-gateway-registry` ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-125926), [AWS bulletin 2026-180-AWS](https://aws.amazon.com/security/security-bulletins/2026-180-aws/)). Tracked in [#712](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/712) (closed: out of scope). | Registration **and** update reject internal, link-local and loopback upstreams. After upgrading, review upstreams registered while an affected version ran: validation at registration time does not clean up stored configuration. |
| **A gateway trusts the name it is given.** Creating a resource under a name another user's object already holds succeeds and transfers ownership (cross-tenant workload takeover). | CVE-2026-109492, Microsoft MCP Gateway ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109492), [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-109492)). Tracked in [#713](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/713) (closed: out of scope). | Names are unique across tenants or namespaced; built-in names are reserved; creation fails when the underlying object already exists, rather than adopting it. |

**Related, and in scope.** Control-plane SSRF in OAuth Dynamic Client Registration ([#714](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/714)) and an
MCP client sending credentials to a server-chosen authorization server ([#715](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/715)) are protocol
behaviour, not product management APIs. Both are planned with the MCP authorization-flow work.
