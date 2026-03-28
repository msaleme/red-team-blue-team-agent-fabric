# Agent Security Attestation Report Format

**Status:** Draft  
**Version:** 0.1.0  
**Date:** 2026-03-28  
**Authors:** Michael Saleme (Signal Ops)  
**Repository:** [msaleme/red-team-blue-team-agent-fabric](https://github.com/msaleme/red-team-blue-team-agent-fabric)  
**Schema:** [schemas/attestation-report.json](https://github.com/msaleme/red-team-blue-team-agent-fabric/blob/main/schemas/attestation-report.json)

---

## Abstract

This document proposes a standard JSON format for reporting agent protocol security test results. The **Agent Security Attestation Report** provides a machine-readable, schema-validated structure for recording what was tested, what passed or failed, the severity and scope of each finding, and actionable remediation guidance. The format is designed for interoperability across security testing tools, CI/CD pipelines, agent registries, and trust evaluation systems.

## 1. Motivation

### 1.1 The Problem

The agent protocol ecosystem (MCP, A2A, L402, x402) is growing rapidly, but there is no standard way to communicate security test results between testing tools, deployment pipelines, and trust systems. Today:

- **Testing tools** produce bespoke output formats (plain text, custom JSON, HTML reports) that require per-tool parsing.
- **CI/CD pipelines** cannot enforce security gates without custom integration code for each testing tool.
- **Agent registries and directories** (A2A AgentCards, MCP tool registries) have no standard field for linking to security attestation evidence.
- **Trust evaluation systems** (OATR, MoltBridge, TrustAgentAI) must reverse-engineer tool-specific output to extract structured findings.
- **Auditors and compliance teams** (AIUC-1) cannot compare security postures across vendors without a common reporting format.

### 1.2 Why Now

Three developments make standardization urgent:

1. **CVE-2026-25253** (MCP Tool Injection via Compromised Upstream Server) demonstrated that MCP protocol attacks are real, not theoretical. Security testing must produce actionable, comparable evidence.
2. **AIUC-1 pre-certification** requires documented evidence of adversarial testing (B001), tool call restriction testing (D003), and third-party tool call testing (D004). A standard format enables automated compliance checking.
3. **Multi-vendor convergence** - multiple teams are building agent security testing tools. Without a common output format, the ecosystem fragments before it matures.

### 1.3 Design Goals

- **Machine-readable and human-inspectable** - valid JSON with descriptive field names
- **Schema-validated** - JSON Schema draft-2020-12 for tooling compatibility
- **Protocol-agnostic** - supports MCP, A2A, L402, x402, and custom protocols via enumerated scope fields
- **Layered** - maps to the three-layer agent security model (protocol, operational, decision)
- **Extensible** - new protocols, severity levels, and scope types can be added without breaking existing consumers
- **Compatible** - aligns with A2A OATR concepts and AIUC-1 requirements

## 2. Schema Overview

The canonical schema is published at `schemas/attestation-report.json` in the repository. This section provides a narrative overview; the schema file is the normative reference.

### 2.1 Top-Level Structure

```json
{
  "schema_version": "1.0.0",
  "harness_version": "3.8.0",
  "suite": "MCP Protocol Security Tests v3.0",
  "timestamp": "2026-03-28T10:00:00Z",
  "target": "http://localhost:8080/mcp",
  "summary": {
    "total": 10,
    "passed": 8,
    "failed": 2,
    "errored": 0,
    "skipped": 0
  },
  "entries": [ ... ]
}
```

### 2.2 Entry Structure

Each entry in the `entries` array represents a single test execution:

```json
{
  "test_id": "MCP-001",
  "name": "Tool List Integrity Check",
  "category": "tool_poisoning",
  "result": "pass",
  "severity": "P0-Critical",
  "scope": {
    "protocol": "mcp",
    "layer": "protocol",
    "attack_type": "tool injection",
    "target_component": "tools/list"
  },
  "remediation": {
    "description": "Validate tool lists against a pinned allowlist.",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-25253"],
    "priority": "immediate"
  },
  "timestamp": "2026-03-28T10:00:01Z",
  "elapsed_s": 0.342,
  "protocol_version": "2024-11-05"
}
```

## 3. Field Definitions

### 3.1 Report-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string (const `"1.0.0"`) | Yes | Version of this attestation schema. Consumers should reject reports with unrecognized major versions. |
| `harness_version` | string | Yes | Semantic version of the testing tool that generated this report. Enables reproducibility. |
| `suite` | string | Yes | Human-readable name of the test suite executed. |
| `timestamp` | string (ISO 8601) | Yes | When the report was generated. Must be UTC or include timezone offset. |
| `target` | string | No | URL, command, or identifier for the system under test. Omit if the report aggregates multiple targets. |
| `summary` | object | Yes | Aggregate counts of test outcomes. See 3.2. |
| `entries` | array | Yes | Individual test results. See 3.3. |

### 3.2 Summary Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `total` | integer (>=0) | Yes | Total number of test entries in the report. Must equal `len(entries)`. |
| `passed` | integer (>=0) | Yes | Count of entries with `result: "pass"`. |
| `failed` | integer (>=0) | Yes | Count of entries with `result: "fail"`. |
| `errored` | integer (>=0) | No | Count of entries with `result: "error"` (test infrastructure failure). |
| `skipped` | integer (>=0) | No | Count of entries with `result: "skip"` (test not applicable to target). |

**Invariant:** `passed + failed + errored + skipped == total`

### 3.3 Entry Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `test_id` | string | Yes | Unique identifier for the test (e.g., `MCP-001`, `A2A-005`, `X4-021`). Should be stable across harness versions. |
| `name` | string | No | Human-readable test name. |
| `category` | string | Yes | Grouping key (e.g., `tool_poisoning`, `capability_escalation`, `payment_flow`). |
| `result` | enum | Yes | One of: `pass`, `fail`, `error`, `skip`. |
| `severity` | enum | Yes | Priority classification: `P0-Critical`, `P1-High`, `P2-Medium`, `P3-Low`, `P4-Info`. |
| `scope` | object | Yes | Localization metadata. See 3.4. |
| `remediation` | object | No | Actionable fix information. See 3.5. |
| `timestamp` | string (ISO 8601) | Yes | When this individual test was executed. |
| `elapsed_s` | number (>=0) | No | Wall-clock duration in seconds. |
| `agent_identity` | object | No | Identity metadata for the agent under test. See 3.6. |
| `protocol_version` | string | No | Wire protocol version tested (e.g., `2024-11-05`). |
| `owasp_asi` | string | No | OWASP Agentic Security Initiative mapping (e.g., `ASI04`). |
| `statistical` | object | No | Multi-trial statistical data. See 3.7. |
| `details` | string or object | No | Free-form evidence, diagnostic output, or structured metadata. |
| `request_sent` | object | No | The request payload sent during the test (for audit evidence). |
| `response_received` | object | No | The response payload received (for audit evidence). |

### 3.4 Scope Object

Scope answers three questions: *what protocol*, *what security layer*, and *what component was attacked*.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `protocol` | enum | Yes | Target protocol: `mcp`, `a2a`, `l402`, `x402`, `platform`, `framework`, `enterprise`, `decision`, `other`. |
| `layer` | enum | Yes | Security layer: `protocol` (wire-level), `operational` (capability/session), `decision` (autonomy/governance). |
| `attack_type` | string | No | Human-readable attack classification (e.g., "tool injection", "receipt replay"). |
| `target_component` | string | No | Specific endpoint, method, or feature targeted (e.g., "tools/call", "agent-card"). |

### 3.5 Remediation Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `description` | string | No | Plain-language remediation guidance. |
| `references` | array of URIs | No | Links to relevant specs, CVEs, OWASP entries. |
| `priority` | enum | No | Triage hint: `immediate`, `next-release`, `backlog`. |

### 3.6 Agent Identity Object

Connects the attestation to the agent's published identity, enabling trust chain verification.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_card_url` | string (URI) | No | A2A agent card URL for identity resolution. |
| `operator_id` | string | No | OATR operator identifier. |
| `trust_score` | number (0-100) | No | Computed trust score based on test outcomes and historical data. |

### 3.7 Statistical Object

For tests that run multiple trials to establish statistical confidence.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `trials` | integer (>=1) | No | Number of trial runs. |
| `pass_rate` | number (0.0-1.0) | No | Fraction of trials that passed. |
| `confidence_interval` | array [lower, upper] | No | 95% confidence interval bounds. |

## 4. Integration Points

### 4.1 A2A AgentCards

A2A AgentCards describe an agent's capabilities and contact information. We propose adding an optional `securityAttestation` field:

```json
{
  "name": "My MCP Agent",
  "url": "https://agent.example.com/.well-known/agent.json",
  "securityAttestation": {
    "reportUrl": "https://agent.example.com/attestation/latest.json",
    "schemaVersion": "1.0.0",
    "lastTested": "2026-03-28T10:00:00Z",
    "summary": {
      "total": 209,
      "passed": 201,
      "failed": 8
    }
  }
}
```

This enables agent discovery systems to surface security posture alongside capability metadata, without requiring consumers to fetch and parse full reports.

### 4.2 MCP Tool Registries

MCP tool registries that catalog available tools and servers can include attestation metadata per registered server:

- **Registry-side:** Store the latest attestation report URL and summary for each registered MCP server.
- **Client-side:** Before connecting to an MCP server, clients can check the registry for attestation data and apply trust policies (e.g., "only connect to servers with 0 P0-Critical failures").
- **CI/CD gate:** During deployment, validate that the target MCP server's attestation report meets organizational thresholds.

### 4.3 OATR (Operator Attestation and Trust Registry)

The A2A Operator Attestation and Trust Registry (OATR) provides a framework for operator-level trust evaluation. This schema extends OATR concepts with test-specific fields:

| OATR Concept | Attestation Schema Field | Relationship |
|--------------|-------------------------|--------------|
| Operator identity | `agent_identity.operator_id` | Direct mapping |
| Trust evaluation | `agent_identity.trust_score` | Derived from test results |
| Attestation evidence | `entries[]` with `request_sent`/`response_received` | Detailed evidence |
| Capability claims | `scope.protocol` + `scope.target_component` | What was tested |

OATR registries can consume attestation reports as trust signals, updating operator trust scores based on test outcomes.

### 4.4 CI/CD Pipeline Integration

Attestation reports can serve as pipeline gates:

```yaml
# Example: GitHub Actions gate
- name: Run security harness
  run: agent-security-harness run --format attestation --output report.json

- name: Check attestation
  run: |
    FAILED=$(jq '.summary.failed' report.json)
    P0=$(jq '[.entries[] | select(.result=="fail" and .severity=="P0-Critical")] | length' report.json)
    if [ "$P0" -gt 0 ]; then
      echo "P0-Critical failures detected - blocking deployment"
      exit 1
    fi
```

## 5. Mapping to AIUC-1

The AIUC-1 pre-certification framework requires specific categories of evidence. The following table maps AIUC-1 requirements to attestation report fields that provide the corresponding evidence.

| AIUC-1 Requirement | Description | Attestation Fields | How It Maps |
|---------------------|-------------|-------------------|-------------|
| B001 | Adversarial robustness testing | `entries[]` where `scope.layer == "protocol"` | Each entry with a protocol-layer scope documents an adversarial test execution and outcome. |
| C010 | Monitoring and logging | `entries[].request_sent`, `entries[].response_received`, `entries[].timestamp` | Request/response payloads with timestamps provide audit-grade monitoring evidence. |
| D003 | Restrict unsafe tool calls | `entries[]` where `category == "tool_poisoning"` or `category == "capability_escalation"` | Tests that verify tool call restrictions map directly to D003 evidence. |
| D004 | Third-party testing of tool calls | `harness_version`, `suite`, `summary` | The harness version and suite name document which third-party testing tool was used and its aggregate results. |

### 5.1 Generating AIUC-1 Evidence Packages

An attestation report can be filtered to produce AIUC-1-specific evidence:

```bash
# Extract B001-relevant entries
jq '{
  requirement: "B001",
  evidence: [.entries[] | select(.scope.layer == "protocol")]
}' report.json > aiuc1-b001-evidence.json

# Extract D003-relevant entries
jq '{
  requirement: "D003",
  evidence: [.entries[] | select(
    .category == "tool_poisoning" or 
    .category == "capability_escalation"
  )]
}' report.json > aiuc1-d003-evidence.json
```

## 6. Security Considerations

### 6.1 Report Integrity

Attestation reports are trust-bearing documents. A tampered report could falsely claim passing results. Implementations SHOULD:

- Sign reports using a verifiable key (e.g., Sigstore cosign, GPG)
- Include a content hash in the report metadata
- Publish reports at stable, HTTPS-only URLs

### 6.2 Sensitive Data in Evidence Fields

The `request_sent`, `response_received`, and `details` fields may contain sensitive information (API keys, tokens, PII from test fixtures). Implementations MUST:

- Redact credentials before publishing reports
- Apply data classification policies to evidence fields
- Provide a `--redact` flag in report generation tooling

### 6.3 Replay and Freshness

A valid attestation report from six months ago may not reflect the current security posture. Consumers SHOULD:

- Check the `timestamp` field against a staleness threshold
- Require periodic re-testing (e.g., within 30 days for production systems)
- Treat `harness_version` mismatches as a signal to re-test

### 6.4 Trust Score Gaming

The optional `trust_score` field is computed, not inherent. Operators could run tests against artificially permissive backends to inflate scores. Mitigations include:

- Third-party attestation (testing performed by an independent party)
- Cross-referencing with production incident data
- Requiring specific test suite identifiers (not arbitrary custom suites)

### 6.5 Schema Versioning

The `schema_version` field uses semantic versioning. Consumers MUST reject reports with unrecognized major versions and SHOULD warn on minor version mismatches. Backward-compatible additions (new optional fields) increment the minor version; breaking changes increment the major version.

## 7. Future Work

- **Cryptographic signatures** - embed report signing into the schema itself (e.g., a `signature` top-level field with JWS or COSE)
- **Differential reports** - a format for expressing "what changed between two test runs"
- **Aggregate reports** - roll up multiple per-server reports into an organization-level security posture view
- **SBOM integration** - link attestation reports to Software Bill of Materials for supply chain traceability

## 8. References

1. Agent Security Harness Repository. [https://github.com/msaleme/red-team-blue-team-agent-fabric](https://github.com/msaleme/red-team-blue-team-agent-fabric)
2. Attestation Report JSON Schema. [schemas/attestation-report.json](https://github.com/msaleme/red-team-blue-team-agent-fabric/blob/main/schemas/attestation-report.json)
3. CVE-2026-25253. "MCP Tool Injection via Compromised Upstream Server." [https://nvd.nist.gov/vuln/detail/CVE-2026-25253](https://nvd.nist.gov/vuln/detail/CVE-2026-25253)
4. Saleme, M. (2026). "Decision Load Index: A Quantitative Framework for Agent Autonomy Risk." Zenodo. DOI: [10.5281/zenodo.18217577](https://doi.org/10.5281/zenodo.18217577)
5. Saleme, M. (2026). "Cognitive Style Governance for Multi-Agent Deployments." Zenodo. DOI: [10.5281/zenodo.15106553](https://doi.org/10.5281/zenodo.15106553)
6. Saleme, M. (2026). "Normalization of Deviance in Autonomous Agent Systems." Zenodo. DOI: [10.5281/zenodo.15105866](https://doi.org/10.5281/zenodo.15105866)
7. AIUC-1. "AI Use Case 1: Pre-Certification Requirements for Autonomous Agent Systems." [https://aiuc.dev](https://aiuc.dev)
8. Google. "Agent-to-Agent Protocol." [https://google.github.io/A2A](https://google.github.io/A2A)
9. Anthropic. "Model Context Protocol Specification." [https://spec.modelcontextprotocol.io](https://spec.modelcontextprotocol.io)
10. OWASP. "Agentic Security Initiative." [https://owasp.org/www-project-agentic-security-initiative/](https://owasp.org/www-project-agentic-security-initiative/)
11. JSON Schema. "Draft 2020-12." [https://json-schema.org/draft/2020-12/schema](https://json-schema.org/draft/2020-12/schema)

---

*This proposal is released under Apache 2.0. Comments and contributions welcome via GitHub issues or A2A spec discussions.*
