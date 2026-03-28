# Changelog

All notable changes to the Agent Security Harness will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.8.0] - 2026-03-28

### Added
- **Attestation JSON Schema** (`schemas/attestation-report.json`) - Machine-readable report format compatible with A2A OATR, consumable by MoltBridge and TrustAgentAI (#1677)
- **Scope annotations** on every test entry: `protocol`, `layer`, `attack_type`, `target_component` for precise localization of findings
- **Remediation annotations** on every test entry: `description`, `references[]`, `priority` for actionable fix guidance
- **Agent identity metadata** per entry: `agent_card_url`, `operator_id`, `trust_score` for OATR integration
- **Attestation report validation** utility (`protocol_tests/attestation.py`) with schema validation and v3.7-to-v3.8 migration
- **v3.8 roadmap** (`docs/v3.8-roadmap.md`) with MoltBridge/TrustAgentAI mapping documentation
- x402 `--method` and `--body` flags for POST-only payment endpoints (#58)
- **MCP-012** Tool Description Oversized Check - detects descriptions exceeding 10KB threshold for context displacement
- **MCP-013** Tool Description Padding / Repetition Detection - detects repeated phrases, whitespace padding, and low-entropy descriptions

### Fixed
- `count_tests.py` now catches test IDs passed as function arguments (AIUC-F002a/b/c), adds 3 missing IDs
- `count_tests.py` excludes synthetic `CVE-ERR` error-handler ID from count
- Definitive test count corrected to **332** across 21 modules
- `action.yml` parse-report step converted from shell-interpolated Python to heredoc+env pattern (no more `${REPORT}` injection)
- `a2a_harness.py` `--trials` flag now wired into statistical report enhancement
- `harmful_output_harness.py` `--categories` flag now filters tests by category
- `cloud_agent_harness.py` gains `--trials` and `--categories` flags with full implementation

### Changed
- Report format extended to attestation schema (backward-compatible; legacy format still emittable)

### Planned
- OATR test fixtures for x402 identity verification (#51)
- Subliminal bias propagation tests (#60)

## [3.7.0] - 2026-03-25

### Added
- 332 security tests across 21 modules
- OATR fixture loader (`protocol_tests/oatr_fixtures.py`)
- x402 payment flow harness with L402 interop
- CVE-2026-25253 supply chain provenance tests
- AIUC-1 pre-certification compliance harness
- Cloud agent platform adapters (Vertex, Bedrock, Azure AI Agent Service)
- Enterprise platform adapters (ServiceNow, Salesforce AgentForce, etc.)
- GTG-1002 APT simulation module
- Jailbreak resistance harness (DAN, token smuggling, authority impersonation)
- Over-refusal / false positive rate testing
- Statistical confidence intervals (--trials flag)
- Return channel poisoning tests
- Framework adapters (AutoGen, CrewAI, LangGraph, Semantic Kernel)
