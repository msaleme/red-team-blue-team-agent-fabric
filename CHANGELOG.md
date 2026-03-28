# Changelog

All notable changes to the Agent Security Harness will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - v3.8.0

### Added
- **Attestation JSON Schema** (`schemas/attestation-report.json`) - Machine-readable report format compatible with A2A OATR, consumable by MoltBridge and TrustAgentAI (#1677)
- **Scope annotations** on every test entry: `protocol`, `layer`, `attack_type`, `target_component` for precise localization of findings
- **Remediation annotations** on every test entry: `description`, `references[]`, `priority` for actionable fix guidance
- **Agent identity metadata** per entry: `agent_card_url`, `operator_id`, `trust_score` for OATR integration
- **Attestation report validation** utility (`protocol_tests/attestation.py`) with schema validation and v3.7-to-v3.8 migration
- **v3.8 roadmap** (`docs/v3.8-roadmap.md`) with MoltBridge/TrustAgentAI mapping documentation

### Changed
- Report format extended to attestation schema (backward-compatible; legacy format still emittable)

### Planned
- OATR test fixtures for x402 identity verification (#51)
- x402 `--method` and `--body` flags for POST-only payment endpoints (#58)
- Subliminal bias propagation tests (#60)

## [3.7.0] - 2026-03-25

### Added
- 367 security tests across 21 modules
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
