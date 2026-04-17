# Changelog

All notable changes to the Agent Security Harness will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.4.0] - 2026-04-17

**Theme: Accuracy + Infrastructure.** Bump to 470 tests, add pyyaml as core dependency, fix all stale test counts and module counts across docs, add missing CI imports, Python 3.13 to matrix.

### Added

- MCP-018: Unbounded request body DoS test (CVE-2026-39313)
- DGB evaluation runner — 3 configs, 52 cases, Section 5 baseline data
- Python 3.13 to CI matrix
- `pyyaml>=6.0` as core dependency (was only installed ad hoc in CI)
- 4 missing module imports in CI workflow (benchmark_integrity, governance_modification, skill_security, community_runner)

### Fixed

- All test counts updated from 466 to 470 across README, pyproject.toml, ROADMAP, docs, CLAUDE.md, free_scan.py
- All stale "439 tests across 29 modules" updated to "470 tests across 32 modules" in docs, STRATEGY, QUICKSTART, submission docs
- AIUC-1 crosswalk: "Maps to all 24 requirements" corrected to "Maps to 19 of 20 testable requirements"
- AIUC-1 crosswalk: stale "431 executable tests" updated to 470
- MCP comparison table: "14 tests" corrected to "18 tests"
- Regex literal mismatch in HC-5 check and missing sanity-check failures
- 10 Cursor Bugbot issues across 5 files (adapters, CVE, SSP, corpus)
- MCP harness Bugbot issues (MCP-015/016/018)
- Governance harness Bugbot issues (4 issues in GM harness)

### Changed

- `protocol_tests/__init__.py` version comment updated from v3.0 to v4.4
- CI import count updated from 32 to 36 modules

## [4.3.0] - 2026-04-15

**Theme: Supply Chain + Corpus.** Skill Security Protocol harness, Decision Behavior Benchmark corpus, DRY infrastructure.

### Added

- Skill Security Protocol harness (SS-001 through SS-008) — RFC #99, manifest integrity, permission validation, prompt injection, exfiltration, Ed25519 provenance, capability escalation, sandboxing, update tampering
- Decision Behavior Benchmark corpus — 52 cases, 5 categories (escalation bypass, collusion, memory tampering, payment/tool chain, evidence fabrication)
- Cross-reference to constitutional-agent governance package

### Changed

- HIDDEN_INSTRUCTION_PATTERN extracted to `_utils.py` (DRY — was duplicated in mcp_harness and skill_security_harness)
- Dynamic test count in CLI derived from HARNESSES registry at runtime

### Fixed

- P0/P1/P2 cleanup: stale VERSION string, dynamic test count, DRY pattern, corpus gaps
- Test count synchronized to 466 across all files

## [4.2.0] - 2026-04-12

**Theme: Incident-Tested.** Every new module maps to a named April 2026 security incident.

### Added

- Benchmark Integrity harness (BI-001 through BI-007) — UC Berkeley: all 8 AI benchmarks hackable
- Governance Modification harness (GM-001 through GM-006) — lightningzero: 9/12 agents disabled own gates
- PraisonAI adapter (PA-001 through PA-004) — CVE-2026-40288 (9.8), CVE-2026-40289 (9.1), CVE-2026-39889, CVE-2026-39891
- MCP-015/016/017: SSRF and STDIO pre-handshake tests — OX Security disclosure, BlueRock 36.7% SSRF finding
- CVE-009, CVE-010: OpenClaw privilege escalation and SSRF tests
- `ash` short alias for agent-security CLI

### Changed

- Shared `_utils.py` extracted (SOLID/DRY), CLI registration for new modules

### Fixed

- MCP harness: dead imports, GCP/Azure SSRF targets, canary finally block
- PraisonAI adapter: simulate flag, base signature, docs
- Harness count assertion updated

## [4.1.0] - 2026-04-10

**Theme: Compliance Evidence.** EU AI Act + ISO 42001 mapping, AUROC, FRIA, kill-switch, watermark tests.

### Added

- AUROC per-module metrics — detection effectiveness scoring
- EU AI Act crosswalk — 16 controls across Articles 9-72
- ISO 42001 crosswalk — 15 controls across Clauses 5-10 + Annex A
- Kill-switch compliance tests (IR-009 through IR-012) — CA SB 942 + EU AI Act Art 14
- FRIA evidence collection — 6 categories, EU AI Act Article 27
- Watermark adversarial tests (WM-001 through WM-005) — EU AI Act Article 50
- HTML compliance report generator — `--framework all --fria` one-command report
- Simulate mode expansion for MCP, A2A, Identity (39 new simulate tests)

## [3.10.0] - 2026-04-08

**Theme: Prove It to Auditors.** Evidence format adoption, payment protocol depth, behavioral drift scoring, and audit-ready reporting. The release where the project transitions from a testing harness to a verification standard.

### Added — New Modules (5)

- **Memory & Continuity Security** (`memory_harness.py`, 10 tests) — Cross-session leakage, RAG poisoning, context overflow, memory-based privilege escalation, cross-user contamination (#119)
- **Multi-Agent Interaction Security** (`multi_agent_harness.py`, 12 tests) — Delegation chain poisoning, authority impersonation, consensus manipulation, capability leakage, agent replacement (#117)
- **Intent Contract Validation** (`intent_contract_harness.py`, 8 tests) — Intent-action consistency, scope violation, implicit escalation, contract forgery, ambiguity exploitation (#116)
- **CrewAI CVE Reproduction** (`crewai_cve_harness.py`, 10 tests) — CVE-2026-2275 (sandbox escape), CVE-2026-2285 (file read), CVE-2026-2286 (SSRF), CVE-2026-2287 (Docker bypass) (#144)
- **MCP-014: Tool Description Injection** — Scans tool descriptions for injection patterns (URLs, base64, encoded commands, hidden instructions) (#91)
- **A2A-013: Agent Card Limitations Field** — Verifies agents declare meaningful operational constraints (#93)

### Added — New Tools

- **HTML Reporting Dashboard** (`scripts/html_report.py`) — Self-contained audit-ready HTML from JSON output. Executive summary, per-module breakdown, OWASP/AIUC-1 coverage matrices. `--html` CLI flag. (#112)
- **Top 10 Failure Summary** (`scripts/top10_failures.py`) — Ranked failure analysis across runs with severity, OWASP, and AIUC-1 mapping. Markdown and JSON output. (#113)
- **`--simulate --json` for all harnesses** — Every harness now produces valid JSON in simulation mode without a live target. Critical for CI dry-runs and pipeline validation.
- **End-to-end integration test** (`testing/test_integration.py`) — Automated test against bundled mock MCP server in CI.

### Added — Test Expansion

- **L402 Payment**: 14 → 33 tests. Macaroon caveat manipulation, payment channel state attacks, preimage correlation, invoice tampering, multi-hop routing, Lightning DoS (#135)
- **x402 Payment**: 41 → 52 tests. Replay/double-spend, auth bypass, settlement attacks, cross-protocol confusion, metadata exfiltration
- **Total: 358 → 430 tests across 29 modules**

### Fixed — Security (from R31/R32 independent evaluations)

- **CRITICAL: Unreachable server false pass** — `_is_conn_error()` helper; connection errors tracked separately; tests FAIL when target is unreachable (#145)
- **HIGH: Dict-merge vulnerability** — Server responses namespaced under `"response"` key; internal metadata (`_status`, `_error`) can no longer be overwritten by malicious servers (#146)
- **HIGH: GitHub Action shell injection** — All variables in `action.yml` properly double-quoted (#147)
- **HIGH: MCP-008 always passes** — "No response" no longer counts as "handled correctly" (#148)
- **HIGH: `_leak()` false positives** — Bare `"token"` keyword replaced with specific credential patterns (#149)
- **MEDIUM: Stale test counts** — All counts synchronized across README, cli.py, pyproject.toml, free_scan.py, and docs (#150, #151)
- **MEDIUM: CREW-ERR inflating count** — Synthetic error IDs excluded from test count (#154)
- **MEDIUM: html_report.py blank Details column** — Field name corrected from `"detail"` to `"details"` (#155)
- **MEDIUM: evidence_pack.py ephemeral signing key** — Auto-generated key now persisted to `signing.key` file with 0o600 permissions (#156)

### Changed — Architecture

- **Shared HTTP helpers** (`protocol_tests/http_helpers.py`) — Canonical `http_post()`, `_err()`, `_is_conn_error()`, `_leak()` extracted from 7 modules. ~285 lines of duplicated code removed. Prevents future regressions.
- **README restructured** — 830 → 124 lines. Reference content moved to `docs/TEST-INVENTORY.md`, `docs/AIUC1-CROSSWALK.md`, `docs/ADVANCED.md`, `docs/QUICKSTART.md`.
- **Documentation links table** in README points to all docs.

### Changed — Quality

- **Self-test suite: 164 tests, 0 failures, 55 subtests** (up from 160/23-failing)
- **Two independent security evaluations** (R31: 7.5/10, R32: 9/10) with all CRITICAL and HIGH findings resolved
- **Test pattern consistency** — All unit tests updated for response namespacing format

## [3.9.0] - 2026-04-06

### Added
- **`--json` CLI output** — Structured JSON to stdout for CI pipelines and automation
- **Improved connection error messages** — Distinguishes DNS failure, connection refused, timeout
- **Scope & Limitations documentation** — Explicit section on what the framework does and does not test
- **CI/CD quickstart** — GitHub Actions workflow example with service startup and output handling
- **Audit-ready evidence packs** (`scripts/evidence_pack.py`) — Signed evidence with AIUC-1 mapping and HMAC-SHA256
- **AIUC-1 test suite formalized** — `--json` output, per-requirement coverage summary, 19/20 requirements covered (95%)
- **OATR v1.2.0 test fixtures** (community: @FransDevelopment) — 3 new Ed25519 tokens, 29 offline tests
- **Behavioral profiling** (`scripts/behavioral_profile.py`) — Drift detection, stability scoring, trend analysis (#111)
- **Agent Payment Security Attack Taxonomy** (APT-01 through APT-10) — First published taxonomy of AI agent payment attack vectors (#136)
- **x402 expansion** — 16 new tests (X4-026 to X4-044) for OATR attestation verification

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
- Definitive test count corrected to **342** across 21 modules
- `action.yml` parse-report step converted from shell-interpolated Python to heredoc+env pattern (no more `${REPORT}` injection)
- `a2a_harness.py` `--trials` flag now wired into statistical report enhancement
- `harmful_output_harness.py` `--categories` flag now filters tests by category
- `cloud_agent_harness.py` gains `--trials` and `--categories` flags with full implementation

### Changed
- Report format extended to attestation schema (backward-compatible; legacy format still emittable)

## [3.7.0] - 2026-03-25

### Added
- 342 security tests across 21 modules
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
