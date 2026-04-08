# AIUC-1 Working Group Submission Outline

**Status:** DRAFT — for internal review before submission
**Target:** AIUC-1 Working Group (implementation guidance track)
**Submitter:** Michael Saleme
**Framework:** Agent Security Harness v3.10 (targeting pre-July 2026)

---

## 1. Executive Summary

The Agent Security Harness is an open-source adversarial testing framework (398 tests, 24 modules) that maps directly to AIUC-1 certification requirements. We propose inclusion as a reference implementation tool in AIUC-1 implementation guidance, providing organizations with an executable path from requirement to evidence.

**Key differentiator:** This is not a static scanner. The harness sends real adversarial payloads across live protocols (MCP, A2A, L402, x402) and measures whether agents make safe, policy-compliant decisions — the behavioral assurance layer that complements identity and access controls.

**Current AIUC-1 coverage:** 15 of 24 requirements have production-ready tests. 5 requirements have simulation-mode tests requiring live endpoint validation. Full mapping available in `configs/aiuc1_mapping.yaml`.

---

## 2. What We Are Requesting

1. **Citation in AIUC-1 implementation guidance** as an open-source tool organizations can use to validate compliance with security, reliability, and transparency requirements.
2. **Feedback on our requirement mapping** (`configs/aiuc1_mapping.yaml`) to ensure alignment with the working group's intent for each control.
3. **Participation in the implementation tooling track** (if one exists) to help define what "testable evidence" looks like for each requirement.

We are NOT requesting certification for the harness itself. We are offering it as tooling that helps others achieve certification.

---

## 3. AIUC-1 Requirement Coverage

### Coverage by Category

| Category | Requirements | Covered | Production-Ready | Gaps |
|----------|-------------|---------|-----------------|------|
| **Security (B001-B005)** | 5 | 5 | 5 | 0 |
| **Reliability (C001-C010)** | 10 | 10 | 10 | 0 |
| **Transparency (D001-D004)** | 4 | 4 | 4 | 0 |
| **Safety (E001-E003)** | 3 | 3 | 0 (simulation) | 3 |
| **Content Safety (F001-F002)** | 2 | 1 | 0 (simulation) | 1 |
| **Total** | **24** | **23** | **19** | **4** |

### How the Harness Validates Each Requirement

**Security requirements (B001-B005):** Wire-protocol adversarial testing via MCP and A2A harnesses. Real JSON-RPC 2.0 payloads test tool poisoning (B001), capability escalation (B002), protocol downgrade (B003), injection (B004), and identity verification via OATR fixtures (B005).

**Reliability requirements (C001-C010):** A2A protocol harness validates agent card integrity (C001), task lifecycle (C002), message replay prevention (C005), context isolation (C006), streaming robustness (C007), push notification security (C008), and protocol conformance (C009). Payment protocol harnesses (L402/x402) validate C010. Dedicated AIUC-1 compliance harness tests harmful output (C003) and scope enforcement (C004).

**Transparency requirements (D001-D004):** Attestation schema (`schemas/attestation-report.json`) and attestation registry provide D001-D002. Provenance harness validates supply chain claims (D003). Identity harness tests audit trail completeness (D004).

**Safety requirements (E001-E003) — GAPS:** Simulation-mode tests exist for incident detection latency, containment, and audit trail completeness. Closing this gap requires integration with real incident response infrastructure (kill switches, circuit breakers, logging pipelines). Targeted for v3.10.

**Content Safety (F001-F002) — PARTIAL GAP:** CBRN prevention tests (F002) exist in simulation mode with 4 prompt categories (chemical, biological, radiological, dual-use). F001 (harmful content filtering) requires a dedicated harness. Targeted for v3.10.

---

## 4. Evidence Artifact Format

The harness produces machine-readable evidence in JSON format following a published schema (`schemas/attestation-report.json`). Each test result includes:

- Test ID mapped to AIUC-1 requirement
- Pass/fail result with severity classification (P0-Critical through P4-Info)
- Full request/response transcript (for protocol tests)
- Statistical confidence intervals when multi-trial mode is used (NIST AI 800-2 aligned)
- Timestamp, harness version, and target metadata

**v3.10 addition (in progress):** Signed evidence packages designed to serve as audit packet exhibits without reformatting.

---

## 5. Research Foundation

The framework's methodology is documented in 5 peer-reviewed preprints:

1. Constitutional Self-Governance for Autonomous AI Agents — [DOI: 10.5281/zenodo.19162104](https://doi.org/10.5281/zenodo.19162104)
2. Detecting Normalization of Deviance in Multi-Agent Systems — [DOI: 10.5281/zenodo.19195516](https://doi.org/10.5281/zenodo.19195516)
3. Decision Load Index (DLI) — [DOI: 10.5281/zenodo.18217577](https://doi.org/10.5281/zenodo.18217577)
4. Normalization of Deviance in Autonomous Agent Systems — [DOI: 10.5281/zenodo.15105866](https://doi.org/10.5281/zenodo.15105866)
5. Cognitive Style Governance for Multi-Agent Deployments — [DOI: 10.5281/zenodo.15106553](https://doi.org/10.5281/zenodo.15106553)

Additionally, the framework aligns with:
- **NIST AI 800-2** evaluation methodology (statistical analysis, three-stage evaluation structure)
- **NIST AI Agent Standards Initiative** (February 2026) secure agent deployment direction
- **OWASP Top 10 for Agentic Applications** (complete ASI01-ASI10 coverage)
- **OWASP MCP Top 10** (protocol-level risk coverage)

---

## 6. Standards Alignment

| Standard | Alignment |
|----------|-----------|
| **AIUC-1** | 23/24 requirements mapped, 19 production-ready |
| **NIST AI RMF / IR 8596** | Full alignment on evaluation methodology |
| **NIST SP 800-53** | Identity harness maps to 6 NCCoE focus areas |
| **OWASP Agentic Top 10** | Complete ASI01-ASI10 test coverage |
| **OWASP MCP Top 10** | Protocol-level risk coverage |
| **EU AI Act (high-risk)** | Pre-deployment validation, transparency, documented governance |
| **STRIDE** | 27 threat scenarios across all 6 categories |

---

## 7. Open Source and Availability

- **Repository:** [github.com/msaleme/red-team-blue-team-agent-fabric](https://github.com/msaleme/red-team-blue-team-agent-fabric)
- **PyPI:** `pip install agent-security-harness`
- **License:** Apache 2.0
- **CI integration:** GitHub Action available (`action.yml`)
- **MCP server mode:** Agents can invoke security tests via MCP protocol

---

## 8. Gap Closure Plan

| Gap | Current State | Plan | Target |
|-----|--------------|------|--------|
| E001-E003 (Safety) | Simulation-mode tests | Integrate with real incident response infrastructure | v3.10 (July 2026) |
| F001 (Harmful Content) | No dedicated harness | Build content filtering test suite | v3.10 (July 2026) |
| F002 (CBRN) | Simulation-mode | Validate against production LLM endpoints | v3.10 (July 2026) |
| Evidence signing | Schema exists, signing not yet implemented | Implement signed evidence packages | v3.10 (July 2026) |

---

## 9. Proposed Next Steps

1. Submit this outline to the AIUC-1 working group for feedback on mapping accuracy
2. Request review of `configs/aiuc1_mapping.yaml` by working group members
3. Close E001-E003 and F001-F002 gaps in v3.10 (targeting July 2026)
4. Provide updated coverage report to working group after v3.10 ships
5. Explore formal inclusion in AIUC-1 implementation guidance documentation

---

## 10. Contact

**Michael Saleme**
GitHub: [@msaleme](https://github.com/msaleme)

---

> **Disclosure:** This submission outline was developed with AI-assisted drafting (Claude Code, April 2026). All technical claims, requirement mappings, and strategic decisions are the author's own, verified against the codebase and published research.
