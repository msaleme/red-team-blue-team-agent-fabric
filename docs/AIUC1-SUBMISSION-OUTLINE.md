# AIUC-1 Working Group Submission Outline

**Status:** DRAFT — for internal review before submission
**Target:** AIUC-1 Working Group (implementation guidance track)
**Submitter:** Michael Saleme
**Framework:** Agent Security Harness (current release on PyPI as `agent-security-harness`)

---

## 1. Executive Summary

The Agent Security Harness is an open-source adversarial testing framework (661 tests, 50 test-bearing modules) that maps directly to AIUC-1 certification requirements. We propose inclusion as a reference implementation tool in AIUC-1 implementation guidance, providing organizations with an executable path from requirement to evidence.

**Key differentiator:** This is not a static scanner. The harness sends real adversarial payloads across live protocols (MCP, A2A, L402, x402) and measures whether agents make safe, policy-compliant decisions — the behavioral assurance layer that complements identity and access controls.

**Current AIUC-1 mapping (release 2026-10-15):** 23 of 50 active requirements listed, 19 with named tests, 4 recorded as gaps. This is an E1 evidence mapping, not a conformance result for any target. Full mapping in `configs/aiuc1_mapping.yaml`; per-requirement tests and limits in `docs/AIUC1-CROSSWALK.md`.

---

## 2. What We Are Requesting

1. **Citation in AIUC-1 implementation guidance** as an open-source tool organizations can use to validate compliance with security, reliability, and transparency requirements.
2. **Feedback on our requirement mapping** (`configs/aiuc1_mapping.yaml`) to ensure alignment with the working group's intent for each control.
3. **Participation in the implementation tooling track** (if one exists) to help define what "testable evidence" looks like for each requirement.

We are NOT requesting certification for the harness itself. We are offering it as tooling that helps others achieve certification.

---

## 3. AIUC-1 Requirement Coverage

### Coverage by Category

Against AIUC-1 release 2026-10-15 (`configs/aiuc1_standard_2026-10-15.json`). **MAPPED** means harness tests are named as potentially relevant evidence; **GAP** means no harness test evidences the requirement.

| Category | Active in standard | Listed | MAPPED | GAP |
|----------|-------------------:|-------:|-------:|----:|
| **A. Data & Privacy** | 9 | 3 | 3 | 0 |
| **B. Security** | 10 | 4 | 4 | 0 |
| **C. Safety** | 10 | 5 | 3 | 2 |
| **D. Reliability** | 3 | 2 | 2 | 0 |
| **E. Accountability** | 16 | 7 | 5 | 2 |
| **F. Society** | 2 | 2 | 2 | 0 |
| **Total** | **50** | **23** | **19** | **4** |

27 active requirements are not listed at all. Most are organisational or documentation controls that a test harness cannot evidence.

### How the Harness Evidences Each Requirement

The per-requirement table, with named tests and a stated limit for each row, is `docs/AIUC1-CROSSWALK.md`, generated from `configs/aiuc1_mapping.yaml`. It is not repeated here so the two cannot drift.

---

## 4. Evidence Artifact Format

The harness produces machine-readable evidence in JSON format following a published schema (`schemas/attestation-report.json`). Each test result includes:

- Test ID mapped to AIUC-1 requirement
- Pass/fail result with severity classification (P0-Critical through P4-Info)
- Full request/response transcript (for protocol tests)
- Statistical confidence intervals when multi-trial mode is used (NIST AI 800-2 aligned)
- Timestamp, harness version, and target metadata

**Signing:** an attestation record (the report plus server name, contact and timestamp) can be signed with a local Ed25519 key (`protocol_tests/attestation_registry.py`) and verified offline with `scripts/verify_attestation_record.py`.

---

## 5. Research Foundation

The framework's methodology is documented in 5 public preprints deposited on Zenodo (not represented as peer-reviewed publications):

1. Constitutional Self-Governance for Autonomous AI Agents — [DOI: 10.5281/zenodo.19162104](https://doi.org/10.5281/zenodo.19162104)
2. Detecting Normalization of Deviance in Multi-Agent Systems — [DOI: 10.5281/zenodo.19195516](https://doi.org/10.5281/zenodo.19195516)
3. Decision Load Index (DLI) — [DOI: 10.5281/zenodo.18217577](https://doi.org/10.5281/zenodo.18217577)
4. Beyond Identity Governance: A Protocol-Level Security Testing Framework for Multi-Agent Systems — [DOI: 10.5281/zenodo.19343034](https://doi.org/10.5281/zenodo.19343034)
5. Community-Driven Security for AI Agents: Evolution of an Adversarial Test Corpus — [DOI: 10.5281/zenodo.19343108](https://doi.org/10.5281/zenodo.19343108)

Additionally, the framework aligns with:
- **NIST AI 800-2** evaluation methodology (statistical analysis, three-stage evaluation structure)
- **NIST AI Agent Standards Initiative** (February 2026) secure agent deployment direction
- **OWASP Top 10 for Agentic Applications** (tests mapped to ASI01–ASI10 with per-category counts and stated limits (see docs/COMPARISON.md))
- **OWASP MCP Top 10** (2025): 6 of 10 entries covered, 1 adjacent, 3 not covered; per-entry tests and limits in docs/OWASP-MCP-TOP10-MAPPING.md

---

## 6. Standards Alignment

| Standard | Alignment |
|----------|-----------|
| **AIUC-1** | E1 mapping: 23 of 50 active requirements listed, 19 with named tests (release 2026-10-15; docs/AIUC1-CROSSWALK.md) |
| **NIST AI RMF** | Tests tagged to three subcategories: GOVERN 1.1, GOVERN 6.1, MANAGE 2.2. MAP and MEASURE are not tagged |
| **NIST IR 8596 (Cyber AI Profile)** | Used as a reporting frame (Secure, Detect, Respond) in EVALUATION_PROTOCOL.md; no per-test mapping |
| **NIST SP 800-53** | Identity harness maps to 6 NCCoE focus areas |
| **OWASP Agentic Top 10** | Tests mapped to ASI01–ASI10; per-category counts and limits stated |
| **OWASP MCP Top 10** | 6 of 10 entries covered, 1 adjacent, 3 not covered (docs/OWASP-MCP-TOP10-MAPPING.md) |
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

| Gap | Requirement | Why the harness does not evidence it |
|-----|-------------|--------------------------------------|
| C001 | Define AI risk taxonomy | Documentation-level. Tests carry STRIDE / OWASP Agentic / NIST tags, but no test evidences a taxonomy |
| C002 | Conduct pre-deployment testing | The harness is a pre-deployment tool; no single test evidences that testing was conducted |
| E004 | Assign accountability | Organisational requirement |
| E006 | Conduct vendor and model due diligence | A bounded harness run can contribute technical evidence; it is not the review |

These are recorded as gaps, not scheduled work: closing them would take organisational evidence, not more tests.

---

## 9. Proposed Next Steps

1. Submit this outline to the AIUC-1 working group for feedback on mapping accuracy
2. Request review of `configs/aiuc1_mapping.yaml` by working group members
3. Ask whether the four GAP rows (C001, C002, E004, E006) should stay out of scope for a test harness
4. Re-run the mapping check against each new AIUC-1 release and report changes
5. Explore formal inclusion in AIUC-1 implementation guidance documentation

---

## 10. Contact

**Michael Saleme**
GitHub: [@msaleme](https://github.com/msaleme)

---

> **Disclosure:** This submission outline was developed with AI-assisted drafting (Claude Code, April 2026). All technical claims, requirement mappings, and strategic decisions are the author's own, verified against the codebase and published research.

---

*Correction, 2026-08-09: previously stated the registered count (44) rather than the test-bearing
count. `scripts/count_tests.py`
reports test IDs in 43 files; `cli.py` registers 44 commands, the extra being
`community_runner.py`, a host for community-contributed tests that ships none of
its own. The 608 test count is unchanged.*
