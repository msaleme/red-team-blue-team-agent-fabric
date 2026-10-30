# AIUC-1 Crosswalk: Evidence Mapping

This document maps selected [AIUC-1](https://www.aiuc-1.com) requirements to
potentially relevant Agent Security Harness tests. It is a research crosswalk,
not a certification, conformity assessment, or determination that a target
system meets a requirement. Applicability, sufficiency, independence, and
conformity must be determined for the specific target and standard version.

In the terms of the [AIUC-1 Evidence Field Guide](https://msaleme.github.io/aiuc1-readiness/),
everything below is **mapped** evidence: a documented requirement relationship, not
a recorded run against any target and not an independent review. Under the
[E1-E5 Evidence Class Taxonomy](EVIDENCE-CLASS-TAXONOMY.md) a mapping is E1-level
material no matter how many requirements it covers. Executed evidence requires a
stated target and a pinned revision; independent review requires a qualified
outside party.

> **Standard currency:** this crosswalk is checked against the **AIUC-1 release of 2026-10-15** (Q4), using the pinned
> snapshot `configs/aiuc1_standard_2026-10-15.json` (requirement IDs and titles from `standard.aiuc-1.com/llms.txt`).
> `tests/test_aiuc1_mapping_matches_standard.py` fails if a title here or in `configs/aiuc1_mapping.yaml` differs from
> the snapshot. AIUC-1 ships quarterly (Jan/Apr/Jul/Oct 15); the next review is due with the 2027-01-15 release.

> **Correction (2026-10-30):** `configs/aiuc1_mapping.yaml` previously attached titles to AIUC-1 IDs that were not
> AIUC-1's (for example B003 "Protocol Downgrade Prevention"; the requirement is "Manage public release of technical
> details"), marked every row COVERED, and the repository claimed "19 of 20 testable requirements (95%)". Those were
> wrong. This document and the YAML now carry the published titles, and no coverage percentage is claimed.

---

## Requirement mapping (23 of 50 active requirements listed; 19 with named tests)

Generated from `configs/aiuc1_mapping.yaml`. **MAPPED** means harness tests are named as potentially relevant to
evidence collection; **GAP** means no harness test evidences the requirement. Neither is a claim about any target.

### A. Data & Privacy

| AIUC-1 Req | Requirement | Status | Named tests | Limit |
|---|---|---|---|---|
| **A003** | Limit AI agent data access | MAPPED | MCP-003, A2A-012, MS-003, SAP-003, SF-001, WD-003, AT-001, OC-002 | Data-access boundary tests across MCP, A2A and enterprise adapters. |
| **A004** | Protect IP & trade secrets | MAPPED | MCP-007, MCP-011, WXO-003 | Context exfiltration, context displacement and credential leakage tests. |
| **A009** | Third-party testing for data & privacy risk | MAPPED | DATA-001, DATA-002, DATA-003, A2A-012, WD-001, ZD-001 | Data-sensitivity, cross-context leakage and PII exfiltration tests. A mapping, not a third-party evaluation report. |

### B. Security

| AIUC-1 Req | Requirement | Status | Named tests | Limit |
|---|---|---|---|---|
| **B001** | Third-party testing for security risk | MAPPED | 37 tests: JB-001, JB-002, JB-003, JB-004, ... CVE-010 (full list in `configs/aiuc1_mapping.yaml`) | Adversarial vectors a third-party evaluator may use. Running them is not itself a third-party evaluation. |
| **B002** | Detect adversarial input | MAPPED | 25 tests: MCP-001, MCP-002, MCP-003, MCP-004, ... ADI-003 (full list in `configs/aiuc1_mapping.yaml`) | Adversarial input via MCP tools, A2A messages and operational data. |
| **B005** | Implement real-time input filtering | MAPPED | POLY-001, POLY-002, CVE-001, MCP-011 | Payload-variation probes; MCP-011 is graded as denial of service, not filtering. |
| **B009** | Limit output over-exposure | MAPPED | DATA-003, MCP-007, WXO-003, GTG-P4-001 | Output sensitivity, context exfiltration and credential exposure tests. |

### C. Safety

| AIUC-1 Req | Requirement | Status | Named tests | Limit |
|---|---|---|---|---|
| **C001** | Define AI risk taxonomy | GAP | none | Documentation-level requirement. The harness tags tests with STRIDE / OWASP Agentic / NIST categories; no test evidences a risk taxonomy. |
| **C002** | Conduct pre-deployment testing | GAP | none | The harness is a pre-deployment testing tool; no single test evidences that pre-deployment testing was conducted. |
| **C003** | Prevent harmful outputs | MAPPED | AIUC-C003a, AIUC-C003b | Harmful and deceptive content refusal. |
| **C004** | Prevent out-of-scope outputs | MAPPED | AIUC-C004a, AIUC-C004b, AIUC-C004c | Out-of-scope execution refusal, scope creep, authority impersonation. |
| **C010** | Third-party testing for safety risk | MAPPED | AIUC-C003a, AIUC-C003b, AIUC-C004a, AIUC-C004b, AIUC-C004c, MCP-003, A2A-004, A2A-008 | Safety vectors a third-party evaluator may use (Q4 folded retired C011 into C010). Not itself a third-party evaluation. |

### D. Reliability

| AIUC-1 Req | Requirement | Status | Named tests | Limit |
|---|---|---|---|---|
| **D003** | Restrict unsafe tool calls | MAPPED | MCP-002, MCP-003, MCP-010, A2A-004, A2A-006, L4-010 | Unauthorised tool registration, capability escalation, argument injection, task hijacking, caveat escalation. |
| **D004** | Third-party testing for reliability risk | MAPPED | 68 tests: MCP-001, MCP-002, MCP-003, MCP-004, ... L4-033 (full list in `configs/aiuc1_mapping.yaml`) | Wire-protocol reliability vectors. The x402 family is excluded until its harness uses the spec's PAYMENT-REQUIRED / PAYMENT-SIGNATURE headers. |

### E. Accountability

| AIUC-1 Req | Requirement | Status | Named tests | Limit |
|---|---|---|---|---|
| **E001** | AI failure plan for security breaches | MAPPED | IR-001, IR-004, AIUC-E001 | Tests that the response behaviour occurs during an incident; they do not evidence the written failure plan itself. |
| **E002** | AI failure plan for harmful outputs | MAPPED | IR-002, AIUC-E002 | Tests that the response behaviour occurs during an incident; they do not evidence the written failure plan itself. |
| **E003** | AI failure plan for hallucinations | MAPPED | IR-003, HALL-001, HALL-002 | Tests that the response behaviour occurs during an incident; they do not evidence the written failure plan itself. |
| **E004** | Assign accountability | GAP | none | Organisational requirement; no test evidences assigned accountability. |
| **E006** | Conduct vendor and model due diligence | GAP | none | A bounded, authorised harness run may contribute technical evidence to vendor and model due diligence; it is not the review. |
| **E015** | Log AI system activity | MAPPED | AUDIT-001, AUDIT-002, IR-006, GM-006 | Audit-trail availability, attribution, log completeness and tamper tests. |
| **E018** | Third-party testing for accountability risk | MAPPED | AUDIT-001, AUDIT-002, GM-006, IR-006 | Accountability vectors a third-party evaluator may use. A mapping, not a third-party evaluation report. |

### F. Society

| AIUC-1 Req | Requirement | Status | Named tests | Limit |
|---|---|---|---|---|
| **F001** | Prevent AI cyber misuse | MAPPED | 15 tests: GTG-P1-001, GTG-P1-002, GTG-P2-001, GTG-P2-002, ... GTG-P6-002 (full list in `configs/aiuc1_mapping.yaml`) | GTG-1002 AI-orchestrated intrusion simulation. |
| **F002** | Prevent catastrophic misuse | MAPPED | 11 tests: CBRN-001, CBRN-002, CBRN-003, CBRN-004, ... AIUC-F002c (full list in `configs/aiuc1_mapping.yaml`) | CBRN refusal tests. |

## Not listed

27 active requirements are not listed in the mapping: A001, A002, A005, A006, A007, A008, B003, B004, B006, B007, B008, B010, C005, C006, C007, C008, C009, D001, E005, E008, E009, E010, E011, E012, E013, E016, E017. Most are process,
policy or infrastructure requirements that an adversarial test harness cannot evidence. Retired in the 2026-10-15 release
and therefore not listed: C011, C012 and D002 (folded into C010 and D004), plus E007 and E014.

> **Claim boundary:** a mapped test has a documented relationship to a requirement. It does not establish that the test was executed, that a target passed, that testing was independent, or that a target conforms to AIUC-1. Retain the pinned revision, invocation, inputs, environment, timestamps, and output before making a runtime claim; obtain independent review before representing evidence as third-party reviewed.

> **Use case:** Use this crosswalk to select potentially relevant tests for an authorized target, run a pinned harness revision, and retain the resulting artifacts for review. The harness can support evidence collection relevant to AIUC-1 requirements. Applicability, sufficiency, independence, and conformity must be determined for the specific target and standard version.

---

## Standards Alignment

- **AIUC-1 (release 2026-10-15)** - E1 evidence mapping; see the table above for the requirements listed and their stated limits
- **OWASP Top 10 for Agentic Applications (2026)** - tests mapped to ASI01–ASI10 with per-category counts and stated limits (see docs/COMPARISON.md)
- **OWASP LLM Top 10** - LLM01 (Prompt Injection), LLM02, LLM03, LLM04, LLM06, LLM08
- **NIST AI RMF** - GOVERN, MAP, MEASURE, MANAGE functions covered
- **NIST AI 800-2: Benchmark Evaluation Practices (Jan 2026)** - Statistical evaluation protocol follows all 9 practices
- **NIST NCCoE: AI Agent Identity & Authorization (Feb 2026)** - Dedicated test harness covering all 6 focus areas
- **NIST AI Agent Standards Initiative (Feb 2026)** - Aligned with agent security, identity, and interoperability pillars
- **NIST Cyber AI Profile (IR 8596, Dec 2025)** - Maps to Secure, Detect, Respond functions
- **ISA/IEC 62443** - Security Levels 1-4, air-gapped fallback for safety-critical agents
- **EU AI Act** - Transparency, human oversight, audit trail requirements
