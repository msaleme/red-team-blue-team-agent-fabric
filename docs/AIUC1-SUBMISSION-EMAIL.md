# AIUC-1 Working Group — Submission Email Draft

**Status:** READY TO SEND (review and personalize before sending)
**From:** Michael Saleme
**To:** AIUC-1 Working Group (locate contact via aiuc-1.com or Schellman/working group directory)
**CC:** (optional: NIST CAISI contacts if appropriate)

---

## Subject Line

Open-source AIUC-1 compliance testing tool — request for inclusion in implementation guidance

---

## Email Body

Dear AIUC-1 Working Group,

I am writing to introduce the Agent Security Harness, an open-source adversarial testing framework that maps directly to AIUC-1 certification requirements. Following UiPath's certification by Schellman in March 2026, I believe there is an opportunity to provide the ecosystem with open tooling that helps organizations validate compliance — and I would like to contribute to that effort.

**What it is**

The Agent Security Harness (Apache 2.0, pip install agent-security-harness) contains 342 executable security tests across 24 modules. Unlike static scanners that analyze configurations, this framework sends real adversarial payloads across live agent protocols (MCP, A2A, L402, x402) and measures whether agents make safe, policy-compliant decisions when already authorized to act.

We currently map to 23 of 24 AIUC-1 requirements, with 19 having production-ready tests. The mapping is maintained in a machine-readable YAML configuration and the framework produces structured JSON evidence artifacts.

**What I am requesting**

1. Feedback on our requirement mapping to ensure alignment with the working group's intent for each control
2. Consideration for citation in AIUC-1 implementation guidance as an open-source tool organizations can use to validate compliance
3. Participation in any implementation tooling track, if one exists, to help define what testable evidence should look like for each requirement

I am not requesting certification for the harness itself. I am offering it as tooling that helps others achieve certification.

**Research foundation**

The methodology is documented in five peer-reviewed preprints:

- Constitutional Self-Governance for Autonomous AI Agents (DOI: 10.5281/zenodo.19162104) — 12 governance mechanisms, 77 days of production data, 56 agents
- Detecting Normalization of Deviance in Multi-Agent Systems (DOI: 10.5281/zenodo.19195516)
- Decision Load Index: A Quantitative Framework for Agent Autonomy Risk (DOI: 10.5281/zenodo.18217577)

The framework also aligns with NIST AI 800-2 evaluation methodology, the OWASP Top 10 for Agentic Applications (complete ASI01-ASI10 coverage), and the NIST AI Agent Standards Initiative.

**Links**

- Repository: https://github.com/msaleme/red-team-blue-team-agent-fabric
- PyPI: https://pypi.org/project/agent-security-harness/
- AIUC-1 requirement mapping: https://github.com/msaleme/red-team-blue-team-agent-fabric/blob/main/configs/aiuc1_mapping.yaml
- Detailed submission outline: https://github.com/msaleme/red-team-blue-team-agent-fabric/blob/main/docs/AIUC1-SUBMISSION-OUTLINE.md

I have attached a detailed submission outline with full requirement coverage tables, gap analysis, and our closure plan for the remaining gaps (targeting July 2026).

I welcome any feedback on the mapping or the approach. Happy to discuss further or present to the working group if that would be useful.

Best regards,
Michael Saleme
https://github.com/msaleme

---

## Before sending — checklist

- [ ] Find the correct AIUC-1 working group contact (check aiuc-1.com, or reach through Schellman, Cloud Security Alliance, or your NIST CAISI contacts)
- [ ] Attach or link the AIUC1-SUBMISSION-OUTLINE.md as a PDF if the recipient prefers attachments
- [ ] Personalize the greeting if you have a named contact
- [ ] Decide whether to CC NIST CAISI contacts (Anita Rao or others) for additional credibility signal
- [ ] Review tone — this is collegial and contribution-oriented, not a sales pitch
