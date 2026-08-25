# OWASP ASI Top 10 (2026) -> Agentic AI Threats & Mitigations (T1-T17)

> **This is a transcription, not an adjudication, and not a coverage claim.**
> A transcription of OWASP's own cross-mapping between the ASI Top 10 and the T1-T17 taxonomy this document adjudicates. It is NOT a coverage claim and NOT an independent adjudication. The methodology section above already states that an ASI or LLM Top 10 crosswalk does not establish coverage on its own, and that rule applies to this block. Read a harness verdict for T-n from the threat detail; read this only to learn which ASI entry OWASP places that threat under.

**Source.** *OWASP Top 10 for Agentic Applications 2026*, OWASP Gen AI Security Project - Agentic Security Initiative, version 2026, December 2025. [Landing page](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/). `OWASP-Top-10-for-Agentic-Applications-2026-12.6-1.pdf`, 57 pp, CC-BY-SA-4.0, SHA-256 `a2db94cd00b08e0b3a5e5b619afe024bdbcd74503111085705e4f3dd886fcb5c`, retrieved 2026-08-25. Primary table: Appendix A - OWASP Agentic AI Security Mapping Matrix (p.39-40).

**Relation semantics.** threats_primary holds the T-ids the entry body states it maps to. threats_contributing holds T-ids the body calls contributing factors or related impacts, plus every T-id that appears only in the Appendix A row. Where the entry body states no split, all T-ids are recorded as contributing and the entry says so; inventing a primary would assert a distinction the source does not draw.

## ASI entry -> threats

| ASI | Title | Maps to (primary) | Contributing / related | AIVSS core risk |
|---|---|---|---|---|
| ASI01 | Agent Goal Hijack | **T6** Intent Breaking & Goal Manipulation, **T7** Misaligned & Deceptive Behaviors | — | Agent Goal & Instruction Manipulation |
| ASI02 | Tool Misuse and Exploitation | **T2** Tool Misuse | T4 Resource Overload, T16 Insecure Inter-Agent Protocol Abuse | Agentic AI Tool Misuse |
| ASI03 | Identity and Privilege Abuse | **T3** Privilege Compromise | — | Agent Access Control Violation |
| ASI04 | Agentic Supply Chain Vulnerabilities | **T17** Supply Chain Compromise | T2 Tool Misuse, T11 Unexpected RCE and Code Attacks, T12 Agent Communication Poisoning, T13 Rogue Agents in Multi-Agent Systems, T16 Insecure Inter-Agent Protocol Abuse | Agent Supply Chain & Dependency Attacks |
| ASI05 | Unexpected Code Execution (RCE) | **T11** Unexpected RCE and Code Attacks | — | Insecure Agent Critical Systems Interaction |
| ASI06 | Memory & Context Poisoning | **T1** Memory Poisoning | T4 Resource Overload †, T6 Intent Breaking & Goal Manipulation †, T12 Agent Communication Poisoning † | — |
| ASI07 | Insecure Inter-Agent Communication | _none stated_ | T12 Agent Communication Poisoning, T16 Insecure Inter-Agent Protocol Abuse | Agent Memory & Context Manipulation |
| ASI08 | Cascading Failures | _none stated_ | T5 Cascading Hallucination Attacks, T8 Repudiation & Untraceability | Agent Cascading Failures |
| ASI09 | Human-Agent Trust Exploitation | _none stated_ | T7 Misaligned & Deceptive Behaviors, T8 Repudiation & Untraceability, T10 Overwhelming Human in the Loop | Agent Untraceability / Human Manipulation |
| ASI10 | Rogue Agents | **T13** Rogue Agents in Multi-Agent Systems | T14 Human Attacks on Multi-Agent Systems, T15 Human Manipulation | Behavioral Integrity (BI) · Operational Security (OS) · Compliance Violations (CV) |

† The ASI document gives this threat number a different title from v1.1. The number is what the source states and what is transcribed; the title shown is v1.1's. See [Threat titles that disagree with v1.1](#threat-titles-that-disagree-with-v11).

## Threat -> ASI entries

| Threat | Primary for | Contributing to |
|---|---|---|
| **T1** Memory Poisoning | ASI06 | — |
| **T2** Tool Misuse | ASI02 | ASI04 |
| **T3** Privilege Compromise | ASI03 | — |
| **T4** Resource Overload | — | ASI02, ASI06 |
| **T5** Cascading Hallucination Attacks | — | ASI08 |
| **T6** Intent Breaking & Goal Manipulation | ASI01 | ASI06 |
| **T7** Misaligned & Deceptive Behaviors | ASI01 | ASI09 |
| **T8** Repudiation & Untraceability | — | ASI08, ASI09 |
| **T9** Identity Spoofing & Impersonation | — | — |
| **T10** Overwhelming Human in the Loop | — | ASI09 |
| **T11** Unexpected RCE and Code Attacks | ASI05 | ASI04 |
| **T12** Agent Communication Poisoning | — | ASI04, ASI06, ASI07 |
| **T13** Rogue Agents in Multi-Agent Systems | ASI10 | ASI04 |
| **T14** Human Attacks on Multi-Agent Systems | — | ASI10 |
| **T15** Human Manipulation | — | ASI10 |
| **T16** Insecure Inter-Agent Protocol Abuse | — | ASI02, ASI04, ASI07 |
| **T17** Supply Chain Compromise | ASI04 | — |

T9 Identity Spoofing & Impersonation is referenced by no ASI Top 10 entry. Sixteen of the seventeen threats appear in the Appendix A matrix; T9 does not. Recorded as an observation about the source, not as a defect in it and not as a statement about harness coverage, which is adjudicated per-threat above.

## Threat titles that disagree with v1.1

The ASI Top 10 references T-ids by NUMBER, and for ASI06 three of those numbers carry titles that do not match Agentic AI - Threats and Mitigations v1.1, the version pinned by this mapping. Both the ASI06 entry body and the Appendix A row use the non-matching titles, so this is what the source says rather than an extraction artifact. The numbers are transcribed verbatim and the titles are NOT normalised: whether these are the same threats renamed or different threats cannot be resolved without the earlier taxonomy version, and silently rewriting them would assert a reconciliation that was not performed.

| Threat | Title in the ASI Top 10 | Title in v1.1 | Seen in |
|---|---|---|---|
| T4 | Memory Overload | Resource Overload | ASI06 body and Appendix A |
| T6 | Broken Goals | Intent Breaking & Goal Manipulation | ASI06 body and Appendix A |
| T12 | Shared Memory Poisoning | Agent Communication Poisoning | ASI06 body and Appendix A |

## Statements transcribed

- **ASI01 Agent Goal Hijack** — "In the OWASP Agentic AI Threats & Mitigations Guide, ASI01 corresponds to T06 Goal Manipulation (altering the agent's objectives) and T07 Misaligned & Deceptive Behaviors (bypassing safeguards or deceiving humans)."
- **ASI02 Tool Misuse and Exploitation** — "The entry maps to T2 Tool Misuse in the Agentic AI Threats and Mitigations Guide whilst T4 Resource Overload and T16 Insecure Inter-Agent Protocol Abuse represent contributing factors that can amplify or enable tool exploitation."
- **ASI03 Identity and Privilege Abuse** — "In the OWASP ASI Threats and Mitigations, it maps one-to-one to T3: Privilege Compromise, and in OWASP AIVSS it corresponds to Core Risk 2: Agent Access Control Violation."
- **ASI04 Agentic Supply Chain Vulnerabilities** — "The entry maps to T17 Supply Chain Compromise in Agentic Threats and Mitigations and across T2 Tool Misuse, T11 Unexpected RCE and Code Attacks, T12 Agent Communication Poisoning, T13 Rogue Agent and T16 Insecure Inter-Agent Protocol Abuse."
- **ASI05 Unexpected Code Execution (RCE)** — "This risk aligns with T11 Unexpected RCE and Code Attacks in Agentic AI - Threats and Mitigations v1."
- **ASI06 Memory & Context Poisoning** — "It maps to T1 Memory Poisoning in Agentic Threats and Mitigations, with related impacts in T4 Memory Overload, T6 Broken Goals, and T12 Shared Memory Poisoning."
- **ASI07 Insecure Inter-Agent Communication** — Appendix A matrix only; the entry body states no primary/contributing split, so every T reference is recorded as contributing.
- **ASI08 Cascading Failures** — Appendix A matrix only; the entry body states no primary/contributing split, so every T reference is recorded as contributing.
- **ASI09 Human-Agent Trust Exploitation** — Appendix A matrix only; the entry body states no primary/contributing split, so every T reference is recorded as contributing.
- **ASI10 Rogue Agents** — "In the OWASP Agentic AI Threats and Mitigations guide, ASI10 corresponds to T13 - Rogue Agents in Multi-Agent Systems."

Generated from `docs/coverage/owasp-agentic-v1.1.yaml` by `scripts/generate_owasp_agentic_coverage.py`. Do not edit by hand.
