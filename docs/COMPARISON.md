# Agent Security Tool Comparison (April 2026)

How does the Agent Security Harness compare to other tools in the AI agent security space?

**Short answer:** We test what static scanners can't see — whether authorized agents make safe decisions under adversarial pressure.

## Comparison Matrix

| Capability | [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) | [Snyk Agent Scan](https://github.com/snyk/agent-scan) | [NVIDIA Garak](https://github.com/NVIDIA/garak) | **Agent Security Harness** |
|---|---|---|---|---|
| **Approach** | Static + LLM-as-judge | Config scanning + toxic flow | Model-layer probing | **Wire-protocol adversarial testing** |
| **MCP coverage** | Tool descriptions, YARA rules | Config files | — | **18 tests: real JSON-RPC 2.0 attacks** |
| **A2A coverage** | — | — | — | **13 tests** |
| **L402/x402 payment coverage** | — | — | — | **85 tests** |
| **Enterprise platform adapters** | — | — | — | **25 cloud + 20 enterprise** |
| **Behavioral profiling / drift** | — | — | — | **Planned (v3.10)** |
| **Compliance evidence packs** | — | — | — | **Yes (AIUC-1, OWASP, NIST)** |
| **AIUC-1 requirement mapping** | — | — | — | **19/20 requirements (95%)** |
| **OWASP Agentic Top 10** | — | — | — | **Tests mapped to ASI01–ASI10; per-category counts and limits below** |
| **Statistical multi-trial** | — | — | — | **Wilson CIs (NIST AI 800-2)** |
| **CI/CD integration** | — | Snyk platform | — | **GitHub Action + CLI** |
| **License** | Apache 2.0 | Proprietary | Apache 2.0 | **Apache 2.0** |


### OWASP Agentic Top 10 — what "mapped" means here

Each test carries one ASI primary, or none. A mapping is a claim about which
category a test's *scenario* evidences; it is not a claim that the category is
covered. Counts below are the corpus denominator an evidence pack reports
against (`protocol_tests/asi_inventory.py`, read from source). 48 tests
carry **no primary** on purpose: over-refusal positive controls, content-safety
refusal checks, and protocol-robustness rows support mitigation work without
evidencing a named agentic failure mode, and counting them as coverage was the
overclaim an external review corrected on 2026-09-07 (81 rows remapped).

| ASI | Category | Tests mapped |
|---|---|---|
| ASI01 | Agent Goal Hijack | 77 |
| ASI02 | Tool Misuse and Exploitation | 84 |
| ASI03 | Identity and Privilege Abuse | 136 |
| ASI04 | Agentic Supply Chain Vulnerabilities | 65 |
| ASI05 | Unexpected Code Execution (RCE) | 41 |
| ASI06 | Memory & Context Poisoning | 33 |
| ASI07 | Insecure Inter-Agent Communication | 26 |
| ASI08 | Cascading Failures | 19 |
| ASI09 | Human-Agent Trust Exploitation | 59 |
| ASI10 | Rogue Agents | 13 |
| — | No ASI primary (positive controls, content safety, robustness) | 48 |

**ASI10 Rogue Agents (13) and ASI08 Cascading Failures (19) are thin.**
That is a true statement about this suite, not a rendering gap. Before the remap
ASI10 read as 38 because 25 over-refusal controls were counted under it.

## When to Use What

**Use static scanners (Cisco, Snyk) for:**
- Pre-deployment config review
- Tool description analysis
- Known pattern matching
- MCP server metadata scanning

**Use this framework for:**
- Active adversarial testing against live endpoints
- Decision-governance validation (does the agent behave safely when authorized?)
- Multi-protocol coverage (MCP + A2A + L402 + x402)
- Compliance evidence generation (AIUC-1, EU AI Act)
- Payment protocol security testing

**Use both.** They're complementary layers. Scan for known issues, then test for behavioral failures under adversarial conditions.

## The Gap This Fills

Most tools answer: *"Is the agent properly configured?"*

This framework answers: *"Even if properly configured, can the agent still be manipulated into unsafe behavior?"*

That's the decision-governance layer. Identity tells you the agent is allowed. Decision governance tells you the agent is right.

## Learn More

- [Repository](https://github.com/msaleme/red-team-blue-team-agent-fabric)
- [Research (5 public Zenodo preprints — not peer-reviewed)](https://github.com/msaleme/red-team-blue-team-agent-fabric#research)
- [AIUC-1 Compliance Mapping](https://github.com/msaleme/red-team-blue-team-agent-fabric/blob/main/configs/aiuc1_mapping.yaml)
- [Roadmap](https://github.com/msaleme/red-team-blue-team-agent-fabric/blob/main/ROADMAP.md)

---

> This comparison reflects publicly available information as of April 2026. We welcome corrections — open an issue or PR.
