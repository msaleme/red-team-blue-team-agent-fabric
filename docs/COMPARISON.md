# Agent Security Tool Comparison

Two kinds of fact live in this document, and they are not the same age. Saying
which is which is the whole point of the split below.

- **The competitor columns are a frozen snapshot taken in April 2026.**
  No competitor tool has been re-examined since 2026-04. Nothing here is a
  current assessment of Cisco, Snyk or NVIDIA, and any of those projects may
  have shipped in either direction since. Read that section as an archive with
  a date on it.
- **This suite's own numbers are derived, regenerated 2026-09-08** from
  `scripts/count_tests.py` and `protocol_tests/asi_inventory.py`.
  `testing/test_comparison_doc_is_current.py` recomputes every one of them and
  fails if the document drifts from the catalog.

The fifth external review (R5-09, 2026-09-09) found the two mixed together: an
April feature table claiming "MCP: 18 tests" and behavioural profiling "Planned
(v3.10)" sat directly above a September ASI remap, in a document headed April
2026, beside a README describing a much broader current surface. No count was
fabricated. A frozen table and a live one were presented as one snapshot, and a
reader could not tell which cells had been re-examined. That is what the split
fixes; it is not a fresh competitor review, and it does not claim to be one.

**Short answer to the question the document exists for:** we test what static
scanners cannot see -- whether authorized agents make safe decisions under
adversarial pressure.

## Competitor snapshot -- FROZEN, April 2026

Not re-examined since 2026-04. No competitor system was executed or inspected
for the 2026-09 revision of this document.

| Capability | [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) | [Snyk Agent Scan](https://github.com/snyk/agent-scan) | [NVIDIA Garak](https://github.com/NVIDIA/garak) |
|---|---|---|---|
| **Approach** | Static + LLM-as-judge | Config scanning + toxic flow | Model-layer probing |
| **MCP coverage** | Tool descriptions, YARA rules | Config files | — |
| **A2A coverage** | — | — | — |
| **L402/x402 payment coverage** | — | — | — |
| **Enterprise platform adapters** | — | — | — |
| **Behavioural profiling / drift** | — | — | — |
| **Compliance evidence packs** | — | — | — |
| **Statistical multi-trial** | — | — | — |
| **CI/CD integration** | — | Snyk platform | — |
| **License** | Apache 2.0 | Proprietary | Apache 2.0 |

## This suite -- DERIVED, regenerated 2026-09-08

Every count in this section is recomputed from source by
`testing/test_comparison_doc_is_current.py`. The third column names the modules
it is summed from, so the derivation is checkable without rerunning anything.

| Surface | Tests | Derived from |
|---|---|---|
| MCP: wire protocol, supply chain, tool poisoning | 47 | `mcp_harness.py`, `mcp_supplychain.py`, `mcp_tool_poisoning_harness.py` |
| A2A | 13 | `a2a_harness.py` |
| Payment protocols and settlement | 153 | `l402_harness.py`, `x402_harness.py`, `x402_fireblocks_harness.py`, `ap2_harness.py`, `ucp_acp_harness.py`, `card_token_harness.py`, `settlement_finality_harness.py` |
| Platform and framework adapters | 98 | `cloud_agent_harness.py`, `enterprise_adapters.py`, `extended_enterprise_adapters.py`, `framework_adapters.py` |
| **All modules, unique test IDs** | **623** | `scripts/count_tests.py` |

The four rows above overlap nothing and cover part of the suite; the remaining
tests live in the identity, jailbreak, over-refusal, provenance, memory,
governance and incident-response modules that `count_tests.py` lists in full.

| Capability | Status |
|---|---|
| Approach | Wire-protocol adversarial testing |
| Behavioural profiling / drift | Shipped: `scripts/behavioral_profile.py` |
| Compliance evidence packs | AIUC-1, OWASP, NIST |
| AIUC-1 requirement mapping | 19 of 20 requirements |
| Statistical multi-trial | Wilson intervals over serviced trials (NIST AI 800-2) |
| CI/CD integration | GitHub Action + CLI |
| License | Apache 2.0 |

### OWASP Agentic Top 10 -- what "mapped" means here

Each test carries one ASI primary, or none. A mapping is a claim about which
category a test's *scenario* evidences; it is not a claim that the category is
covered. Counts below are the corpus denominator an evidence pack reports
against, read from source by `protocol_tests/asi_inventory.py`, and regenerated
2026-09-08. Tests carrying **no primary** do so on purpose: over-refusal
positive controls, content-safety refusal checks, and protocol-robustness rows
support mitigation work without evidencing a named agentic failure mode, and
counting them as coverage was the overclaim an external review corrected on
2026-09-07 (81 rows remapped).

| ASI | Category | Tests mapped |
|---|---|---|
| ASI01 | Agent Goal Hijack | 79 |
| ASI02 | Tool Misuse and Exploitation | 87 |
| ASI03 | Identity and Privilege Abuse | 136 |
| ASI04 | Agentic Supply Chain Vulnerabilities | 65 |
| ASI05 | Unexpected Code Execution (RCE) | 41 |
| ASI06 | Memory & Context Poisoning | 33 |
| ASI07 | Insecure Inter-Agent Communication | 29 |
| ASI08 | Cascading Failures | 19 |
| ASI09 | Human-Agent Trust Exploitation | 59 |
| ASI10 | Rogue Agents | 13 |
| — | No ASI primary (positive controls, content safety, robustness) | 52 |

The table's rows sum to 613, not to the 623 unique test IDs above: 10 tests
carry no ASI tag site at all and so are not in the corpus this table is a
denominator for. Untagged is a third state, and folding it into "no primary"
would report an unmade decision as a made one.

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

> The competitor half of this comparison reflects publicly available information
> as of April 2026 and has not been revisited since. The counts under "This
> suite" are regenerated from source and tested. We welcome corrections — open
> an issue or PR.
