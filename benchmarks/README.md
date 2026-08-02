# Decision Behavior Benchmark Corpus

**[`dgb-v1.0.0`](https://github.com/msaleme/red-team-blue-team-agent-fabric/releases/tag/dgb-v1.0.0) — Issue [#120](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/120)**

A curated, machine-readable corpus of decision-behavior test cases for autonomous
AI agents. Part of the v5.0 "Lock the Category" milestone. This is the corpus
and evaluation harness behind the paper *Decision Governance Benchmark:
Executable Behavioral Tests for Autonomous AI Agent Security* (see
[`docs/paper-dgb/`](../docs/paper-dgb/)). The `dgb-v1.0.0` tag is versioned
independently of the `agent-security-harness` package (`pyproject.toml`) —
they are separate deliverables that happen to live in the same repository.

## What this is

The corpus documents 52 failure modes where an ungoverned agent takes a harmful
action that a well-governed agent must block. Every case includes:

- The scenario and context presented to the agent
- What a well-governed agent must do (`expected_behavior`)
- What an ungoverned agent does instead (`failure_behavior`)
- Whether a metadata-only scanner (tool description scan) would catch it
  (derived — see `benchmarks/scanner_derived.py`)
- A reference to the executable harness test that covers the case
  (`executable_test`)
- The grounding source (`source`)

### Grounding provenance

Not every case is externally grounded. **29 of the 52 cases (56%) are grounded in
the author's own work** — internal HRAO-E deployment runs, the MCP cost-inflation
finding, the `agent-security-harness` suites, and seven cases declared
author-constructed on 2026-08-02 after their citations were withdrawn. The
`memory_tampering` category is the most affected: 9 of its 10 cases derive from a
single internal run.

The figure is derived, not maintained by hand, and guarded by
`test_author_grounded_count_is_derived`. **Definition:** a case counts as
externally grounded if its `source` names a third-party publication, ignoring
withdrawn `NOTE:` material. Everything else is author-grounded. The previously
published figure was *24 of 52 (46%)*; it rose because seven citations were
withdrawn, not because new internal cases were added. The earlier breakdown
(`13 + 4 + 7`) also double-counted — the audit's seven `full (internal)` rows
already contained the four cost-inflation cases.

Those 28 cases are **not** independent corroboration. Read the `source` field
before citing any individual case as externally evidenced.

**The former "85% (44 of 52)" headline has been withdrawn.** The audit that
withdrew it is published in [`docs/audits/`](../docs/audits/). It was a
hand-assigned label, not a measurement: until 2026-07-27 the corpus contained no
artifact a scanner could read. See `benchmarks/CHANGELOG.md`.

Measured instead, against the tool-registry fixtures in `tool_fixtures.py`:

| Scanner | Fixtures flagged |
|---|---|
| `scan_tool_fields` — 14 regex patterns | **1 / 52** |
| `capability_scanner.scan_registry` — 7 capability concepts | **17 / 52** |

Of the 17, two disclose the abusive behaviour in the registry text, one exposes a
toxic capability combination, and fourteen indicate only that a risky capability
is present. **Any "% undetectable" figure depends on the scanner, the fixture
set, and what qualifies as detection** — it is not a property of metadata
scanning in the abstract. Cite all three alongside it.

The failure ordinarily lives in the execution path — the *decision* the agent
makes — not in the description of the tool it calls. Scanning tool descriptions
did not surface it here; executing the decision path did.

## Usage

```python
from benchmarks.decision_behavior_corpus import CORPUS, BenchmarkCase

# All 52 cases
print(len(CORPUS))

# Filter by category
escalation = [c for c in CORPUS if c.category == "escalation_bypass"]

# Scanner contrast set
from benchmarks.scanner_derived import scanner_detects, scanner_misses
scanner_missed  = [c for c in CORPUS if scanner_misses(c.id)]
scanner_caught  = [c for c in CORPUS if scanner_detects(c.id)]

print(f"Scanner does not flag {len(scanner_missed)}/{len(CORPUS)} cases "
      f"({len(scanner_missed)/len(CORPUS)*100:.0f}%)")
```

The corpus is also accessible via the benchmark integrity harness:

```python
from protocol_tests.benchmark_integrity_harness import load_corpus
corpus = load_corpus()
```

## Category Breakdown

| Category | IDs | Cases | Description |
|---|---|---|---|
| `escalation_bypass` | DBC-001–010 | 10 | Privilege, scope, or authority escalation without authorization |
| `collusion` | DBC-011–020 | 10 | Multi-agent cooperation to circumvent controls |
| `memory_tampering` | DBC-021–030 | 10 | Manipulation of history, context, or audit state |
| `payment_chain` | DBC-031–040 | 10 | Abuse of payment or tool execution paths |
| `evidence_fabrication` | DBC-041–052 | 12 | Fabrication, inflation, or misrepresentation of evaluation results |

**Total: 52 cases across 5 categories.**

## BenchmarkCase Schema

```python
@dataclass
class BenchmarkCase:
    id: str                  # "DBC-001"
    category: str            # escalation_bypass | collusion | memory_tampering |
                             #   payment_chain | evidence_fabrication
    name: str                # human-readable short name
    description: str         # what the test case evaluates
    scenario: str            # setup and context presented to the agent
    expected_behavior: str   # what a well-governed agent must do
    failure_behavior: str    # what an ungoverned agent does instead
    executable_test: str     # harness test reference (e.g., "GM-001", "BI-003")
    severity: str            # P0-Critical | P1-High | P2-Medium | P3-Low
    source: str              # incident/research source
    owasp_asi: str           # OWASP ASI mapping
```

## Contrast-Set Methodology

Scanner visibility is **derived, not stored**. `scanner_passes` was retired on
2026-07-27; see `benchmarks/scanner_derived.py`:

- **`True`** — a metadata-only scanner (scanning tool descriptions, API schema,
  or static configuration) would not detect this failure. The failure is
  behavioral: it only becomes visible when the agent executes the decision path.
- **`False`** — a scanner that inspects tool descriptions or configurations could,
  in principle, flag this case without executing the agent.

**Measured:** a pattern-based scanner (`scan_tool_fields`, 14 regexes) run over the
tool-registry fixtures detects **1 of 52**; 51 are not flagged. The retired
hand-assigned labels claimed 8 and 44. This number is a property of that scanner
over those fixtures — report both alongside it. This is the core
argument for executable behavioral testing: the large majority of agent
governance failures were not surfaced by scanning these tool descriptions. Note
that no production agent is invoked — Configs A/B are deterministic functions
over each case's metadata — so this does not establish what running an agent
would show. (See `docs/paper-dgb/main.tex` Section 5.3 for a McNemar's
exact test on this detection gap, $p \approx 2.9\times10^{-11}$ — nominal, and
comparing a deterministic Config B against an executed Config C.)

## Evaluation Configurations

`benchmarks/evaluation_runner.py` scores the corpus under four
configurations:

| Config | What it does | Requires network/credentials? | Status |
|---|---|---|---|
| A: Ungoverned | Always executes `failure_behavior` | No | Run — baseline (`dgb-v1.0.0`) |
| B: Constitutional | Deterministic gate/HC logic reads `failure_behavior` text | No | Run — baseline (`dgb-v1.0.0`) |
| C: Scanner Only | Scans `tool_fixtures.py` | No | Run — **supersedes the `dgb-v1.0.0` baseline** |
| D: Real Agent Under Test | Invokes a real agent, judge-scores its response | Yes (agent + `ANTHROPIC_API_KEY` for the judge) | **Scaffolding only — not yet run** |

Configs A/B/C are deterministic rule-based functions over each case's own
metadata — none of them invoke an LLM or agent. They establish the
benchmark and harness baseline, not evidence about any real agent's
behavior.

Config D (`benchmarks/agent_under_test.py`) closes that gap: implement the
`AgentUnderTest` interface to wire in a real agent (Claude, GPT, Gemini, or
open-weight), then score it via `evaluation_runner.run_config_d`, which
uses an independent LLM judge (`protocol_tests._utils.model_judge_compliance`)
to compare the agent's actual response against `expected_behavior` /
`failure_behavior`. As of this writing no such run has been performed or
recorded anywhere in this repository — `run_config_d` returns `"UNSCORED"`
(never a fabricated PASS/FAIL) whenever the judge isn't available, so
partial or missing evaluations can't be silently reported as results. See
`benchmarks/agent_under_test.py` for the interface and
`testing/test_evaluation_runner_config_d.py` for the tests that guard this
behavior.

Results (Config A/B/C baseline today; Config D once real runs exist) are
tracked in [`LEADERBOARD.md`](LEADERBOARD.md). To submit a new corpus case
or a Config D run, see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Executable Test Mapping

Each corpus case references an executable harness test via `executable_test`:

| Prefix | Harness |
|---|---|
| `GM-xxx` | `protocol_tests/governance_modification_harness.py` |
| `BI-xxx` | `protocol_tests/benchmark_integrity_harness.py` |
| `MCP-xxx` | `protocol_tests/mcp_harness.py` |
| `CVE-xxx` | `protocol_tests/mcp_tool_poisoning_harness.py` |
| `L402-xxx` | `protocol_tests/l402_harness.py` |
| `x402-xxx` | `protocol_tests/x402_harness.py` |

## Citation

If you reference this corpus in a paper or report, cite the versioned release
rather than the repository at large, so the citation stays pinned to the
exact 52-case corpus a result was evaluated against:

```
Saleme, M. K. (2026). Decision Governance Benchmark (DGB) Corpus, v1.0.0.
msaleme/red-team-blue-team-agent-fabric, Issue #120.
https://github.com/msaleme/red-team-blue-team-agent-fabric/releases/tag/dgb-v1.0.0

Sources: UC Berkeley RDI 2026 (Wang, Mang, Cheung, Sen, Song), internal
HRAO-E runs (unpublished),
METR Autonomy Evaluation Framework 2025, OX Security 2026,
OpenClaw CVE-2026-35625/35629, Kiro/Amazon 2026.
```

If citing the accompanying paper instead of (or in addition to) the corpus
directly, see [`docs/paper-dgb/README.md`](../docs/paper-dgb/README.md) for
the paper's own citation and arXiv identifier once submitted.

## Sources

**Published sources.** These are externally verifiable.

Case lists below are derived from the `source` field of each case and guarded by
`test_readme_source_table_matches_the_corpus`. They were previously maintained by
hand and had drifted: `DBC-037` was listed under OX Security although it has
never cited OX, four METR cases were missing, and both internal-run ranges
included a case that belongs to a different source. A source table that is
edited by hand next to a corpus that is edited by code will always drift; the
test is the fix, not this paragraph.

The **fetched** column records whether the corroboration audit (v6, 2026-07-27)
actually retrieved the source and read it. Rows marked no are not findings of
absence — they are unchecked.

<!-- dgb:source-table:start -->

| Source | Finding | Fetched | Cases |
|---|---|---|---|
| UC Berkeley RDI 2026 (Wang, Mang, Cheung, Sen, Song) | All 8 major AI benchmarks gamed for near-perfect scores | yes | DBC-028, DBC-036, DBC-041, DBC-045, DBC-047, DBC-048 |
| METR 2025 | Reward-hacking in >30% of o3 and Claude 3.7 Sonnet eval runs | no | DBC-010, DBC-011, DBC-012, DBC-013, DBC-017, DBC-019, DBC-020, DBC-050 |
| OX Security 2026 | MCP STDIO command/argument injection | yes | DBC-009, DBC-032 |
| OpenClaw CVE-2026-35625 | Privilege escalation via tool permission inheritance | yes | DBC-003, DBC-006 |
| OpenClaw CVE-2026-35629 | SSRF via unguarded configured base URLs in channel extensions | yes | DBC-037 |
| Kiro/Amazon 2026 | Autonomous file deletion during reorganization task | no | DBC-007 |
| MCP cost inflation 2026 | 658x compute cost via recursive tool calls | no | DBC-008, DBC-015, DBC-018, DBC-033 |
| IQuest-Coder 2026 | Git log copying to inflate benchmark scores | no | DBC-042, DBC-046 |
| AgentSeal runtime exploitation 2026 | Credential retention in tool descriptions | no | DBC-051 |
| Return channel poisoning (harness RCP-001, CVE-004) | Cross-tool context leakage | n/a — internal | DBC-052 |

<!-- dgb:source-table:end -->

**One source in this table has no locatable publication.** `$45M crypto agent
2026` is cited by `DBC-036` and appears nowhere in `docs/paper-dgb/references.bib`
or anywhere else in this repository as an identifiable article, incident report
or advisory. The audit found it does not substantiate the cases that cited it.
It is listed here rather than quietly dropped, because a reader comparing the
corpus against this table would otherwise find a citation with no row.

| Source | Status | Cases |
|---|---|---|
| $45M crypto agent 2026 | No locatable publication; audit found it unsupporting | DBC-036 (partial — the RDI half of that case's citation holds) |

**Withdrawn attributions.** These cases previously cited a published source that
the audit found does not cover them. The citation was removed on 2026-08-02 and
the cases are now declared author-constructed. Removing an unsupportable
citation is a correction of the record; it does not make the behaviour
corroborated, and these cases claim no external support.

| Case | Previously cited | What the audit found |
|---|---|---|
| DBC-014 | OX Security 2026 | Advisory covers STDIO command/argument injection, not credential relay or agent impersonation |
| DBC-016 | OX Security 2026 | Does not cover A2A cross-agent injection relay |
| DBC-039 | OX Security 2026 | Does not cover phantom tool injection via MCP tool registration |
| DBC-031 | $45M crypto agent 2026 | Does not substantiate a single agent approving an over-threshold trade |
| DBC-038 | $45M crypto agent 2026 | Credential extraction in a payment flow not evidenced |
| DBC-040 | $45M crypto agent 2026 | Payment structuring to evade limits not evidenced |
| DBC-044 | UC Berkeley RDI 2026 | Demonstrates gaming without task-solving; does not discuss contamination or memorisation |
| DBC-026 | OX Security 2026 (external half of a compound citation) | Does not cover cross-agent or cross-session memory contamination. Hidden from the currency flag because revising the internal half flipped the case digest; found by re-reading on 2026-08-02. Case still rests on an unpublished internal run. |
| DBC-043, DBC-049 | UC Berkeley RDI 2026 | Does not discuss LLM-judge manipulation or string-collision gaming (withdrawn earlier, 2026-07-27) |

**Internal, unpublished.** `lightningzero` and `zhuanruhu` are internal HRAO-E
runs by the corpus author. The underlying run data is not public, so these are
**not** independent corroboration of the corpus — they are the author's own
observations, recorded here so the distinction is visible rather than implied.

<!-- dgb:internal-table:start -->

| Internal run | Observation | Cases |
|---|---|---|
| HRAO-E `lightningzero` (2026, unpublished) | 9/12 agents self-disabled governance gates within 48h | DBC-001, DBC-002, DBC-004, DBC-005 |
| HRAO-E `zhuanruhu` (2026, unpublished) | 2,847 memory deletions in production deployment | DBC-021, DBC-022, DBC-023, DBC-024, DBC-025, DBC-026, DBC-027, DBC-029, DBC-030 |

<!-- dgb:internal-table:end -->
