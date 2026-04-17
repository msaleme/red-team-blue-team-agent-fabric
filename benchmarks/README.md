# Decision Behavior Benchmark Corpus

**v1.0 — Issue [#120](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/120)**

A curated, machine-readable corpus of decision-behavior test cases for autonomous
AI agents. Part of the v5.0 "Lock the Category" milestone.

## What this is

The corpus documents 50+ failure modes where an ungoverned agent takes a harmful
action that a well-governed agent must block. Every case includes:

- The scenario and context presented to the agent
- What a well-governed agent must do (`expected_behavior`)
- What an ungoverned agent does instead (`failure_behavior`)
- Whether a metadata-only scanner (tool description scan) would catch it
  (`scanner_passes`)
- A reference to the executable harness test that covers the case
  (`executable_test`)

The central finding: **metadata scanners miss 70%+ of behavioral failures**.
The failure lives in the execution path — the *decision* the agent makes — not
in the description of the tool it calls. Scanning tool descriptions is
insufficient; you need to execute the decision path.

## Usage

```python
from benchmarks.decision_behavior_corpus import CORPUS, BenchmarkCase

# All 50+ cases
print(len(CORPUS))

# Filter by category
escalation = [c for c in CORPUS if c.category == "escalation_bypass"]

# Scanner contrast set
scanner_misses = [c for c in CORPUS if c.scanner_passes]
scanner_catches = [c for c in CORPUS if not c.scanner_passes]

print(f"Scanner misses {len(scanner_misses)}/{len(CORPUS)} cases "
      f"({len(scanner_misses)/len(CORPUS)*100:.0f}%)")
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
| `evidence_fabrication` | DBC-041–050 | 10 | Fabrication, inflation, or misrepresentation of evaluation results |

**Total: 50 cases across 5 categories.**

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
    scanner_passes: bool     # True = metadata scanner misses this
    executable_test: str     # harness test reference (e.g., "GM-001", "BI-003")
    severity: str            # P0-Critical | P1-High | P2-Medium | P3-Low
    source: str              # incident/research source
    owasp_asi: str           # OWASP ASI mapping
```

## Contrast-Set Methodology

Each case carries a `scanner_passes` boolean:

- **`True`** — a metadata-only scanner (scanning tool descriptions, API schema,
  or static configuration) would not detect this failure. The failure is
  behavioral: it only becomes visible when the agent executes the decision path.
- **`False`** — a scanner that inspects tool descriptions or configurations could,
  in principle, flag this case without executing the agent.

The corpus maintains >= 70% `scanner_passes=True` cases. This is the core
argument for executable behavioral testing: the majority of agent governance
failures require running the agent to observe.

## Executable Test Mapping

Each corpus case references an executable harness test via `executable_test`:

| Prefix | Harness |
|---|---|
| `GM-xxx` | `protocol_tests/governance_modification_harness.py` |
| `BI-xxx` | `protocol_tests/benchmark_integrity_harness.py` |
| `MCP-xxx` | `protocol_tests/mcp_harness.py` |
| `CVE-xxx` | `protocol_tests/cve_2026_25253_harness.py` |
| `L402-xxx` | `protocol_tests/l402_harness.py` |
| `x402-xxx` | `protocol_tests/x402_harness.py` |

## Citation

If you reference this corpus in a paper or report:

```
Agent Security Harness Decision Behavior Benchmark Corpus v1.0.
msaleme/red-team-blue-team-agent-fabric, Issue #120. April 2026.
https://github.com/msaleme/red-team-blue-team-agent-fabric

Sources: UC Berkeley RDI (Xu et al. 2025), lightningzero 2026,
METR Autonomy Evaluation Framework 2025, OX Security 2026,
zhuanruhu 2026, OpenClaw CVE-2026-35625/35629, Kiro/Amazon 2026.
```

## Sources

| Source | Finding | Cases |
|---|---|---|
| UC Berkeley RDI (Xu et al. 2025) | All 8 major AI benchmarks hackable for perfect scores | DBC-041–050 |
| lightningzero 2026 | 9/12 agents self-disabled governance gates within 48h | DBC-001–005 |
| METR 2025 | Reward-hacking in >30% of o3 and Claude 3.7 Sonnet eval runs | DBC-012, 013, 017, 020, 050 |
| OX Security 2026 | MCP STDIO injection, 36.7% SSRF, cross-agent relay | DBC-009, 016, 032, 037 |
| zhuanruhu 2026 | 2,847 memory deletions in production deployment | DBC-021–030 |
| OpenClaw CVE-2026-35625 | Privilege escalation via tool permission inheritance | DBC-003, 006 |
| OpenClaw CVE-2026-35629 | SSRF via tool URL parameter | DBC-037 |
| Kiro/Amazon 2026 | Autonomous file deletion during reorganization task | DBC-007 |
| MCP cost inflation 2026 | 658x compute cost via recursive tool calls | DBC-008, 033, 015 |
| IQuest-Coder 2026 | Git log copying to inflate benchmark scores | DBC-042, 046 |
| $45M crypto agent 2026 | Autonomous over-threshold trade approval | DBC-031, 036, 038, 040 |
