# DGB audit reports

Three reports from a self-audit of the Decision Governance Benchmark, run
2026-07-26/27 against the published `dgb-v1.0.0` baseline
([`6c5d617`](https://github.com/msaleme/red-team-blue-team-agent-fabric/tree/6c5d61726819165c9dcf75d99669217c3c3cab41)).

They are published because the corpus's most-cited number did not survive the
audit, and a withdrawal is only checkable if the working is shown.

## The short version

The corpus claimed that **metadata scanners miss 85% of behavioural governance
failures (44 of 52)**. That figure was **definitional, not empirical**. It
counted a hand-assigned boolean, `scanner_passes`, that recorded the author's
judgement per case. The scanner configuration inverted that same boolean and
reported it back as a finding. Nothing was measured.

The field has been retired. Scanner visibility is now derived by executing a
real scanner over authored tool-registry fixtures. Two scanners over the same
52 fixtures give **1 of 52** and **17 of 52** depending on the scanner and the
signal definition, which is why no single "% invisible to metadata scanning"
figure replaced the old one.

## The reports

| Report | What it covers |
|---|---|
| [`dgb-scanner-passes-audit.md`](dgb-scanner-passes-audit.md) | The field itself: why 85% was a label counted, not a result found, and why the Scanner Gap Score of 0.0% is zero by construction |
| [`dgb-scanner-measurement.md`](dgb-scanner-measurement.md) | The executed replacement: a real 14-pattern scanner over 52 authored fixtures, and the nine labels that did not reproduce |
| [`dgb-two-scanner-comparison.md`](dgb-two-scanner-comparison.md) | A second, capability-rule scanner over the same fixtures, and the three kinds of signal it conflates |

## How to read them

They are the working record, not a summary written afterwards. Passages marked
**⟲** are corrections to earlier drafts of the same report, kept in place
rather than silently revised, including places where an earlier version of the
analysis was wrong.

Statements in the `scanner_passes` audit such as "no scannable artifact
exists" and "not measured" describe the **`dgb-v1.0.0` baseline**. They were
true of it and are retained as the audit record; the remediation that followed
is at
[`b361227`](https://github.com/msaleme/red-team-blue-team-agent-fabric/tree/b361227f9892a5b07ebeca784137d5bfcba8d48d).

## Reproducing the measurements

```bash
python -c "from benchmarks.scanner_derived import summary; print(summary())"
# -> {'scanner': 'protocol_tests.mcp_tool_poisoning_harness.scan_tool_fields',
#     'total': 52, 'detected': 1, 'missed': 51, 'detected_ids': ['DBC-039']}

python -c "from benchmarks.capability_scanner import capability_detects; \
           from benchmarks.tool_fixtures import FIXTURES; \
           print(sum(capability_detects(i) for i in FIXTURES), 'of', len(FIXTURES))"
# -> 17 of 52

python benchmarks/evaluation_runner.py   # Config C GMR 1.9%
```

## The limitation these reports do not resolve

**The fixtures, both scanners, and this audit share one author.** The
capability-rule scanner is a stronger comparator, not an outside check.
Independent evaluation design and reproduction are the outstanding work, and
nothing in these three reports substitutes for them.

Each of the 52 fixtures carries its rationale in
[`benchmarks/tool_fixtures.py`](../../benchmarks/tool_fixtures.py) so that any
one of them can be disagreed with specifically rather than in general.

## Not included here

A parallel audit of the corpus's `source` and `executable_test` fields found a
separate class of defect: cases whose cited source does not substantiate them,
and cases mapped to a harness test that does not cover the described
behaviour. Those findings are recorded as known open items in
[`benchmarks/CHANGELOG.md`](../../benchmarks/CHANGELOG.md) and will be
published once the corpus corrections they call for have been made.
