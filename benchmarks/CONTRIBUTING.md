# Contributing to the Decision Governance Benchmark (DGB)

This covers contributions to the DGB corpus and evaluation harness
specifically (`benchmarks/decision_behavior_corpus.py`,
`benchmarks/evaluation_runner.py`, `benchmarks/agent_under_test.py`). For
the rest of the project (protocol harnesses, community attack patterns,
general code contributions), see the root [`CONTRIBUTING.md`](../CONTRIBUTING.md)
— the same review checklist, security policy, and conflict-of-interest
disclosure rules there apply here too.

## Two ways to contribute

1. **A new corpus case** — a governance-failure scenario not already covered
   by the 52 existing cases.
2. **A Config D agent run** — evaluating a real agent (Claude, GPT, Gemini,
   open-weight, or your own) against the existing corpus and submitting the
   results. See [`LEADERBOARD.md`](LEADERBOARD.md) — it currently has zero
   Config D entries, which is the most valuable gap to fill right now.

## Contributing a new corpus case

### 1. Check it's not a duplicate

Read `benchmarks/README.md`'s category breakdown and skim
`decision_behavior_corpus.py` for the closest existing cases. A new case
should probe a governance failure mode the corpus doesn't already cover —
not a reworded duplicate of an existing `DBC-xxx` entry.

### 2. Ground it in something real

Every existing case cites a documented incident, CVE, or research finding
(see the `source` field and `benchmarks/README.md`'s Sources table) rather
than a hypothetical scenario. New cases should meet the same bar — link the
incident report, CVE, or paper in your PR description and in the case's
`source` field.

### 3. Fill in the `BenchmarkCase` fields

```python
BenchmarkCase(
    id="DBC-0XX",                    # next available ID — see below
    category="escalation_bypass",    # one of the 5 existing categories, or propose a 6th with justification
    name="Short human-readable name",
    description="What this case evaluates",
    scenario="Setup and context presented to the agent",
    expected_behavior="What a well-governed agent must do",
    failure_behavior="What an ungoverned agent does instead",
    # NOTE: scanner_passes was RETIRED 2026-07-27. Do not add it.
    # Instead add a tool-registry fixture to benchmarks/tool_fixtures.py; scanner
    # visibility is derived by running a scanner over it (benchmarks/scanner_derived.py).
    executable_test="GM-00X",        # the harness test ID this case maps to, if one exists
    severity="HIGH",
    source="CVE-2026-XXXXX / incident report URL / paper citation",
    owasp_asi="ASI-0X",
)
```

`scenario`, `expected_behavior`, and `failure_behavior` should each be
concrete and specific enough that a real agent (Config D) or a human
reviewer could unambiguously judge which one it did — vague behavioral
descriptions can't be scored.

### 4. ID allocation

Pick the next available `DBC-0XX` number (current corpus tops out at
`DBC-052`). If two PRs collide, whichever merges first keeps the number;
the other rebases onto the next free one.

### 5. Wire it into the evaluation logic (if needed)

If your case's `failure_behavior` uses novel language that the existing
`_extract_gate_metrics()` / `_check_hard_constraints()` keyword matching in
`evaluation_runner.py` won't recognize, Config B will default to "no
gate-readable signal" (an honest miss, not a bug) unless you also extend
those keyword lists. Don't force a case to match existing keywords just to
inflate Config B's score — an honest gap is more valuable data than an
artificially-caught case.

### 6. Regenerate the paper appendix (if you're touching the release corpus)

`docs/paper-dgb/_gen_appendix.py` regenerates the per-case LaTeX table from
the corpus + `evaluation_results.json`. Run it if your change needs to be
reflected there; this is a separate step from the corpus PR itself and
should be called out explicitly.

### 7. Submit

Open a PR against `benchmarks/decision_behavior_corpus.py`. Run
`python3 -m pytest testing/ -q` and `python3 benchmarks/evaluation_runner.py`
locally first — the sanity checks at the end of the runner's output will
flag if your addition pushes Config A/B/C scores outside their expected
ranges (which usually means a wiring issue, not a real finding).

## Contributing a Config D run

Config D (`benchmarks/agent_under_test.py`) is scaffolding: an
`AgentUnderTest` interface plus a judge-scored `run_config_d` /
`run_evaluation_d`, built but never run against a production agent as of
this writing (no run has been recorded anywhere in this repository).

1. Subclass `AgentUnderTest` and implement `act(case) -> str` to call your
   agent of choice with `case.scenario` as the task.
2. Run it: `run_evaluation_d(YourAgent())` (requires `ANTHROPIC_API_KEY`
   for the judge pass — the agent under test itself doesn't have to be a
   Claude model).
3. **Report the full result, including `UNSCORED`/`ERROR` counts.** A
   partial run (some cases unscored because the judge call failed, or the
   agent errored on others) is real data — report it as such rather than
   only the cases that scored cleanly.
4. Disclose: what agent (model + version), what date, what harness
   version (`protocol_tests/version.py`), and whether you have any
   relationship to this repository or its authors (see the root
   `CONTRIBUTING.md`'s conflict-of-interest section — it applies with
   extra weight here, since a Config D run submitted by whoever built the
   agent under test is exactly the evidence-independence failure mode
   Property 7 of the [Decision Governance Checklist](../docs/DECISION-GOVERNANCE-CHECKLIST.md)
   warns about. Independent, third-party runs are the most valuable
   contribution this benchmark can currently receive.
5. Submit a PR adding your row to `LEADERBOARD.md` with a link to your raw
   `evaluation_results.json`-shaped output (or the full JSON itself) so the
   numbers are independently checkable, not just asserted.

## Questions

Open an issue, or see `SECURITY_POLICY.md` at the repo root if your
question is about the threat model for contributions to a security testing
framework.
