# Decision Governance Benchmark — Leaderboard

Results are per-configuration GMR (Governance Maintenance Rate: the
fraction of the 52-case corpus where governance held) with a Wilson 95%
confidence interval, plus SGS (Scanner Gap Score: GMR restricted to the 51
cases invisible to metadata-only scanning). See `benchmarks/README.md`'s
"Evaluation Configurations" section for what each config means, and
`docs/paper-dgb/main.tex` Section 5 for full methodology.

**Current state: this leaderboard has exactly one contributor (the
benchmark's own author) and zero Config D (real-agent) entries.** That is
disclosed, not hidden — read the "Reading this table honestly" section
below before drawing conclusions from it. Community submissions, especially
independent Config D runs, are the most valuable thing this leaderboard is
currently missing (see `benchmarks/CONTRIBUTING.md`).

## Configs A/B/C — deterministic baseline (no agent invoked)

| Config | GMR | 95% CI | SGS (N=51) | 95% CI | Contributor | Harness version | Date |
|---|---|---|---|---|---|---|---|
| A: Ungoverned | 0.0% | [0.0%, 6.9%] | 0.0% | [0.0%, 8.0%] | Michael K. Saleme (benchmark author) | 4.10.0 | 2026-04-17 |
| B: Constitutional (`constitutional-agent` v0.1.0) | 71.2% | [57.7%, 81.7%] | 70.6% | [57.0%, 81.3%] | Michael K. Saleme (benchmark author) | 4.10.0 | 2026-07-28 |
| C: Scanner Only (**measured**) | 1.9% | [0.3%, 10.1%] | 0.0% | [0.0%, 7.0%] | Michael K. Saleme (benchmark author) | 4.10.0 | 2026-07-28 |

Source: `benchmarks/evaluation_results.json` (run timestamp
`2026-04-17T12:07:43Z`), the same data reported in the `dgb-v1.0.0` release
and the paper's Section 5. These three configs are deterministic — re-running
`python3 benchmarks/evaluation_runner.py` against an unchanged corpus will
reproduce identical numbers, so "contributor" here means "who ran the
harness and reported it," not "whose agent was tested." Configs A and C
don't test an agent at all; Config B tests one specific, author-built
governance implementation (`constitutional-agent`) — see the paper's
"Threats to Validity" section for why that's flagged as a limitation, not
presented as an industry baseline.

## Config D — real agent, judge-scored

*(No entries yet.)*

Config D (`benchmarks/agent_under_test.py`) is built and unit-tested
(`testing/test_evaluation_runner_config_d.py`) but has never been run
against a real production agent — no credentials or network access were
available in the environment that built it. This table will be populated
only from actual recorded runs; it will never carry a placeholder or
estimated number.

To add a row: implement `AgentUnderTest`, run `run_evaluation_d(agent)`,
and submit a PR per `benchmarks/CONTRIBUTING.md`'s "Contributing a Config D
run" section — including the full `UNSCORED`/`ERROR` breakdown, not just
clean-scoring cases. Suggested columns once entries exist: Agent (model +
version), GMR, 95% CI, SGS, Unscored/Error count, Contributor, Conflict-of-
interest disclosure, Date, Raw results link.

## Reading this table honestly

- **Config C changed on 2026-07-28 and supersedes the `dgb-v1.0.0` figures.** It
  previously reported 15.4% GMR by inverting a hand-assigned `scanner_passes`
  field. That field is retired; Config C now executes a pattern-based scanner over
  the tool-registry fixtures in `benchmarks/tool_fixtures.py` and flags 1 of 52.
  A capability-rule comparator over the same fixtures flags 17, of which only 2
  disclose the failure itself. **The number moves with the scanner — cite the
  scanner and the fixture set alongside it.**
- **Config C's SGS is structurally zero**, not an empirical finding: Config C passes
  exactly when the scanner flags, so restricted to unflagged cases it can only
  score 0.
- Config B's 71.2% GMR is **one governance implementation's** score, not a
  general property of "AI agents" or even of "constitutional governance" as
  an approach — `constitutional-agent` and the DGB corpus share an author,
  which is the paper's own largest disclosed threat to validity.
- Nothing in this table currently says anything about how Claude, GPT,
  Gemini, or any other production agent behaves on this corpus. That's the
  Config D gap above — the whole reason the "Real-agent evaluation
  scaffolding" work landed before this leaderboard did.
- A single row per config is not a trend or a comparison — this leaderboard
  becomes useful once there are multiple independent Config D submissions
  to actually compare, which requires community contribution, not more
  work by this repository's own author.
