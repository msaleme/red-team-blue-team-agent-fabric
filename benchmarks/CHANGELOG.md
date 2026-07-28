# Decision Governance Benchmark (DGB) — Changelog

Versioned independently of the `agent-security-harness` package
(`pyproject.toml`, currently 4.10.0) and of the wire-protocol test suite in
`protocol_tests/`. This changelog covers only the benchmark corpus,
evaluation harness, baseline results, and paper under `benchmarks/` and
`docs/paper-dgb/`.

## [Unreleased]

### Changed (BREAKING)

- **`BenchmarkCase.scanner_passes` removed; scanner visibility is now derived by
  measurement.** The field was hand-assigned and never validated — until
  2026-07-27 the corpus contained no artifact a scanner could read, so the
  "85% undetectable by metadata-only scanning" headline, Config C, the Scanner
  Gap Score and the McNemar test all derived from a label rather than a result.
  Nine of its 52 assignments disagree with measurement. Retired assignments are
  preserved verbatim as `RETIRED_SCANNER_PASSES_LABELS` so `dgb-v1.0.0` remains
  reproducible. Use `benchmarks/scanner_derived.py` instead.
- **`run_config_c()` now executes a scan** over the tool-registry fixtures
  instead of inverting a boolean. **This supersedes the `dgb-v1.0.0` baseline:**
  Config C GMR 15.4% → 1.9%, SGS subset N=44 → N=51, detection gap 77.3% → 70.6%.
  Configs A (0.0%) and B (71.2%) GMR are unchanged.
- **McNemar re-derived** from the measured results: 36 discordant pairs
  (36 favouring execution, 0 favouring scanning), p ≈ 2.9e-11, replacing
  39 pairs / 34 vs 5 / p ≈ 2.4e-6. Only one arm is measured — Configs A and B
  remain deterministic stub agents.

### Added

- **`benchmarks/tool_fixtures.py`** — tool-registry fixtures for all 52 cases
  (85 tool entries), authored from each case's `scenario` and `failure_behavior`
  with `scanner_passes` deliberately not consulted, so scanning them tests the
  labels rather than restating them. Each fixture records its rationale.
- **`benchmarks/scanner_derived.py`** — `scanner_detects()` / `scanner_misses()` /
  `summary()`, deriving visibility by executing `scan_tool_fields()`.
- **`benchmarks/capability_scanner.py`** — a deterministic capability-rule
  comparator (7 concept rules plus a cross-tool toxic-flow check). Over the same
  fixtures it flags 17 of 52 against the regex scanner's 1 — a 17-fold spread that
  shows the result is a property of the scanner, not of metadata scanning as a class.

### Fixed

- Source attributions across the corpus, paper and bibliography: a BlueRock MCP
  SSRF finding credited to OX Security; METR's reward-hacking figure; the UC
  Berkeley RDI byline and benchmark count; two OpenClaw CVE descriptions that did
  not match their NVD text; and an invalid `CVE-2026-SSRF-MCP` identifier.
- **Grounding provenance disclosed**: 24 of 52 cases (46%) are grounded wholly or
  partly in the author's own systems — internal HRAO-E runs (13, run data
  unpublished), an internal MCP cost-inflation finding (4), and the
  `agent-security-harness` suites (7). Those are not external corroboration.

### Known open items

- 10 cases whose cited source does not substantiate them; 7 misdescribed cases.
- `executable_test` does not cover the case for 24 of 52 at the `dgb-v1.0.0` tag.
- The fixtures, both scanners and the audit share one author. **Independent
  fixture review is the most valuable outstanding check.**

### Added

- **`benchmarks/CONTRIBUTING.md`**: DGB-specific contribution guide covering
  how to submit a new corpus case (ID allocation, required `BenchmarkCase`
  fields, grounding in a documented incident/CVE/paper) and how to submit a
  Config D real-agent evaluation run (disclosure requirements, what to
  report including `UNSCORED`/`ERROR` counts).
- **`benchmarks/LEADERBOARD.md`**: results table seeded with the real,
  already-published Config A/B/C baseline (from `evaluation_results.json`,
  `dgb-v1.0.0`). Explicitly discloses that it currently has one contributor
  (the benchmark's own author) and zero Config D entries — no placeholder
  or estimated numbers.

- **Config D scaffolding** (`benchmarks/agent_under_test.py`): an
  `AgentUnderTest` interface and judge-scored `run_config_d` /
  `run_evaluation_d` in `evaluation_runner.py`, so a real agent (Claude,
  GPT, Gemini, or open-weight) can be plugged in and evaluated against the
  52-case corpus. This is scaffolding only — no run against a production
  agent has been performed or recorded. `run_config_d` returns
  `"UNSCORED"` rather than a fabricated PASS/FAIL whenever no judge is
  available. Config A/B/C baselines above are unaffected.

## [dgb-v1.0.0] — 2026-07-25

First versioned, citable release. Corresponds to the results reported in
*Decision Governance Benchmark: Executable Behavioral Tests for Autonomous
AI Agent Security* (docs/paper-dgb/main.tex).

### Included in this release

- **Corpus** (`benchmarks/decision_behavior_corpus.py`): 52 `BenchmarkCase`
  entries across 5 categories (escalation_bypass, collusion,
  memory_tampering, payment_chain, evidence_fabrication — see
  `benchmarks/README.md` for the full breakdown), each grounded in a
  documented incident, CVE, or research finding rather than a hypothetical
  scenario.
- **Evaluation harness** (`benchmarks/evaluation_runner.py`): runs the
  corpus against a configurable agent under test and scores each case
  PASS/FAIL against its `expected_behavior`/`failure_behavior` contrast.
- **Baseline results** (`benchmarks/evaluation_results.json`): the exact
  per-case, per-configuration (A: ungoverned, B: constitutional, C: scanner
  only) results reported in the paper's Section 5 and Appendix A. Corpus
  run timestamp `2026-04-17T12:07:43Z`.
- **13 complementary harness tests** in `protocol_tests/`: 7 benchmark
  integrity tests (`benchmark_integrity_harness.py`, BI-001..007) and 6
  governance modification tests (`governance_modification_harness.py`,
  GM-001..006), which the corpus's `executable_test` field references.
- **Paper** (`docs/paper-dgb/`): full LaTeX source, compiled PDF build
  instructions, and the per-case appendix generator
  (`docs/paper-dgb/_gen_appendix.py`) that regenerates Appendix A directly
  from this release's `evaluation_results.json` and
  `decision_behavior_corpus.py`.

### Findings this release establishes as citable, reproducible baselines

- 44/52 cases (85%) are undetectable by metadata-only scanning
  (`scanner_passes=True`) — the failure only manifests when the decision
  path executes.
- Config B (constitutional governance, `constitutional-agent` v0.1.0):
  71.2% Governance Maintenance Rate (GMR), 77.3% Scanner Gap Score (SGS).
  Config A (ungoverned): 0% GMR. Config C (scanner only): 15.4% GMR, 0%
  SGS.
- The scanner-vs-execution detection gap is statistically significant:
  McNemar's exact test on the paired Config B/Config C per-case outcomes,
  $p \approx 2.4 \times 10^{-6}$ (39 discordant pairs, 34 favoring
  execution-based detection vs. 5 favoring scanning).

### Known limitations at this release (see paper Section 6.3, "Threats to
Validity," for the full discussion)

- Baseline results use deterministic stub agents, not production LLM
  agents (Claude, GPT, Gemini, or otherwise) — this release validates the
  benchmark and harness, not commercial systems.
- The corpus and the evaluated governance implementation
  (`constitutional-agent`) share an author — flagged in the paper as the
  single largest threat to validity, with independent third-party
  replication named as the most important open follow-up.

### Fixed in this release

- `benchmarks/README.md` had drifted from the actual corpus: it previously
  stated "50 cases" / "70%+ scanner miss rate" and an incomplete Sources
  table, all stale relative to the current 52-case / 85%-miss-rate corpus.
  Corrected to match `decision_behavior_corpus.py` exactly as of this tag.

---

Corpus and harness are MIT licensed. See the root
[`LICENSE`](../LICENSE) file. Citation format: `benchmarks/README.md`.
