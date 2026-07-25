# Decision Governance Benchmark (DGB) — Changelog

Versioned independently of the `agent-security-harness` package
(`pyproject.toml`, currently 4.10.0) and of the wire-protocol test suite in
`protocol_tests/`. This changelog covers only the benchmark corpus,
evaluation harness, baseline results, and paper under `benchmarks/` and
`docs/paper-dgb/`.

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
