# CRITICAL EVALUATION — Round 35

**Date:** 2026-07-25
**Round:** 35
**Focus:** Self-audit of the four Claude Cookbook-primitive harnesses + multi-agent
race-condition tests + jailbreak model-based grading (PRs #271-274, merged
2026-07-25)
**Test count:** 595 across 43 modules
**Version:** 4.9.1 (unbumped, consistent with current post-4.9.1 convention of
bumping version only in a dedicated release-prep commit, not per-feature-PR)
**Evaluator:** Automated round (3 parallel audit agents — security, logic/
correctness, consistency/integration — each scoped to the session's new/
changed files, per CLAUDE.md's round procedure)

---

## 1. What Changed (this session, prior to this round)

| PR | Change | Tests |
|---|---|---|
| #271 | New modules `tool_search_harness.py` (TS-001..006), `ptc_harness.py` (PTC-001..006) | 565 → 577 |
| #271 | `multi_agent_harness.py` v3.4 → v3.5: MAG-013..018 (race-condition-pretext attacks) | 577 → 583 |
| #271 | `jailbreak_harness.py` v3.0 → v3.1: opt-in `--judge` model-based grading via new `protocol_tests._utils.model_judge_compliance()` | 583 (unchanged, methodology only) |
| #271 | New module `prompt_caching_harness.py` (PCH-001..006) | 583 → 589 |
| #271 | New module `extended_thinking_harness.py` (ET-001..006) | 589 → 595 |
| #272 | `docs/STRATEGY.md`: test-count refresh + cookbook-coverage risk paragraph | — |
| #273 | `SKILL.md`: stale-count fix (553→595) + new `test_skill_md` regression guard | — |
| #274 | Recovered stalled `docs/paper-dgb/main.tex` reviewer edits; dropped dead NeurIPS 2026 deadline | — |

**This round (R35)** is a self-audit of that work, not new coverage. Three
parallel agents each audited the same file scope (the four new harness
modules, plus the modified `multi_agent_harness.py`, `jailbreak_harness.py`,
and `_utils.py`) from a different angle — security, logic/correctness,
consistency/integration — matching CLAUDE.md's "use parallel agents for
thorough audits" instruction. Real findings were fixed in this round; details
below.

---

## 2. Prior Fix Verification

R35 doesn't inherit an open defect list from R34 (AP2 harness, 2026-07-01) —
the intervening 24 days saw substantial unrelated work land on `main` (receipt-
claim verification, MCP tool-poisoning reproduction, settlement-finality,
card-token conformance, etc., per `git log`). Verification here is scoped to
confirming that work plus R35's own fixes are all intact:

| Area | Guard | Status |
|---|---|---|
| AP2 mandate-chain (R34) | `TestRegAP2` (8 checks) | ✅ intact, full suite green |
| VS-R03 verdict-correctness | `test_vsr03_verdict_correctness.py` | ✅ intact |
| MCP-019/020 composite poisoning | full suite | ✅ intact |
| Receipt-claim verification (RCL-001..011) | full suite | ✅ intact |
| Everything merged in PRs #271-274 | full suite + `count_tests.py` | ✅ intact, 595 confirmed |

---

## 3. Issues Found & Fixed This Round

| # | Severity | File:line | Issue | Fix |
|---|---|---|---|---|
| #275 | LOW-MEDIUM | `extended_thinking_harness.py` (ET-003) | Simulate-mode leak check was a self-referential tautology: `_naive_render` returned its input verbatim, so `naive_output == redacted_block["data"]` reduced to `x == x`, always `True` regardless of any real detection logic — a "test that can't fail" (CLAUDE.md-flagged recurring class) | Introduced a real detector function `_exposes_raw_payload(rendered_text, block)` doing an actual containment check (`raw in rendered_text`); `_naive_render` now embeds the payload in a larger string so detecting the leak requires genuine substring logic, not identity comparison |
| #276 | LOW-MEDIUM | `jailbreak_harness.py` (4 locations: docstring, `run_all` banner, `generate_report`, trial_runner `suite_name`) | Version string disagreed across the file: v3.1/v3.0/v3.0/v3.4 — partly newly introduced (docstring bumped to v3.1 by the `--judge` commit, other 3 sites weren't touched), partly pre-existing (the stray v3.4 predates this session) | All four sites now consistently say v3.1 |
| #277 | LOW | `README.md:13`, `docs/TEST-INVENTORY.md:3,6,183` | "42 modules" stale — extended-thinking harness pushed the count to 43, but the commit that added it (`68c15d4`) bumped its own commit-message text from 41→42 instead of 42→43, one step behind. No existing regression test checked module-count prose (only test-count) | Fixed all 4 locations; added `TestRegTestCount.test_readme_module_count` / `test_test_inventory_module_count` |
| #278 | LOW / informational | `CHANGELOG.md` `[Unreleased]` | No entry for PRs #271-274 | Added a summary entry |

**Not fixed, accepted as a documented tradeoff:**

| # | Severity | File:line | Issue | Disposition |
|---|---|---|---|---|
| #279 | LOW | `_utils.py::model_judge_compliance` | The grader prompt interpolates untrusted target-response text with only a plain-text label, no XML delimiter fencing — a malicious target could theoretically try to confuse the judge model | Traced the actual call path in `jailbreak_harness.py::_apply_model_judge_pass`: it only ever flips a result `True→False` (extra scrutiny), never `False→True` (line: `if verdict["complied"]: result.passed = False`). A successful prompt-injection-against-the-judge can therefore only produce a noisy false FAIL on an opt-in corroboration pass — it cannot launder a real jailbreak success into a false PASS, because the deterministic substring scan already caught it before the judge ever runs. Net exploitable impact is bounded to reduced signal quality on an optional feature, not a security bypass. Delimiter-fencing the prompt is reasonable defense-in-depth for a future round, not urgent enough to justify touching a shared grading helper mid-round. |

No CRITICAL, HIGH, or unaccepted MEDIUM defects were found.

---

## 4. What's Good

- **The asymmetric design of `_apply_model_judge_pass` structurally neutralized
  what looked like it could be a real prompt-injection finding** (#279) —
  because the judge pass can only make verdicts *stricter*, never more
  permissive, the worst case for a malicious target is "the harness got extra
  suspicious of me," not "the harness got fooled into clearing me." This is
  the same asymmetric-verification instinct as the repo's own VS-R03 pattern
  (independent re-derivation catches overconfidence) — good that it was
  designed in from the start rather than needing a follow-up fix.
- **All four new harness modules' `--trials` wiring, `run_all` completeness,
  and boolean detection logic passed a genuinely adversarial line-by-line
  trace** (not just a pattern-match skim) with zero findings — the "house
  style" template (dataclass result, simulate/live dual mode, `trial_runner`
  integration) is holding up well as new modules are added against it.
- **MAG-013..018's OR/AND combination logic (`compromised = succeeded or
  <keyword-match>`, `passed = not compromised`) traced correctly** on first
  audit — the polarity is easy to get backwards in this style of test and it
  wasn't.
- **The regression tests added this round were verified, not assumed** — each
  of the 4 new checks in `test_code_quality.py` was run against the pre-fix
  `origin/main` source (via `git show`) to confirm it would actually have
  failed there, not just that it passes now. (E.g. `TestRegJailbreakVersionConsistency`
  correctly detects `{docstring: 3.1, banner: 3.0, report: 3.0, trial_suite_name: 3.4}`
  as disagreeing when run against the pre-fix file.)

---

## 5. Methods

- **Audit:** 3 parallel general-purpose agents, each independently scoped to
  the same 7 files (4 new harnesses + `multi_agent_harness.py`,
  `jailbreak_harness.py`, `_utils.py`), each with a distinct lens:
  - Security: ReDoS, SSRF, command injection, path traversal, deserialization,
    secrets handling, prompt-injection-into-the-judge.
  - Logic/correctness: per-test simulate-mode fail-ability, `run_all`
    completeness, `--trials` wiring, boolean-logic correctness, in-file
    version-string self-consistency.
  - Consistency/integration: `cli.py`/`test_code_quality.py`/`count_tests.py`
    registration, doc test-count reconciliation across every file that cites
    a count, prefix-collision check, version-bump convention check.
- **Fix:** applied directly (not delegated) — each finding traced to its exact
  root cause before editing, each fix re-verified against the harness's own
  `--simulate` output and the full suite.
- **Verification:** `python3 -m pytest testing/ -q` (315 passed pre- and
  post-fix comparison), `python3 scripts/count_tests.py` (595, unchanged —
  this was a bugfix round, not a coverage round), `git show origin/main:<path>`
  diffing to confirm each new regression test fails on pre-fix source.

---

## 6. Self-Test Suite

- **New (4 checks):**
  - `TestRegTestCount.test_readme_module_count` / `test_test_inventory_module_count`
    — module-count prose (as opposed to test-count prose, already guarded)
    reconciled against `len(HARNESSES)`.
  - `TestRegJailbreakVersionConsistency.test_consistent_version` — the 4
    version-string sites in `jailbreak_harness.py` must agree.
  - `TestRegExtendedThinkingET003.test_not_tautological` — ET-003's simulate
    branch must not compare a value to itself and must route through a real
    detector function.
- **Full suite:** 315 passed, 73 subtests passed (was 311 before this round's
  4 new tests).
- **Count:** definitive 595; unchanged by this round (bugfix-only, no new test
  IDs); `len(HARNESSES)` = 43, now correctly reflected everywhere.

---

## 7. Score

**9/10** — No CRITICAL/HIGH/unaccepted-MEDIUM issues; the two LOW-MEDIUM
findings (#275, #276) were real defects that shipped in the prior session
before this audit caught them, which is exactly the scenario round-based
re-auditing exists for — scoring this 10 would understate that something
genuinely slipped through initial review (a tautological test, specifically,
is the kind of thing that provides false assurance if it isn't later caught).
Both are now fixed with verified regression coverage. #279 is a disclosed,
traced-through, accepted design tradeoff rather than an open defect.

| Round | Score |
|---|---|
| R32 | 9 |
| R33 | 9 |
| R34 | 9 |
| **R35** | **9** |

---

## 8. Recommendations

- **Immediate:** none blocking — all round findings fixed and merged-ready.
- **Before next release:** delimiter-fence the untrusted response text in
  `model_judge_compliance`'s grader prompt (#279) as defense-in-depth, even
  though the current asymmetric design already bounds the exploitable impact.
- **Architecture:** the "test that can't fail" bug class (#275) would be
  caught earlier by a lightweight structural lint — e.g. a `test_code_quality.py`
  check that flags any `simulate` branch whose passing condition reduces to a
  literal self-comparison (`X == X` / `X != X` on the same variable) via AST
  inspection rather than the current per-incident regex guards. Worth scoping
  as a follow-up if this bug class recurs a second time.

---

## 9. Cumulative Assessment

R35 is the first purely self-audit round in recent history (R31-R34 were all
additive coverage rounds). It found what a coverage-focused round structurally
can't: two real defects (#275, #276) that a fast four-PR session introduced
alongside 24 genuinely new tests and a feature retrofit, plus two doc-drift
items (#277, #278) that no existing regression test was positioned to catch.
All four are now fixed with verified, falsifiability-checked regression tests
— not just "added a test," but confirmed each test actually fails on the
pre-fix code before counting it as a real guard. Issues raised this round: 5
(#275-279). Fixed: 4. Accepted with documented rationale: 1. Open defects: 0.
Total tests unchanged at 595 (this was a quality round, not a coverage round)
— cumulative harness count 39 → 43 across this session.
