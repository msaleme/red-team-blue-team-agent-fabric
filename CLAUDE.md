# Agent Security Harness — Claude Code Instructions

## Project Overview

Security testing framework for AI agent systems. 611 tests across 44 test-bearing modules covering MCP, A2A, L402, x402, identity protocols, plus MCP server, telemetry, attestation registry, and community plugin system. (Canonical counts verified 2026-09-01 via `scripts/count_tests.py`. `cli.py` registers 45 commands; the extra one is `community_runner.py`, which hosts community-contributed tests and ships none of its own.)

## Testing Procedures

### Round-Based Evaluation

Each "round" follows this exact procedure:

1. **Pull latest** — `git fetch origin && git pull origin main`
2. **Baseline check** — `python3 scripts/count_tests.py` + `python3 -m pytest testing/ -v --tb=short`
3. **Verify prior fixes** — Confirm all issues from the previous round are resolved with exact line numbers and evidence
4. **Deep scan for new issues** — Use parallel agents for thorough audits:
   - Security: command injection, SSRF, path traversal, deserialization, ReDoS, YAML bombs
   - Logic: tests that can't fail/pass, off-by-one, race conditions, dead code
   - Consistency: test count drift, version mismatches, missing CLI registrations
   - Integration: new modules registered in cli.py, test_code_quality.py, README
5. **Write new tests** — Add tests to `testing/test_code_quality.py` that catch every issue found
6. **Run full suite** — Verify new tests pass (for regressions) or fail (for real issues)
7. **Write evaluation report** — Unique file per round

### Report Naming Convention

```
testing/CRITICAL_EVALUATION_R{round}_{YYYY-MM-DD}.md
```

Examples:
- `testing/CRITICAL_EVALUATION_R24_2026-03-30.md`
- `testing/CRITICAL_EVALUATION_R25_2026-03-31.md`

Reports are **never overwritten** — each round produces a new dated file. The generic `testing/CRITICAL_EVALUATION.md` may also be updated as a "latest" pointer.

### Report Structure

Each evaluation report contains these sections in order:

1. **Header** — Date, round number, test counts, version, evaluator
2. **What Changed** — Files added/modified, line counts, purpose
3. **Prior Fix Verification** — Table: issue number, severity, FIXED/NOT FIXED, evidence with line numbers
4. **New Issues Found** — Each with: issue number (sequential across all rounds), severity (CRITICAL/HIGH/MEDIUM/LOW), file:line, description, recommended fix
5. **What's Good** — Positive findings to acknowledge
6. **Methods** — Evaluation approach, files audited, tools used
7. **Self-Test Suite** — Test count, passing/failing, new tests added with descriptions
8. **Score** — 1-10 scale with historical table and trajectory chart
9. **Recommendations** — Prioritized: immediate, before next release, architecture
10. **Cumulative Assessment** — Total issues raised/fixed/open, trajectory

### Scoring Criteria

| Score | Criteria |
|-------|---------|
| 10/10 | Zero MEDIUM+ issues. All prior fixes intact. Tests all pass. |
| 9/10 | Only LOW issues. No regressions. |
| 8-9/10 | 1-3 MEDIUM issues. No HIGH/CRITICAL. |
| 7-8/10 | HIGH issues or 4+ MEDIUM issues. |
| <7/10 | CRITICAL issues or systemic problems. |

### Issue Severity Definitions

- **CRITICAL** — Remote code execution, credential exposure, data loss
- **HIGH** — Authentication bypass, supply chain risk, no sandboxing for untrusted input
- **MEDIUM** — SSRF, ReDoS, path traversal, info disclosure, stale counts in 10+ places
- **LOW** — Dead code, cosmetic, documentation inaccuracy, design discussions

## Issue Tracking

Issues are numbered sequentially across ALL rounds (currently at #140). Each issue includes:
- Unique number (never reused)
- Severity
- File and line number(s)
- Description
- Status: FIXED (with round number) / NOT FIXED / PARTIAL / DESIGN CHOICE

The test suite in `testing/test_code_quality.py` encodes key issues as executable regression checks. Failing tests indicate real unfixed issues, not test bugs.

## Key Files

| File | Purpose |
|------|---------|
| `testing/test_code_quality.py` | Main regression suite — guards all issue classes |
| `testing/test_trial_runner.py` | trial_runner.py unit tests |
| `testing/test_gtg1002_patterns.py` | GTG-1002 _leak()/_recon_info() pattern tests |
| `testing/test_autogen_harness.py` | AutoGen harness unit tests |
| `testing/test_statistical.py` | Wilson CI, bootstrap, statistical report tests |
| `testing/test_transport.py` | JSON-RPC structure tests |
| `scripts/count_tests.py` | Single source of truth for test count |
| `protocol_tests/trial_runner.py` | Shared multi-trial runner (test-ID matching) |
| `protocol_tests/version.py` | Centralized version lookup |

## Common Issue Patterns to Watch For

These recur across rounds — always check:

1. **Test count drift** — New tests added but count not updated in CLI, README, pyproject.toml, badge, MCP server. Use `count_tests.py` as source of truth.
2. **New module not registered** — Added to `protocol_tests/` but missing from cli.py HARNESSES, test_code_quality.py MODULES, README table.
3. **Dict-merge vulnerability** — `{"_status": x, **(json.loads(body)...)}` lets server overwrite internal keys. Safe pattern: parse first, then assign.
4. **--trials no-op** — Module accepts `--trials` but doesn't actually loop. Must use `trial_runner.run_with_trials()`.
5. **Hardcoded versions** — Scripts/docs reference specific version instead of using `version.py`.
6. **YAML/plugin safety** — community_runner.py loads untrusted YAML. Check: safe_load, no eval/exec, file size limits, delay caps, regex safety.
7. **A new harness must not define its own `_record`** — inherit
   `protocol_tests.harness_base.RecordingHarness`, or call `super()._record(result)`
   from an override. The package accumulated 45 result dataclasses and 44 parallel
   `_record` implementations, which is why one verdict defect had to be fixed four
   times (v4.13.1, #348, #350, #351): it had 44 homes and each repair reached only
   the files someone opened. `testing/test_harness_base_adoption.py` holds a
   grandfather list that may shrink and must never grow.
8. **Absence of a detected attack is not evidence a control held** — if the target
   never serviced the request, the verdict is INCONCLUSIVE, never a pass. Never write
   `passed = self._check_error(resp)` or `passed = not leaked` without establishing
   the target answered. Two status conventions exist (`_status` and `status`);
   `inconclusive_detail()` in `http_helpers.py` understands both so individual
   modules do not have to.

   **An exemption from that guard is not an exemption from the rule.** x402 and
   L402 are excluded from `_serviced` because a 402 IS the protocol servicing the
   request, and applying it would invert both modules. That is correct, and it
   was read as needing no instrument at all: against a closed port the two
   returned PASS on 44 of 54 and 4 of 33. There is no 402 from a host that is not
   running. Use `silence_detail()` where a non-2xx is a real answer -- it fires
   only when a test issued requests and not one was answered -- and
   `inconclusive_detail()` everywhere else. Never neither.

9. **A gap found in someone else's work is not permission to implement a test.**
   Adopted 2026-08-29 from a strategic review, after it caught a defect in tests
   written an hour earlier. Before adding a test family, require all six:

   ```text
   an observable target capability
   an adversarial precondition
   a deterministic oracle
   a positive control      (a target shape that must PASS)
   a negative control      (a target shape that must FAIL)
   PASS / FAIL / INCONCLUSIVE semantics for each
   ```

   The positive control is the one that gets skipped, and skipping it is how
   `X4-057` shipped returning PASS against a target with no delegated-allowance
   support at all: nothing accepted, nothing settled, so nothing overdrawn, so
   "the control held". That is item 8 one level up — not *the target never
   answered*, but *the target answered and has no such capability*. The serviced
   guard cannot catch it, because the answer was real. Write the truth table
   before the test; see `testing/test_x402_capability_controls.py`.

    **The closed port is one shape of the question.** `dead_host_sweep.py` asks
    what a harness claims when nothing answers; `permissive_host_sweep.py` asks
    what it claims when the target says yes to everything. The second is the
    harder pole and the one that matters against real endpoints, because the
    target answers and every serviced-request guard correctly stays out of the
    way. It found `AUTH-003` reporting "Elevated scope claims not honored"
    against a server returning `{"granted": true, "admin": true}` to a forged
    `admin:all` token. A non-zero row there is a reading list entry, not a
    defect: it may be correct by construction, may need a marker the fixture
    does not emit, or may be an inversion. Only reading the test separates them.

10. **The progress metric is the unclassified remainder, not the test count.**
    Every module that records a target response must end up guarded, reviewed,
    carrying a documented protocol-specific exception, or declared unsupported.
    The number to move is `len(UNREVIEWED)` in `testing/test_serviced_guard.py`.

    A rising test count is compatible with every verdict in the suite being
    unsound, and this repository has shipped a released version where that was
    partly true. Do not report coverage growth as progress while the remainder
    is non-empty.

## Docker

Docker is available. Ask to turn it on if not found.
