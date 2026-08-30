# CRITICAL EVALUATION — Round 36

**Date:** 2026-08-30
**Round:** 36
**Reviewed commit:** `1814e95aec1e968300e7ef7db3aa9f2c5a20e629`
**Reviewed range:** `bfdc8cc04cb4894def5bc1b51f2bce75f34eeb3e..1814e95aec1e968300e7ef7db3aa9f2c5a20e629` (199 commits)
**Prior baseline:** R35 (2026-07-25) named a date and a PR list but no commit, so
its boundary had to be reconstructed. `bfdc8cc04cb4894def5bc1b51f2bce75f34eeb3e` is the last commit on or before
that date and is recorded here as the reconstructed lower bound. **From this
round on, every evaluation report pins both ends.**
**Test count:** 608 across 43 test-bearing modules (`scripts/count_tests.py`)
**Version:** 4.16.0 (released 2026-08-30, PyPI wheel + sdist)
**Evaluator:** Session round plus four independent I0 reviews from the Hermes
agent, pinned at `033a537`, `c593346`, `fbdad1b` and `bc9759c`

---

## 1. Why this header changed

An independent review could not determine a "since prior review" boundary,
because R35 identifies its scope by date and PR numbers rather than by commit.
Reconstructing it from dates is guesswork that gets more expensive every round.

Two lines fix it, and they are the first recommendation this round adopts:
**Reviewed commit** and **Reviewed range**. The next round inspects a bounded
delta from `1814e95aec1e968300e7ef7db3aa9f2c5a20e629` instead of re-deriving scope.

## 2. What changed

Twenty-five merged PRs, #417 through #441, all at 7/7 CI. The theme is one
issue, #351, and its generalisation.

| Area | Result |
|---|---|
| Dead-host false passes | 88 across ten modules, now 3, all declared local self-tests |
| Two new target poles | `permissive_host_sweep.py`, `refusing_host_sweep.py`, each with a pinned state file |
| Sweep discovery | class-name convention replaced by capability; 28 modules became 61 suites |
| Live calibration | first runs against a real MCP implementation, HTTP and stdio |
| Release | v4.16.0 shipped; `publish-pypi.yml` repaired |
| Machine interface | `--json` now emits exactly one document on stdout |

## 3. Prior fix verification

| Issue | Severity | Status | Evidence |
|---|---|---|---|
| #348/#350/#351 unserviced-request passes | CRITICAL | FIXED | `dead_host_sweep`: 3 of 500, all declared self-tests, 0 errors |
| `_serviced` non-2xx rule wrong for refusal-subject harnesses | HIGH | FIXED (10 modules) | `refusing_host_sweep`: 5 suites recognise a refusal where none did |
| `--json` stdout impurity | MEDIUM | FIXED | `test_json_stdout_purity.py`, subprocess, source-derived module list |
| MCP in-band `result.isError` idiom unrecognised | MEDIUM | FIXED | live reference server, MCP-002/008/018 |
| MCP-009 response claimed from elapsed time | MEDIUM | FIXED | `test_mcp_liveness_grounded_verdicts.py`, five branches |

## 4. New issues found this round

**None open.** Both MEDIUM findings raised by external review were closed in the
round that raised them (#432, #441).

The MCP-009 finding is worth recording in full because of how it survived. PR
#426 read all 27 permissive-sweep rows in `mcp_harness`, repaired 26, and kept
one deliberately, writing into the source that it was "the one row that is
CORRECT and stays" and citing it in `test_permissive_host_state.py` as the
taxonomy's example of a legitimate pass. It discarded the transport's return and
computed `passed = elapsed < 10.0`.

The first repair was then also wrong, in the opposite direction: it called a
server that ignores the batch and keeps serving "wedged", borrowing MCP-018's
wording where MCP-018 had earned it and this had not. That was caught by running
the new calibration job, not by review.

## 5. What is good

- Three target poles, each pinning measurements rather than asserting zero.
- `ran-no-verdicts` is a distinct sweep status; `mcp_harness` at the dead host
  is visibly unmeasured rather than a clean 0/0.
- Reference-server calibration retains classes: 16 PASS / 2 FAIL / 14
  INCONCLUSIVE, with the server version pinned.
- Public metadata reconciles across four surfaces at 608 / 43 / v4.16.0.

## 6. Methods

Behaviour-first. Three synthetic sentinels, then a real implementation over both
transports. Every claim in this report is reproducible from
`1814e95aec1e968300e7ef7db3aa9f2c5a20e629` with the scripts named above.

**The limit, stated plainly:** every defect the sentinels could not reach was
found by a live target or by source review. Three of them. Synthetic fixtures
encode the same assumptions as the harness that ships with them.

## 7. Self-test suite

`testing/` + `tests/`: 750 passed, 305 subtests. `ruff --select F821` clean.
`count_tests.py` 608. `verify_release_claims.py` 5 passed, 0 failed, 0 not
reproduced.

## 8. Score

**9/10.** No open MEDIUM or above. Not 10: two MEDIUMs reached `main` this round
and both were found by an external reviewer rather than by this repository's own
checks, one of them in a row this repository had explicitly examined and
defended.

## 9. Recommendations

1. Bounded, no-semantic-change lint cleanup, separate from verdict repairs.
2. Read the permissive and refusing backlogs one family at a time. They are
   reading lists, not defect counts.
3. Keep `mcp_harness`'s dead-host `0/0` visible as unmeasured; do not fabricate
   per-test failures to give the sweep a count.
4. A second real implementation, chosen for a different protocol idiom.

## 10. Cumulative assessment

#351 is closed for the dead-host pole and open as a reading list for the other
two. The instruments are in place and pinned; what remains is reading, and one
more real target.

None of this establishes that any agent, gateway, MCP server or payment endpoint
is secure. It establishes what this harness claims when it has nothing to go on.
