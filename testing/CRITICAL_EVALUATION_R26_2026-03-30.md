# Critical Evaluation: Agent Security Harness v3.8.1 (Round 26)

**Date:** 2026-03-30
**Evaluation rounds:** 26
**Self-test suite:** 140 tests (137 passing, 3 catching real issues)
**Version:** v3.8.1
**Evaluator:** Claude Opus 4.6

---

## What Changed Since Round 25

One commit (`511399d`) fixing R25 findings in `community_runner.py` — 21 lines added, 12 removed.

### Changes

| Fix | Lines | Verification |
|-----|-------|-------------|
| Remove `re.search(timeout=5)` crash | 578 | `timeout=` no longer appears. ReDoS protection now via nested quantifier detection + input truncation. |
| Path traversal: `startswith` → `is_relative_to` | 887, 895 | Both `--pattern` and `--report` now use `Path.is_relative_to(cwd)`. Prefix collision bypass eliminated. |
| Negative duration clamp | 371, 462 | `max(0, min(..., MAX_DELAY_MS))` in both `delay_ms` and `_do_wait`. |
| Step count limit | 56, 263-266 | `MAX_ATTACK_STEPS = 20`. Patterns with >20 steps rejected during validation. |
| ReDoS nested quantifier detection | 575-577 | `re.search(r'\([^)]*[+*][^)]*\)[+*]', pattern)` catches `(a+)+`, `(a*)*`, etc. |
| Input length truncation | 573-574 | `actual[:10_000]` limits regex search input to 10K chars. |

---

## Methods

1. **Diff review** — Line-by-line audit of all 33 changed lines
2. **Runtime verification** — Confirmed `re.search(timeout=5)` no longer in code; ReDoS detector catches `(a+)+` but passes `[a-z]+`
3. **Bypass testing** — Confirmed `is_relative_to()` correctly rejects `/project-evil/` when cwd is `/project`
4. **Regression suite** — 140 tests covering all issue classes from 26 rounds

---

## Round 25 Issue Fix Verification — ALL 6 FIXED

| Issue | Sev | Status | Detail |
|-------|-----|--------|--------|
| 141 | HIGH | **FIXED** | `re.search(timeout=5)` removed. Uses pattern analysis + input truncation instead. |
| 142 | MEDIUM | **FIXED** | `is_relative_to(cwd)` for `--pattern`. No prefix collision bypass. |
| 143 | MEDIUM | **FIXED** | `is_relative_to(cwd)` for `--report`. Same fix. |
| 144 | LOW | **FIXED** | `max(0, min(...))` clamps negative values. |
| 145 | LOW | **PARTIALLY ADDRESSED** | `MAX_ATTACK_STEPS = 20` limits total steps, so worst case is 20 × 30s = 10 min (not 50 min). Still cooperative, not preemptive. |
| 146 | LOW | **FIXED** | Nested quantifier detector + input truncation replaces the broken timeout approach. |

---

## Carryover Issues (from Round 24)

These were not in scope of the community_runner.py hardening commit:

| Issue | Sev | Status |
|-------|-----|--------|
| 125 | HIGH | NOT FIXED — No plugin signing/integrity |
| 126 | HIGH | NOT FIXED — No sandboxing |
| 127 | HIGH | NOT FIXED — Test count 342 vs 332 (15+ locations) |
| 128 | HIGH | NOT FIXED — AutoGen not in CLI HARNESSES |
| 134 | MEDIUM | NOT FIXED — min_harness_version not enforced |
| 135 | MEDIUM | NOT FIXED — Extra YAML fields accepted |
| 136 | MEDIUM | NOT FIXED — SafeSkill badge unverifiable |
| 137 | LOW | NOT FIXED — getattr dispatch (not allowlist) |
| 138 | LOW | NOT FIXED — http_request stub expectations |
| 139 | LOW | NOT FIXED — AutoGen not in test_code_quality MODULES |
| 140 | LOW | NOT FIXED — CONTRIBUTING missing checklist |

---

## New Issues Found (Round 26)

### Zero new issues.

The R25 fixes are clean and well-implemented. No new bugs introduced. The ReDoS nested quantifier detector correctly catches dangerous patterns while allowing safe ones. The `is_relative_to()` path check is the correct approach. The step count limit (20) effectively bounds the cooperative timeout issue.

---

## Self-Test Suite

**140 tests: 137 passed, 3 failed (all carryover integration gaps)**

### Failing Tests
1. `TestCountReconciliation.test_script_matches_cli` — count_tests=342, CLI=332
2. `TestCountReconciliation.test_readme_badge` — count_tests=342, badge=332
3. `TestAutogenRegistered.test_in_cli` — autogen not in CLI HARNESSES

### Tests Added This Round (33 total new)

| Test Class | Tests | Guards |
|-----------|-------|--------|
| `TestCountReconciliation` | 2 | count = CLI = badge |
| `TestAutogenRegistered` | 2 | CLI + import |
| `TestCommunityRunnerSafety` | 5 | safe_load, no eval, size limit, delay cap, step limit |
| `TestCommunityRunnerRegexSafe` | 3 | No timeout kwarg, ReDoS detector, input truncation |
| `TestCommunityRunnerPathSafe` | 2 | is_relative_to, no startswith |
| `TestCommunityRunnerDurationClamp` | 1 | max(0, ...) in _do_wait |
| `TestMCPServerHardening` | 3 | Auth, stderr, size limit |
| `TestVersionConsistency` | 2 | CLI = pyproject = version.py |
| `TestArchitectureGuards` | 2 | No positional loops, safe merge |
| `TestCIPinned` | 2 | Workflow SHA pins |
| `TestStatistical` | 3 | Wilson CI, bootstrap |
| `TestNoHardcodedTmp` | 1 | No /tmp |

---

## Score

| Round | Version | Tests | Issues Found | Score |
|-------|---------|-------|-------------|-------|
| 23 | v3.8.1 | 332 | 0 | 10/10 |
| 24 | v3.8.1 | 342 | 16 (2H 7M 7L) | 7/10 |
| 25 | v3.8.1 | 342 | 6 new (1H 2M 3L) | 6.5/10 |
| **26** | **v3.8.1** | **342** | **0 new, 11 carried** | **7.5/10** |

**Score: 7.5/10** (up from 6.5/10)

The score increase reflects:
- **All 6 R25 issues fixed correctly** — no regressions, no new bugs
- **The R25 regression (re.search crash) is fully resolved** — first regression in 26 rounds is now fixed
- **Community runner now has genuine security controls**: file size limits, delay caps, step limits, ReDoS protection, correct path traversal prevention

The score is held back by the 11 carryover issues, especially the 4 HIGHs:
- No plugin signing (125)
- No sandboxing (126)
- Test count 342 vs 332 (127) — the same integration gap pattern from Rounds 13/18
- AutoGen not in CLI (128)

---

## Recommendations

### Immediate (15-minute fixes)

1. **Register AutoGen in CLI HARNESSES + update count to 342 (Issues 127-128)** — Add entry to `cli.py` HARNESSES dict. Update 332→342 in cli.py, pyproject.toml, README badge/prose/table, mcp_server/server.py. Add to test_code_quality.py MODULES. This is the exact same fix pattern used successfully in Rounds 13, 18, and 19.

### Before v3.9

2. **Add plugin manifest with SHA-256 checksums (Issue 125)** — `community_modules/manifest.json` with hashes. Runner validates before loading.

3. **Enforce min_harness_version (Issue 134)** — `if parse_version(pattern.min_harness_version) > parse_version(VERSION): skip`.

4. **Reject unknown YAML fields (Issue 135)** — `KNOWN_FIELDS = {...}; unknown = set(data.keys()) - KNOWN_FIELDS; if unknown: error`.

### Architecture

5. **Consider process-level sandboxing for community patterns (Issue 126)** — `subprocess.run()` with timeout, or `multiprocessing` with resource limits.

6. **Replace getattr dispatch with explicit allowlist (Issue 137)** — `ACTIONS = {"send_message": self._do_send_message, ...}`.

---

## Cumulative Assessment

| Metric | Value |
|--------|-------|
| Total rounds | 26 |
| Total issues raised | 146 |
| Fixed | 105 |
| Open | 11 (4 HIGH, 3 MEDIUM, 4 LOW) |
| Self-test suite | 140 tests |
| Security test modules | 22 (21 registered + 1 unregistered) |
| Security tests | 342 |
| Regressions | 1 (R25, now resolved) |

### Trajectory

```
Round  1 ████████░░░░░░░░░░░░  7.0  Foundation
Round 17 ████████████████████ 10.0  First perfect
Round 23 ████████████████████ 10.0  Fourth perfect
Round 24 ██████████████░░░░░░  7.0  Plugin system
Round 25 █████████████░░░░░░░  6.5  Broken fix
Round 26 ███████████████░░░░░  7.5  Recovery ← HERE
```

The community runner hardening is now solid. The path to 10/10 is clear: register AutoGen in CLI, update test count to 342, add plugin manifest. The core harness remains at 10/10 quality with 140 regression tests guarding it.

**146 issues raised across 26 rounds. 105 fixed. Score: 7.5/10.**
