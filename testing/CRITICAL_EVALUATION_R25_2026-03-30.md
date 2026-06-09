# Critical Evaluation: Agent Security Harness v3.8.1 (Round 25)

**Date:** 2026-03-30
**Evaluation rounds:** 25
**Self-test suite:** 137 tests (132 passing, 5 catching real issues)
**Version:** v3.8.1
**Evaluator:** Claude Opus 4.6

---

## What Changed Since Round 24

One commit (`71386dc`) hardening `community_runner.py` — 67 lines added, 6 removed. Addresses Round 24 findings for the community plugin system.

### Changes in community_runner.py

| Change | Lines | Purpose |
|--------|-------|---------|
| `MAX_YAML_FILE_SIZE = 256KB` | 51 | YAML bomb protection |
| `MAX_DELAY_MS = 30_000` | 52 | Delay cap |
| `MAX_PATTERN_EXECUTION_TIMEOUT_S = 120` | 53 | Per-pattern timeout |
| `MAX_REGEX_LENGTH = 200` | 54 | ReDoS length limit |
| File size check before `yaml.safe_load()` | 155-159 | YAML bomb protection |
| `delay_ms = min(delay_ms, MAX_DELAY_MS)` | 363-365 | Delay cap |
| `_do_wait` duration cap | 456 | Delay cap |
| `re.search(pattern, actual, timeout=5)` | 567 | ReDoS timeout (BROKEN) |
| Regex length check | 563-565 | ReDoS length limit |
| Path traversal check for `--pattern` | 873-879 | Path restriction (BYPASSABLE) |
| Path traversal check for `--report` | 883-888 | Path restriction (BYPASSABLE) |
| Per-pattern execution timeout | 601-615 | Resource limit |

---

## Methods

### Evaluation Approach
1. **Automated regression suite** — 137 tests covering all issue classes from 25 rounds
2. **Static analysis** — Line-by-line review of all 67 changed lines
3. **Runtime verification** — Executed `re.search(timeout=5)` to confirm crash (Python 3.12.3)
4. **Bypass testing** — Confirmed path traversal bypass via `Path('/home/user/project-evil').startswith('/home/user/project')`
5. **Negative value testing** — Confirmed `time.sleep(-5.0)` raises ValueError via `_do_wait`
6. **Cross-reference** — Checked all 16 Round 24 issues against the diff

### Files Audited
- `protocol_tests/community_runner.py` — full diff review + surrounding context

---

## Round 24 Issue Fix Verification

### Fixed Effectively (3 of 16)

| Issue | Severity | Status | Detail |
|-------|----------|--------|--------|
| 130 | MEDIUM | **MOSTLY FIXED** | File size limit (256KB) before `yaml.safe_load()`. Minor TOCTOU race. |
| 133 | MEDIUM | **PARTIALLY FIXED** | `delay_ms` capped at 30s. But `_do_wait` allows negative values → ValueError crash. |
| + | — | **NEW** | Per-pattern execution timeout (120s) added — good but cooperative only. |

### Fix Attempted But Broken (3 of 16)

| Issue | Severity | Status | Detail |
|-------|----------|--------|--------|
| 129 | MEDIUM | **BROKEN** | `re.search(timeout=5)` does not exist in Python's `re` module — crashes with TypeError on every `field_matches` assertion. **New Issue 141 (HIGH).** |
| 131 | MEDIUM | **BYPASSABLE** | `str(path).startswith(str(cwd))` — `/project-evil/` passes when cwd is `/project`. Must use `Path.is_relative_to()`. **New Issue 142 (MEDIUM).** |
| 132 | MEDIUM | **BYPASSABLE** | Same `startswith` bypass as Issue 131. **New Issue 143 (MEDIUM).** |

### Not Addressed (12 of 16)

| Issue | Severity | Status |
|-------|----------|--------|
| 125 | HIGH | NOT FIXED — No plugin signing/integrity |
| 126 | HIGH | NOT FIXED — No sandboxing |
| 127 | HIGH | NOT FIXED — Test count 342 vs 332 in 15+ locations |
| 128 | HIGH | NOT FIXED — AutoGen not in CLI HARNESSES |
| 134 | MEDIUM | NOT FIXED — min_harness_version not enforced |
| 135 | MEDIUM | NOT FIXED — Extra YAML fields silently accepted |
| 136 | MEDIUM | NOT FIXED — SafeSkill badge unverifiable |
| 137 | LOW | NOT FIXED — getattr dispatch (not allowlist) |
| 138 | LOW | NOT FIXED — http_request stub sets dangerous expectations |
| 139 | LOW | NOT FIXED — AutoGen not in test_code_quality MODULES |
| 140 | LOW | NOT FIXED — CONTRIBUTING missing checklist |

---

## New Issues Introduced by This Commit

### Issue 141 — `re.search(timeout=5)` crashes with TypeError (HIGH)

**File:** `community_runner.py:567`

```python
if re.search(pattern, actual, timeout=5):
```

**Python's `re.search()` does not accept a `timeout` parameter.** This is not a version-specific feature — it has never existed in CPython's `re` module. On Python 3.12.3 (this system):

```
TypeError: search() got an unexpected keyword argument 'timeout'
```

This means **every `field_matches` assertion crashes** at runtime. The TypeError is caught by the generic `except Exception` in `evaluate()` (line 486), silently converting it to an assertion failure with an unhelpful error message. All community patterns using `field_matches` are now functionally broken.

**Fix:** Remove `timeout=5`. For ReDoS protection, either:
- Use `signal.alarm()` (Unix only) to interrupt long-running regexes
- Limit both pattern length AND input length
- Use the `regex` package which supports timeouts: `regex.search(pattern, actual, timeout=5)`

### Issue 142 — Path traversal check bypassable via prefix collision (MEDIUM)

**File:** `community_runner.py:878`

```python
if not (str(pattern_path).startswith(str(cwd))):
```

Confirmed bypass: if `cwd = /home/user/project`, then `/home/user/project-evil/malicious.yaml` passes because `"/home/user/project-evil/..."` starts with `"/home/user/project"`.

**Fix:** `if not pattern_path.is_relative_to(cwd):` (Python 3.9+)

### Issue 143 — Report path check has same bypass (MEDIUM)

**File:** `community_runner.py:887`

Same `startswith` pattern as Issue 142. Same bypass applies.

### Issue 144 — Negative `duration_ms` in `_do_wait` crashes (LOW)

**File:** `community_runner.py:456`

`min(payload.get("duration_ms", 0), MAX_DELAY_MS)` doesn't clamp to >= 0. `duration_ms: -1` → `time.sleep(-0.001)` → `ValueError`. Caught by generic handler but produces confusing output.

### Issue 145 — Execution timeout is cooperative, not preemptive (LOW)

**File:** `community_runner.py:601-615`

Timeout check runs only between steps. A single step can block for up to `MAX_DELAY_MS` (30s). With 100 steps, total time could be 100 * 30s = 50 minutes, far exceeding the 120s "timeout".

### Issue 146 — `MAX_REGEX_LENGTH=200` doesn't prevent ReDoS (LOW)

**File:** `community_runner.py:55`

The classic ReDoS pattern `(a+)+$` is 7 characters. Length limits don't correlate with regex complexity.

---

## Self-Test Suite

**137 tests: 132 passed, 5 failed (all catching real issues)**

### Failing Tests
1. `TestCountReconciliation.test_script_matches_cli` — count_tests=342, CLI=332
2. `TestCountReconciliation.test_readme_badge` — count_tests=342, badge=332
3. `TestAutogenRegistered.test_in_cli` — autogen not in CLI
4. `TestCommunityRunnerRegexSafety.test_no_invalid_timeout_kwarg` — `re.search(timeout=5)` found
5. `TestCommunityRunnerPathTraversal.test_no_startswith_path_check` — startswith bypass

### New Tests Added This Round (30 tests)

| Test Class | Tests | Guards |
|-----------|-------|--------|
| `TestCountReconciliation` | 2 | count = CLI = badge |
| `TestAutogenRegistered` | 2 | CLI + import |
| `TestCommunityRunnerYAMLSafety` | 4 | safe_load, no eval, size limit, delay cap |
| `TestCommunityRunnerRegexSafety` | 2 | No invalid timeout kwarg, proves crash |
| `TestCommunityRunnerPathTraversal` | 1 | No startswith path check |
| `TestMCPServerHardening` | 3 | Auth, stderr, size limit |
| `TestVersionConsistency` | 2 | CLI = pyproject = version.py |
| `TestArchitectureGuards` | 2 | No positional loops, safe merge |
| `TestCIPinned` | 2 | Workflow SHA pins |
| `TestStatistical` | 3 | Wilson CI, bootstrap |
| `TestNoHardcodedTmp` | 1 | No /tmp |

---

## Score

| Round | Version | Tests | Issues | Score |
|-------|---------|-------|--------|-------|
| 22 | v3.8.0 | 332 | 5 LOW | 10/10 |
| 23 | v3.8.1 | 332 | 0 | 10/10 |
| 24 | v3.8.1 | 342 | 16 (2H 7M 7L) | 7/10 |
| **25** | **v3.8.1** | **342** | **6 new + 12 carried = 18 (1H 2M 3L new; 4H 5M 3L carried)** | **6.5/10** |

**Score: 6.5/10** (down from 7/10)

The score decreased because:
- The hardening commit **introduced a new HIGH issue** (Issue 141: `re.search(timeout=5)` crash) — a fix that breaks functionality is worse than no fix
- Path traversal "fixes" are bypassable (textbook `startswith` anti-pattern)
- 12 of 16 original issues remain entirely unaddressed, including all 4 HIGHs
- Only 3 of 16 original issues were effectively fixed (YAML size limit, delay cap, execution timeout)

The core harness (332 original tests, 21 modules) remains at 10/10. The score reflects the community plugin system state.

---

## Recommendations

### Critical (fix before any use)

1. **Remove `timeout=5` from `re.search()` (Issue 141)** — This crashes on every Python version. Replace with:
   ```python
   if len(pattern) > MAX_REGEX_LENGTH:
       return False, "Regex too long"
   try:
       if re.search(pattern, actual[:10000]):  # Limit input length too
           return True, f"..."
   except re.error as e:
       return False, f"Invalid regex: {e}"
   ```

2. **Fix path checks to use `is_relative_to()` (Issues 142-143)**:
   ```python
   if not pattern_path.is_relative_to(cwd):
       print("ERROR: path must be within project directory")
       sys.exit(1)
   ```

3. **Clamp `duration_ms` to >= 0 (Issue 144)**:
   ```python
   duration_ms = max(0, min(payload.get("duration_ms", 0), MAX_DELAY_MS))
   ```

### High Priority (Round 24 carryover)

4. **Register AutoGen in CLI + update count to 342 (Issues 127-128)** — Add to HARNESSES, update all 15+ count references.

5. **Add plugin manifest with SHA-256 checksums (Issue 125)** — Minimum viable integrity model.

6. **Add resource limits / sandboxing (Issue 126)** — At minimum: `signal.alarm()` for preemptive timeout.

7. **Enforce `min_harness_version` (Issue 134)** — Compare against `get_harness_version()`.

---

## Cumulative Assessment

| Metric | Value |
|--------|-------|
| Total rounds | 25 |
| Total issues raised | 146 |
| Fixed | 99 |
| Open | 18 active (5 HIGH, 7 MEDIUM, 6 LOW) |
| Self-test suite | 137 tests |
| Security test modules | 22 (21 registered + 1 unregistered) |
| Security tests | 342 |
| Regressions | 1 (Issue 141: re.search crash introduced by hardening commit) |

### Trajectory

```
Round  1 ████████░░░░░░░░░░░░  7.0  Foundation
Round 17 ████████████████████ 10.0  First perfect
Round 23 ████████████████████ 10.0  Fourth perfect
Round 24 ██████████████░░░░░░  7.0  Plugin system
Round 25 █████████████░░░░░░░  6.5  Broken fix ← HERE
```

This is the first round where a fix commit introduced a regression. The `re.search(timeout=5)` crash (Issue 141) means every `field_matches` assertion in the community runner is now broken. The path to recovery is clear — remove the invalid `timeout` parameter, switch to `is_relative_to()`, and address the 4 HIGH carryover issues.

**146 issues raised across 25 rounds. 99 fixed. 1 regression. Score: 6.5/10.**
