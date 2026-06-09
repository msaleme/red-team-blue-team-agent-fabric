# Critical Evaluation: Agent Security Harness v3.8.1 (Round 24)

**Date:** 2026-03-30
**Evaluation rounds:** 24
**Self-test suite:** 134 tests (131 passing, 3 catching real issues)
**Version:** v3.8.1
**Evaluator:** Claude Opus 4.6

---

## What Changed Since Round 23

Three PRs merged: community plugin system (#94), AutoGen harness (#86), SafeSkill badge (#87). 2,393 lines across 9 files. This is the largest single feature addition in the project's history.

### New Files

| File | Lines | Purpose |
|------|-------|---------|
| `protocol_tests/community_runner.py` | 855 | YAML-based attack pattern runner with schema validation, step executor, assertion engine |
| `protocol_tests/autogen_harness.py` | 705 | Dedicated AutoGen security harness (10 tests, 3 categories) |
| `testing/test_autogen_harness.py` | 79 | AutoGen harness unit tests |
| `community_modules/TEMPLATE.yaml` | 121 | YAML attack pattern template |
| `community_modules/examples/crewai_role_escape.yaml` | 133 | CrewAI role escalation pattern |
| `community_modules/examples/mcp_description_exfil.yaml` | 152 | MCP tool description exfiltration pattern |
| `docs/PLUGIN_SPEC.md` | 243 | Plugin specification |
| `CONTRIBUTING.md` | +110 | Community contribution guidelines |

---

## Critical Findings

### Issue 125 — No plugin signing or integrity checking (HIGH)

**File:** `community_runner.py` — absent entirely

Zero integrity verification on community YAML files:
- No cryptographic signatures
- No hash verification
- No trust model
- `contributor` field is self-declared and unverified
- `discover_patterns()` auto-discovers and loads any `.yaml` in `community_modules/`
- A malicious PR adding a YAML file gets auto-executed on the next run

**This is a supply chain attack vector.** While the current step executor is simulation-only, the architecture is designed to be extended with real HTTP execution.

### Issue 126 — No sandboxing of plugin execution (HIGH)

**File:** `community_runner.py` — absent entirely

No process isolation, resource limits, network restrictions, or filesystem access restrictions. The runner executes in the same process with the same permissions as the calling user. Combined with ReDoS, YAML bombs, and unbounded delays, any DoS attack directly impacts the host.

### Issue 127 — Test count 342 but shows 332 in 15+ locations (HIGH)

**Files:** `cli.py`, `pyproject.toml`, `README.md` (10+ places), `mcp_server/server.py`, `scripts/free_scan.py`

Same class of issue as Round 13/18. The AutoGen harness added 10 tests (AG-*) bringing the total to 342, but the count was never updated anywhere. **New tests catch this.**

### Issue 128 — AutoGen harness not registered in CLI (HIGH)

**File:** `protocol_tests/cli.py:30-115`

`HARNESSES` dict has 21 entries, `autogen` is absent. `agent-security test autogen` fails. `agent-security list` doesn't show it. **New test catches this.**

### Issue 129 — ReDoS via YAML-controlled regex in `field_matches` (MEDIUM)

**File:** `community_runner.py:546`

`re.search(pattern, actual)` where `pattern` comes from YAML. A malicious YAML can supply a catastrophic backtracking regex like `(a+)+$` that hangs the process indefinitely. No timeout, no complexity limit, no use of `re2`.

### Issue 130 — YAML bomb (billion laughs) not protected (MEDIUM)

**File:** `community_runner.py:147`

`yaml.safe_load()` prevents code execution but not resource exhaustion. Anchor/alias expansion can cause exponential memory consumption. No file size limit before parsing.

### Issue 131 — `--pattern` accepts arbitrary filesystem paths (MEDIUM)

**File:** `community_runner.py:800`

No validation that the path is within `community_modules/`. A user can force parsing of any readable YAML file: `--pattern /etc/something.yaml`.

### Issue 132 — `--report` allows arbitrary file overwrite (MEDIUM)

**File:** `community_runner.py:845`

`open(args.report, "w")` writes to any path with no validation. `--report /home/user/.bashrc` would overwrite it with JSON.

### Issue 133 — Unbounded `delay_ms` in YAML steps (MEDIUM)

**File:** `community_runner.py:348-349`

`time.sleep(delay_ms / 1000.0)` where `delay_ms` comes from YAML. A pattern with `delay_ms: 999999999` blocks for 11.5 days.

### Issue 134 — `min_harness_version` parsed but never enforced (MEDIUM)

**File:** `community_runner.py:305`

The field is stored but never compared against the running harness version. A pattern requiring v99.0.0 runs anyway.

### Issue 135 — Extra YAML fields silently accepted (MEDIUM)

**File:** `community_runner.py:203-308`

Validation checks required fields but never rejects unknown ones. Arbitrary extra keys are stored in the pattern dict and available to future code that accesses them.

### Issue 136 — SafeSkill badge score unverifiable (MEDIUM)

**File:** `README.md:3`

Badge claims 85/100 but the linked URL (`safeskill.dev/scan/...`) does not display the actual scan result. The score cannot be independently verified.

### Issue 137 — `getattr`-based dispatch on YAML-controlled strings (LOW)

**Files:** `community_runner.py:351,462`

`getattr(self, f"_do_{action}")` where `action` comes from YAML. The `_do_` prefix provides namespace isolation, but an explicit allowlist dict would be safer against future method additions.

### Issue 138 — `http_request` stub sets dangerous expectations (LOW)

**Files:** `community_runner.py:428-435`, `docs/PLUGIN_SPEC.md:113`

The `http_request` action is a no-op simulation but docs describe it as "Send an arbitrary HTTP request." When connected to a real HTTP client, there's zero URL validation.

### Issue 139 — AutoGen harness not in test_code_quality.py MODULES (LOW)

**File:** `testing/test_code_quality.py:19-38`

Import test list doesn't include `protocol_tests.autogen_harness`.

### Issue 140 — CONTRIBUTING.md missing test count update checklist (LOW)

**File:** `CONTRIBUTING.md`

No mention that new harnesses require updating: cli.py, README, pyproject.toml, test_code_quality.py, count_tests.py MODULE_NAMES.

---

## What's Good

- **YAML uses `yaml.safe_load()`** — no arbitrary code execution via deserialization
- **No eval/exec/subprocess** — payloads are treated as inert data
- **No template substitution vulnerabilities** — no Jinja2 or format string injection
- **Schema validation exists** — required fields checked, types validated
- **AutoGen harness code quality is solid** — follows existing patterns, uses trial_runner
- **Example YAML patterns are well-crafted** — legitimate attack pattern descriptions

---

## Methods

### Evaluation Approach
1. **Automated regression suite** — 134 tests covering all issue classes from 24 rounds
2. **Static analysis** — Manual code review of all 2,393 new lines with security focus
3. **Parallel agent-based audits** — Two specialized agents: one for community_runner.py security, one for AutoGen integration
4. **Pattern matching** — Grep for dangerous patterns: `yaml.load(`, `eval(`, `exec(`, `subprocess`, `getattr`, `re.search` with untrusted input
5. **Cross-reference verification** — Test count reconciliation across CLI, README, pyproject.toml, badge, MCP server
6. **Threat modeling** — YAML supply chain, ReDoS, YAML bomb, SSRF, path traversal, file overwrite attack scenarios

### Files Audited
- `protocol_tests/community_runner.py` (855 lines) — full security audit
- `protocol_tests/autogen_harness.py` (705 lines) — security + integration audit
- `community_modules/TEMPLATE.yaml` (121 lines) — schema review
- `community_modules/examples/*.yaml` (285 lines) — pattern safety review
- `docs/PLUGIN_SPEC.md` (243 lines) — accuracy vs implementation
- `testing/test_autogen_harness.py` (79 lines) — coverage assessment
- `CONTRIBUTING.md` (+110 lines) — completeness review
- `README.md` (+2 lines) — consistency check

---

## Self-Test Suite

**134 tests: 131 passed, 3 failed (all catching real issues)**

### Failing Tests (intentional — catching real bugs)
1. `TestCountReconciliation.test_script_matches_cli` — count_tests=342, CLI=332
2. `TestCountReconciliation.test_readme_badge` — count_tests=342, badge=332
3. `TestAutogenHarnessRegistered.test_in_cli_harnesses` — autogen not in CLI

### New Tests Added This Round (26 tests)

| Test Class | Tests | Guards |
|-----------|-------|--------|
| `TestCountReconciliation` | 2 | count = CLI = badge |
| `TestCommunityRunnerYAMLSafety` | 2 | safe_load, no eval/exec |
| `TestCommunityRunnerReDoS` | 1 | Tracking ReDoS risk |
| `TestCommunityRunnerPathSafety` | 1 | Tracking path traversal |
| `TestAutogenHarnessRegistered` | 2 | CLI registration + import |
| `TestCommunityRunnerImportable` | 1 | Module import |
| `TestMCPServerHardening` | 3 | Auth, stderr, size limits |
| `TestVersionConsistency` | 2 | CLI = pyproject = version.py |
| `TestArchitectureGuards` | 2 | No positional loops, safe merge |
| `TestCIPinned` | 2 | Workflow SHA pins |
| `TestStatistical` | 3 | Wilson CI, bootstrap |
| `TestNoHardcodedTmp` | 1 | No /tmp |

---

## Score

| Round | Version | Tests | Issues | Score |
|-------|---------|-------|--------|-------|
| 1 | v3.1.0 | 189 | 5 | 7/10 |
| 8 | v3.2.0 | 274 | 0 | 9.5/10 |
| 17 | v3.7.0 | 330 | 3 LOW | 10/10 |
| 19 | v3.8.0 | 332 | 0 | 10/10 |
| 22 | v3.8.0 | 332 | 5 LOW | 10/10 |
| 23 | v3.8.1 | 332 | 0 | 10/10 |
| **24** | **v3.8.1** | **342** | **16 (2H 7M 7L)** | **7/10** |

**Score: 7/10** (down from 10/10)

This is the largest single-round score drop since the evaluation began. The community plugin system introduces significant security concerns:

- **2 HIGH issues**: No plugin signing and no sandboxing. These are architectural gaps, not code bugs — they require design decisions, not one-line fixes.
- **7 MEDIUM issues**: ReDoS, YAML bomb, path traversal, file overwrite, unbounded delays, version check bypass, silent extra fields.
- **4 integration gaps**: Test count stale (15+ locations), AutoGen not in CLI, not in import list, not in README.

The core harness (332 tests, 21 modules) remains at 10/10 quality. The score drop is entirely from the new community plugin system and incomplete AutoGen integration.

---

## Recommendations

### Immediate (before any community adoption)

1. **Register AutoGen harness in CLI (Issue 128)** — Add to `HARNESSES` dict, update count to 342 everywhere, add to README table, add to test_code_quality.py MODULES.

2. **Add YAML file size limit (Issue 130)** — Before `yaml.safe_load()`:
   ```python
   if file_path.stat().st_size > 1_000_000:  # 1MB
       raise ValueError("YAML file too large")
   ```

3. **Cap delay_ms (Issue 133)** — `delay_ms = min(delay_ms, 30_000)` (30 second max).

4. **Add ReDoS protection (Issue 129)** — Either limit pattern length (`if len(pattern) > 500: skip`) or use `re` with a timeout wrapper.

5. **Validate --report path (Issue 132)** — Restrict to current directory or `reports/` subdirectory.

### Before v3.9 Release

6. **Add plugin manifest with checksums (Issue 125)** — `community_modules/manifest.json` with SHA-256 hashes of approved YAML files. Runner validates hash before loading. This is the minimum viable trust model.

7. **Add resource limits (Issue 126)** — At minimum: overall execution timeout (`signal.alarm()` or `threading.Timer`), per-step timeout, memory soft limit.

8. **Enforce `min_harness_version` (Issue 134)** — Compare against `get_harness_version()`.

9. **Reject unknown YAML fields (Issue 135)** — Explicit allowlist of top-level and step-level keys.

10. **Add CONTRIBUTING checklist (Issue 140)** — Required integration steps when adding a new harness.

### Architecture

11. **Consider explicit action allowlist instead of getattr dispatch (Issue 137)** — `ACTIONS = {"send_message": _do_send_message, ...}` prevents future method-name collisions.

12. **Add URL validation to http_request stub NOW (Issue 138)** — Before anyone connects it to a real HTTP client.

---

## Cumulative Assessment

| Metric | Value |
|--------|-------|
| Total rounds | 24 |
| Total issues raised | 140 |
| Fixed | 99 |
| Open | 16 new (2 HIGH, 7 MEDIUM, 7 LOW) + 3 carried |
| Self-test suite | 134 tests |
| Security test modules | 22 (21 registered + 1 unregistered) |
| Security tests | 342 |
| Regressions | 0 (across 24 rounds) |

### Trajectory

```
Round  1 ████████░░░░░░░░░░░░  7.0  Foundation
Round  8 ███████████████████░  9.5  Stabilization
Round 17 ████████████████████ 10.0  First perfect
Round 20 ████████████████░░░░  8.0  MCP server raw
Round 22 ████████████████████ 10.0  Full surface perfect
Round 23 ████████████████████ 10.0  Fourth perfect
Round 24 ██████████████░░░░░░  7.0  Plugin system ← HERE
```

The pattern is familiar — Rounds 10, 18, and 20 all saw score drops when major new features were added, followed by rapid recovery. The community plugin system is architecturally sound but needs hardening before community adoption. The fix path is clear: signing, sandboxing, input limits, and integration completion.

**140 issues raised across 24 rounds. 99 fixed. 0 regressions. Score: 7/10 (core harness 10/10, plugin system needs hardening).**
