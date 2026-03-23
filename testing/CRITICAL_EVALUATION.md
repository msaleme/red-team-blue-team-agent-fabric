# Critical Evaluation: Agent Security Harness v3.1.0

**Date:** 2026-03-22
**Evaluator:** Automated code review + structural analysis
**Repo:** github.com/msaleme/red-team-blue-team-agent-fabric

---

## Executive Summary

Agent Security Harness is an ambitious open-source security testing framework for multi-agent AI systems. It claims 189 tests across 9 harnesses covering MCP, A2A, L402, x402, enterprise platforms, and APT simulations. The framework demonstrates strong standards alignment and thoughtful security governance. However, several structural and design issues reduce its real-world effectiveness.

**Overall Assessment: Promising foundation with significant gaps that need addressing.**

---

## Strengths (What Works Well)

### 1. Zero-Dependency Core Design
The protocol harnesses use only Python stdlib (`urllib`, `json`, `http.client`). This is a genuine competitive advantage — it eliminates supply chain risk for the testing tool itself and makes installation trivial.

### 2. Threat Model for the Framework Itself
`SECURITY_POLICY.md` addresses attacks *on the testing framework* — poisoned test logic, false-pass injection, AI-generated code risks. This level of meta-security awareness is rare in open-source security tools.

### 3. Statistical Rigor
Wilson score CIs and bootstrap CIs for multi-trial evaluation, aligned to NIST AI 800-2. This is the right approach for non-deterministic AI systems where single-run results are unreliable.

### 4. Standards Mapping Depth
Complete OWASP ASI01-ASI10 coverage, NIST AI RMF mapping, STRIDE threat categorization per test, and NIST NCCoE identity alignment. This makes the framework audit-friendly.

### 5. Blue Team Playbooks
1,218 lines of incident response playbooks with TTD/TTC targets is genuinely useful for operationalizing findings.

---

## Critical Issues (Must Fix)

### Issue 1: x402 Harness Missing from CLI
**Severity: High**

`protocol_tests/x402_harness.py` exists (1,609 lines, 20 tests) but is **not registered in `cli.py`**. Users cannot run x402 tests via the `agent-security` CLI. This means 20 of the claimed 189 tests are inaccessible through the documented interface.

**Impact:** Inflated test count. Users trusting the README's "189 tests" claim get 169 via CLI.

### Issue 2: Pass/Fail Logic is Overly Simplistic
**Severity: Critical**

In `red_team_automation.py`, the pass condition is:
```python
passed = response.status_code in expected_status and ttd < self.ttd_target
```

This means:
- A server that returns 403 for *every* request (broken auth, not security) passes all tests
- A server that returns the right status code but leaks data in the response body still passes
- Response body content is captured but **never analyzed for pass/fail determination**

The protocol harnesses (MCP, A2A) do better — they inspect response content — but the legacy `red_team_automation.py` suite has this fundamental flaw.

### Issue 3: No Self-Tests / No CI Test Suite
**Severity: High**

The repo has **zero automated tests for its own code** (until this testing folder). The GitHub Actions workflow only publishes to PyPI — it doesn't run any validation. For a security testing framework, this is a significant credibility gap.

The `CASE_STUDY_FALSE_PASS.md` documents a real bug where AI-generated test code had:
- A loop variable that was never used (tests appeared to run but didn't)
- A category filter that broke test ID assignment

These bugs would have been caught by basic unit tests.

### Issue 4: Connection Errors Conflated with Security Findings
**Severity: Medium**

When a target endpoint is unreachable (`ConnectionError`), the test records `passed=False`. This is correct behavior (fail-safe), but the error reporting doesn't distinguish between:
- "Server properly blocked the attack" (security pass)
- "Server is down" (infrastructure issue)
- "Network timeout" (unrelated to security)

All three produce `passed=False` with different `error_message` values, but downstream reporting treats them identically.

### Issue 5: `datetime.utcnow()` Deprecation
**Severity: Low**

`red_team_automation.py` uses `datetime.utcnow()` (deprecated since Python 3.12). The protocol harnesses correctly use `datetime.now(timezone.utc)`. Inconsistency within the same project.

---

## Design Concerns (Should Address)

### Concern 1: Tests Are Not Actually Executable Without Targets
Every test requires a live endpoint. There are no mock servers, no Docker Compose targets, no example MCP servers to test against. A user who `pip install`s the package and runs `agent-security test mcp --url http://localhost:8080` will get 10/10 failures from connection errors — which looks identical to 10/10 security vulnerabilities found.

**Recommendation:** Ship a minimal compliant MCP server (even 50 lines of Python) so users can validate the harness works before pointing it at real targets.

### Concern 2: Enterprise Adapter Tests Are Speculative
The enterprise adapters (SAP, Salesforce, Workday, etc.) send pre-configured payloads to generic API paths. These are not protocol-level tests — they're HTTP request templates with security-themed payloads. Whether they actually test the *real* enterprise AI agent APIs depends entirely on the target having endpoints that match the assumed URL patterns.

The payloads are well-crafted, but calling them "enterprise platform security tests" overstates what they validate.

### Concern 3: No Rate Limiting or Throttling
Running 189 tests against a production endpoint at full speed could trigger WAF blocks, rate limiters, or even incident response. There's no `--delay` flag, no backoff logic, and no warning about this in the documentation.

### Concern 4: Report Output Validation
JSON reports are generated with `json.dump()` but never schema-validated. Response snippets from adversarial payloads are included in reports without sanitization. If reports are rendered in a web UI, this could create stored XSS vectors.

### Concern 5: `geopy` Dependency in Legacy Suite
`red_team_automation.py` imports `geopy.distance.geodesic` at the top level. This means `import red_team_automation` fails if `geopy` isn't installed, even though it's only used for one threat intel feature. Should be a lazy import.

---

## Test Count Verification

| Source | Claimed | Verified |
|--------|---------|----------|
| README "189 tests" | 189 | See breakdown below |
| red_team_automation.py | 30 | ~30 test methods found |
| MCP harness | 10 | 10 test methods |
| A2A harness | 12 | 12 test methods |
| L402 harness | 14 | 14 test methods |
| x402 harness | 20 | 20 test methods (NOT in CLI) |
| Framework adapters | 21 | ~21 test methods |
| Enterprise Tier 1 | 30 | ~30 test methods |
| Enterprise Tier 2 | 27 | ~27 test methods |
| GTG-1002 APT | 17 | ~17 test methods |
| Advanced attacks | 10 | 10 test methods |
| Identity harness | 18 | ~18 test methods |

**Approximate total:** ~209 test methods found (some files may have helper methods matching `test_` pattern). The 189 count appears to exclude `red_team_automation.py`'s 30 tests from the protocol-level count, which is reasonable but not clearly documented.

---

## Comparison to Alternatives

| Feature | This Tool | NVIDIA Garak | MS Counterfit | OWASP ZAP |
|---------|-----------|-------------|---------------|-----------|
| Agent protocol testing (MCP/A2A) | Yes | No | No | No |
| LLM prompt injection | Yes | Yes | Yes | No |
| Payment protocol security | Yes | No | No | No |
| Statistical evaluation | Yes (NIST) | Limited | No | No |
| Self-test suite | **No** | Yes | Yes | Yes |
| Bundled test targets | **No** | Yes | Yes | Yes |
| Zero dependencies | Yes (core) | No | No | No |

The niche — protocol-level testing for MCP/A2A/L402/x402 — is genuinely underserved. No other tool does this.

---

## Recommendations (Priority Ordered)

1. **Add the x402 harness to cli.py** — 5-minute fix, restores 20 missing tests
2. **Create a CI pipeline that runs the testing/ suite** — validates the framework itself
3. **Ship a minimal mock MCP server** — enables zero-config validation
4. **Fix pass/fail logic in red_team_automation.py** — inspect response body, not just status code
5. **Add `--delay` flag to CLI** — prevent WAF/rate-limit issues on real targets
6. **Distinguish connection errors from security findings** in reports
7. **Lazy-import `geopy`** to avoid hard dependency
8. **Replace `datetime.utcnow()`** with `datetime.now(timezone.utc)` in legacy code

---

## Conclusion

Agent Security Harness fills a real gap in the AI security tooling ecosystem. Protocol-level testing for MCP, A2A, and payment protocols doesn't exist elsewhere. The standards alignment is thorough, the governance model is mature, and the zero-dependency design is smart.

However, the framework's credibility is undermined by having no tests for itself, an incomplete CLI, and pass/fail logic that doesn't actually analyze response content in the legacy suite. The claimed "189 tests" is close to accurate but 20 of them aren't accessible via the CLI.

**Rating: 7/10 — Strong concept, solid protocol harnesses, needs execution refinement.**
