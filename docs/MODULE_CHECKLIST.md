# Module Checklist

Use this checklist when adding or reviewing a harness module to ensure consistency across the project.

## Required for every module

- [ ] **`--categories` support** - Module tests are filterable via `--categories` CLI flag
- [ ] **`--trials` support** - Module supports `--trials N` for statistical confidence intervals
- [ ] **`request_sent` populated** - Every `TestResult` / harness result includes `request_sent` with the actual payload sent
- [ ] **Canonical error IDs** - Error/test IDs use the canonical format (e.g., `MCP-001`, `CBRN-003`), not function names or ad-hoc strings
- [ ] **No unused imports** - Run `ruff check --select F401` or equivalent; remove dead imports
- [ ] **No bare `except:`** - All exception handlers catch specific types (at minimum `except Exception:`)
- [ ] **Test count matches claimed count** - The number of unique `test_id=` values in the module matches the count in README.md, CHANGELOG.md, pyproject.toml, and CLI output. Run `python scripts/count_tests.py` to verify.

## Recommended

- [ ] **Simulate mode** - Module works with `--simulate` (no live endpoint needed)
- [ ] **Timeout handling** - Network calls have explicit timeouts; `subprocess.run` uses `timeout=`
- [ ] **Deterministic test IDs** - Test IDs are stable across runs (no random suffixes)
- [ ] **Session isolation** - Multi-step tests (e.g., injection then follow-up) share a persistent `session_id` within the test, not a fresh one per call
- [ ] **Secure temp files** - Use `tempfile.mkstemp()` or `tempfile.NamedTemporaryFile()` instead of hardcoded `/tmp` paths
- [ ] **SSRF protection** - Any user-supplied URLs are validated against internal/private IP ranges before use

## How to verify

```bash
# Count tests per module
python scripts/count_tests.py

# Check for unused imports
ruff check --select F401 protocol_tests/

# Check for bare except
grep -rn "except:" protocol_tests/ --include="*.py" | grep -v "except.*:"

# Run the test suite
python -m pytest testing/ -v
```
