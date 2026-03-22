# Contribution Review Checklist

Every PR must complete this checklist before merge. Copy into the PR description and check each item.

---

## For All Contributions

- [ ] **Syntax and compilation** - Code compiles/parses without errors (`python3 -m py_compile`)
- [ ] **No new external dependencies** - Stdlib only unless explicitly approved
- [ ] **Consistent with existing patterns** - Follows the architecture of MCP/A2A/L402 harnesses (CLI flags, JSON output, test class structure)
- [ ] **Documentation** - Module docstring explains what the code does and how to use it
- [ ] **AI disclosure** - If AI-generated, commit message includes "AI-assisted" and code has been manually reviewed

## For New Tests or Test Modifications

- [ ] **Spec citation** - Each test cites the specific protocol spec section, CVE, or OWASP category it validates
- [ ] **Independent of test targets** - Test logic validated against the spec, not against a specific server's behavior
- [ ] **Pass AND fail verification** - Confirmed the test PASSES against compliant behavior AND FAILS against known-vulnerable behavior
- [ ] **No external input as trusted context** - If the test was suggested by a community member, the implementation was derived from the spec, not from their description of how it should work
- [ ] **Statistical mode compatible** - Test works correctly with `--trials N` (no state leakage between trials)

## For Test Endpoint Additions

- [ ] **Documented as community test targets** - NOT as reference implementations or ground truth
- [ ] **No credentials or secrets** - Endpoints don't require auth that would expose contributor credentials
- [ ] **Harness does not send real money/tokens** - Verified that no test path results in actual payment, transaction, or irreversible action
- [ ] **Conflict of interest disclosure** - If the contributor operates the endpoint being tested, this is noted in the PR

## For Security-Critical Code (pass/fail logic, result reporting, statistical evaluation)

- [ ] **Manual review required** - At least one human has read every line of the diff
- [ ] **No false-pass risk** - Reviewer has specifically checked for conditions where a test could report PASS when the target is actually vulnerable
- [ ] **Edge cases** - Tested with: empty responses, timeout, connection refused, malformed headers, unexpected status codes
- [ ] **Category filtering** - If test IDs are assigned, verified they remain correct when `--categories` filters are applied

## For Protocol Harness Additions (new protocol modules)

- [ ] **Protocol spec referenced** - README docstring cites the authoritative specification
- [ ] **CLI interface** - Supports `--url`, `--categories`, `--list`, `--trials N` at minimum
- [ ] **JSON output** - Report format matches existing harnesses (same keys, same structure)
- [ ] **Zero-cost testing** - The harness does not spend money, tokens, credits, or resources on the target system
- [ ] **Rate limiting awareness** - Tests include appropriate delays or document rate-limit considerations

---

## Reviewer Notes

When reviewing, ask yourself:
1. **If this test has a bug, would it produce a false PASS?** That's the worst failure mode.
2. **Could the contributor have a reason to want this test to behave differently?** Check for conflicts of interest.
3. **Does the test logic match the spec, or does it match "how the contributor's server works"?** These are not the same thing.
4. **If an AI agent wrote this, what would it have gotten wrong?** Common AI-generated bugs: loop variables unused, state not reset between iterations, off-by-one in index tracking, error handling that swallows failures silently.
