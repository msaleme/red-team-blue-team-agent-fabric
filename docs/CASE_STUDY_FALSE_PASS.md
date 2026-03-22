# Case Study: AI-Generated Security Tests Produced False-Pass Results

**Date:** March 22, 2026
**Severity:** Medium (caught before deployment)
**CSG Mechanisms Validated:** HC-9 (no fabricated data), Design Principle 2.3 (external verification)

## What Happened

An AI coding agent (Claude Code) was tasked with building an L402 payment flow security harness (14 tests). The agent produced 1,242 lines of code that:
- Compiled without errors
- Passed syntax validation
- Produced clean CLI output
- Generated correctly formatted JSON reports

External automated review (Cursor Bugbot) identified two bugs:

### Bug 1: Loop Variable Never Used
In `test_l402_malformed_invoice`, the loop iterated over malformed invoice variants but never used the variant in the actual test. Every iteration tested the same input. **The test would report "all malformed invoices rejected" when it only tested one.**

### Bug 2: Category Filter Broke Test ID Assignment
When `--categories` filtered out some test categories, the test ID counter didn't advance past excluded tests. Subsequent tests received wrong IDs. **An auditor reading "L4-009 passed" would be looking at results from a different test entirely.**

## Why This Matters

Both bugs would produce **false-pass results** on security tests. This is the most dangerous failure mode for a security testing framework:
- The harness reports the target system is secure
- The operator trusts the report
- The target system is actually vulnerable
- The vulnerability goes undetected

## CSG Analysis

This is a live example of the WHO vs. HOW governance gap:

- **WHO governance says:** The agent was authorized to write code. It had valid credentials. It operated within its permission scope.
- **HOW governance asks:** Is the code correct? Does it test what it claims to test? Would a false-pass mislead users?

The agent self-reported success ("Done: Built L402 payment flow security harness"). Without external verification, this self-report would have been trusted.

## Mechanisms That Caught It

1. **External verification (Design Principle 2.3):** Cursor's static analysis acted as an independent check on the agent's output. The agent's self-report was not trusted.
2. **HC-9 applicability:** While the agent didn't intentionally fabricate data, the functional result was equivalent: a security report that looks correct but isn't.

## Outcome

Both bugs were fixed within 30 minutes. The incident was documented and motivated the creation of:
- `SECURITY_POLICY.md` - Threat model for contributions to security testing frameworks
- `CONTRIBUTION_REVIEW_CHECKLIST.md` - Per-PR verification checklist including false-pass checks
- AI-generated code policy requiring same review scrutiny as human contributions

## Lesson

An authorized agent, operating within its permissions, producing output that passes surface-level validation, can still be functionally wrong in ways that create real-world risk. Constitutional governance catches what identity governance cannot.
