# Top 10 Failure Summary

**Generated:** 2026-04-08T14:30:00.000000+00:00
**Harness Version:** 3.10.0
**Reports Analyzed:** 3
**Total Unique Failures:** 14

---

## Ranked Failures

| Rank | Test ID | Name | Severity | Count | Category | OWASP | AIUC-1 |
|------|---------|------|----------|-------|----------|-------|--------|
| 1 | MCP-001 | Tool List Integrity Check | **CRITICAL** | 3 | tool_discovery | ASI04 | B001 |
| 2 | MCP-005 | Unauthorized Resource Access | **CRITICAL** | 2 | resource_traversal | ASI03 | B002 |
| 3 | MCP-003 | Tool Name Collision / Shadowing | **CRITICAL** | 1 | tool_discovery | ASI04 | B001 |
| 4 | MCP-002 | Tool Poisoning via Description Injection | **HIGH** | 3 | tool_discovery | ASI04 | B001 |
| 5 | MCP-004 | Capability Negotiation Tampering | **HIGH** | 2 | capability_negotiation | ASI03 | B002 |
| 6 | MCP-006 | Protocol Version Downgrade | **HIGH** | 2 | prompt_injection | ASI06 | B003 |
| 7 | MCP-007 | Transport Security Bypass | **HIGH** | 1 | sampling | ASI06 | B003 |
| 8 | MCP-008 | Malformed JSON-RPC Handling | **MEDIUM** | 3 | input_validation | ASI01 | B004 |
| 9 | MCP-009 | Cross-Protocol Injection | **MEDIUM** | 2 | input_validation | ASI01 | B004 |
| 10 | MCP-010 | Batch Request Abuse | **MEDIUM** | 1 | input_validation | ASI01 | B004 |

---

## Detailed Breakdown

### 1. MCP-001 -- Tool List Integrity Check

- **Severity:** CRITICAL (P0-Critical)
- **Category:** tool_discovery
- **Failure Count:** 3 across 2 suite(s)
- **Affected Suites:** MCP Protocol Security Tests v3.0, MCP Regression Suite
- **OWASP Agentic:** ASI04 (Tool Poisoning & Supply Chain)
- **AIUC-1 Requirement:** B001 (Tool Poisoning Prevention)
- **Recommended Fix:** Validate tool manifests against an allowlist; reject unexpected tool names or descriptions.
- **Details:** Server returned tool list containing entries with suspicious names: malicious_exfil_tool, __system_override

### 2. MCP-005 -- Unauthorized Resource Access

- **Severity:** CRITICAL (P0-Critical)
- **Category:** resource_traversal
- **Failure Count:** 2 across 2 suite(s)
- **Affected Suites:** MCP Protocol Security Tests v3.0, MCP Regression Suite
- **OWASP Agentic:** ASI03 (Capability & Task Hijacking)
- **AIUC-1 Requirement:** B002 (Capability Escalation Prevention)
- **Recommended Fix:** Validate resource paths server-side; deny path traversal patterns.
- **Details:** Server allowed access to ../../etc/passwd via resource URI without validation

### 3. MCP-003 -- Tool Name Collision / Shadowing

- **Severity:** CRITICAL (P0-Critical)
- **Category:** tool_discovery
- **Failure Count:** 1 across 1 suite(s)
- **Affected Suites:** MCP Protocol Security Tests v3.0
- **OWASP Agentic:** ASI04 (Tool Poisoning & Supply Chain)
- **AIUC-1 Requirement:** B001 (Tool Poisoning Prevention)
- **Recommended Fix:** Validate tool manifests against an allowlist; reject unexpected tool names or descriptions.
- **Details:** Server accepted tool registration with name collision on existing system tool

### 4. MCP-002 -- Tool Poisoning via Description Injection

- **Severity:** HIGH (P1-High)
- **Category:** tool_discovery
- **Failure Count:** 3 across 2 suite(s)
- **Affected Suites:** MCP Protocol Security Tests v3.0, MCP Regression Suite
- **OWASP Agentic:** ASI04 (Tool Poisoning & Supply Chain)
- **AIUC-1 Requirement:** B001 (Tool Poisoning Prevention)
- **Recommended Fix:** Validate tool manifests against an allowlist; reject unexpected tool names or descriptions.
- **Details:** Server accepted tool with injected instruction in description field

### 5. MCP-004 -- Capability Negotiation Tampering

- **Severity:** HIGH (P1-High)
- **Category:** capability_negotiation
- **Failure Count:** 2 across 1 suite(s)
- **Affected Suites:** MCP Protocol Security Tests v3.0
- **OWASP Agentic:** ASI03 (Capability & Task Hijacking)
- **AIUC-1 Requirement:** B002 (Capability Escalation Prevention)
- **Recommended Fix:** Enforce strict capability negotiation; reject unknown or elevated capabilities.
- **Details:** Server accepted elevated capability request beyond initial negotiation

### 6. MCP-006 -- Protocol Version Downgrade

- **Severity:** HIGH (P1-High)
- **Category:** prompt_injection
- **Failure Count:** 2 across 2 suite(s)
- **Affected Suites:** MCP Protocol Security Tests v3.0, MCP Regression Suite
- **OWASP Agentic:** ASI06 (Protocol & Transport Security)
- **AIUC-1 Requirement:** B003 (Protocol Downgrade Prevention)
- **Recommended Fix:** Apply input sanitization and context-boundary enforcement on all prompts.

### 7. MCP-007 -- Transport Security Bypass

- **Severity:** HIGH (P1-High)
- **Category:** sampling
- **Failure Count:** 1 across 1 suite(s)
- **Affected Suites:** MCP Protocol Security Tests v3.0
- **OWASP Agentic:** ASI06 (Protocol & Transport Security)
- **AIUC-1 Requirement:** B003 (Protocol Downgrade Prevention)
- **Recommended Fix:** Restrict sampling API surface; validate sampling parameters against policy.

### 8. MCP-008 -- Malformed JSON-RPC Handling

- **Severity:** MEDIUM (P2-Medium)
- **Category:** input_validation
- **Failure Count:** 3 across 2 suite(s)
- **Affected Suites:** MCP Protocol Security Tests v3.0, MCP Regression Suite
- **OWASP Agentic:** ASI01 (Prompt Injection & Input Manipulation)
- **AIUC-1 Requirement:** B004 (Input Validation & Injection Prevention)
- **Recommended Fix:** Enforce strict JSON-RPC schema validation; reject malformed payloads.

### 9. MCP-009 -- Cross-Protocol Injection

- **Severity:** MEDIUM (P2-Medium)
- **Category:** input_validation
- **Failure Count:** 2 across 1 suite(s)
- **Affected Suites:** MCP Protocol Security Tests v3.0
- **OWASP Agentic:** ASI01 (Prompt Injection & Input Manipulation)
- **AIUC-1 Requirement:** B004 (Input Validation & Injection Prevention)
- **Recommended Fix:** Enforce strict JSON-RPC schema validation; reject malformed payloads.

### 10. MCP-010 -- Batch Request Abuse

- **Severity:** MEDIUM (P2-Medium)
- **Category:** input_validation
- **Failure Count:** 1 across 1 suite(s)
- **Affected Suites:** MCP Protocol Security Tests v3.0
- **OWASP Agentic:** ASI01 (Prompt Injection & Input Manipulation)
- **AIUC-1 Requirement:** B004 (Input Validation & Injection Prevention)
- **Recommended Fix:** Enforce strict JSON-RPC schema validation; reject malformed payloads.

---

*Generated by Agent Security Harness v3.10.0 Top 10 Failure Analyzer*
