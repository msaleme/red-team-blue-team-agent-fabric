# OWASP MCP Top 10 (2025): what this harness tests

**Result: 6 of 10 entries covered, 1 adjacent, 3 not covered.**

- **OWASP source:** the ten entry pages of [OWASP/www-project-mcp-top-10 at 165fe0f](https://github.com/OWASP/www-project-mcp-top-10/tree/165fe0f78ef104459237b4a8e0f6e78db9b02391/2025) (2025 edition), read 2026-11-07. The project describes itself as in "Phase 3 – Beta Release and Pilot Testing", so entries may change.
- **Harness source:** test IDs and their own docstrings on `main` at v4.30.0. `testing/test_owasp_mcp_mapping.py` fails if this page names a test ID the repository does not contain.
- **Verdict rules:** **covers** means a test's own description targets the entry's stated scope. **Adjacent** means the same class through a different mechanism. **Not covered** means no test. Every verdict is the repository author's reading (E1/I0), not an independent review.

## Mapping

| Entry | OWASP scope, in brief | Tests | Verdict |
|---|---|---|---|
| MCP01 Token Mismanagement and Secret Exposure | Hard-coded or long-lived tokens; secrets recalled through a prompt, scraped from debug logs, or extracted through poisoned context | MCP-007 | **Not covered.** MCP-007 (sampling hijack to exfiltrate context) is adjacent at most. Token *validation* tests belong to MCP07. |
| MCP02 Privilege Escalation via Scope Creep | Narrow or temporary permissions that expand over time | CVE-009, MCP-003 | **Covers** via CVE-009 (a shared-auth reconnect auto-approves scope upgrades). MCP-003 (a one-shot capability claim) is adjacent. |
| MCP03 Tool Poisoning | Schema poisoning, plus descriptor checks: imperatives, sensitive paths, hidden Unicode, comment-smuggled instructions | MCP-001, MCP-002, MCP-012, MCP-013, MCP-014, MCP-019, MCP-020, CVE-001, CVE-002, CVE-006 | **Covers** the descriptor checks. Remapping an operation to a destructive one is adjacent (MCP-020, mid-session identity rebinding). |
| MCP04 Software Supply Chain Attacks & Dependency Tampering | Trojanized or typo-squatted plugins, registry compromise, dependency confusion, build pipeline | MCP-F-001, MCP-F-002, MCP-F-003, MCP-F-004, CVE-005, CVE-007, CVE-008 | **Covers** |
| MCP05 Command Injection & Execution | Shell, script, API or SQL built from untrusted input | MCP-005, MCP-010, MCP-015, MCP-016, MCP-017, CVE-010 | **Covers** the direct path. A read-only SQL differential is tracked in #688. |
| MCP06 Intent Flow Subversion | Instructions in retrieved context override the user's goal | MCP-006, CVE-004 | **Adjacent.** These measure what a server puts into the context, not whether a model acts on it. (The OWASP overview titles this entry "Prompt Injection via Contextual Payloads".) |
| MCP07 Insufficient Authentication & Authorization | Missing token validation, replay, spoofed identity, inherited tokens | MCP-021, MCP-022, MCP-RC-001, MCP-RC-002, MCP-RC-003, MCP-RC-004, MCP-RC-005, MCP-RC-012 | **Covers** |
| MCP08 Lack of Audit and Telemetry | Agent actions, tool calls and data access not logged | MCP-RC-011 | **Not covered.** MCP-RC-011 (conflicting trace context rejected) is adjacent. |
| MCP09 Shadow MCP Servers | Unapproved deployments with default credentials or permissive configuration | none | **Not covered.** This is a deployment-inventory risk, which a harness pointed at one server is not built to observe. |
| MCP10 Context Injection & Over-Sharing | Cross-user or cross-agent leakage; multi-tenant bleed in a shared store | MEM-008, MEM-011, MEM-012, PCH-005, MCP-RC-006, MCP-RC-010 | **Covers**, through the memory and prompt-caching harnesses rather than the MCP modules. |

## Limits

- A covered entry means the harness has tests aimed at it. It does not mean every scenario OWASP lists is exercised, or that a target passing those tests is safe from the entry.
- MCP03, MCP06 and MCP10 are rooted in the model reading data as instructions. Tests can measure what reaches the context, and whether data crosses a principal boundary. They cannot measure whether a given model will follow it.
