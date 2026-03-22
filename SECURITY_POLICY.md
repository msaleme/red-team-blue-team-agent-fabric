# Security Policy

This project is a security testing framework. That makes it a high-value target for supply chain attacks, test logic manipulation, and reputation poisoning. We hold ourselves to a higher standard than typical open-source projects because a flaw in a security testing tool creates false confidence - worse than having no tool at all.

## Threat Model for This Project

### 1. Poisoned Test Endpoints

**Risk:** External contributors offer test endpoints that are designed to pass specific attack patterns a real server would fail. If we validate our harness against those endpoints, we bake in a false baseline.

**Policy:**
- External endpoints are **test targets**, never **validators**
- Harness logic must be validated against the protocol specification (RFC, OWASP, NIST), not against any specific server's behavior
- Each harness must include a reference to the authoritative spec it tests against
- When a contributor provides endpoints, document them as "community test targets" - not "reference implementations"

### 2. Suggested Test Logic That Misses Vulnerabilities

**Risk:** A contributor suggests changing test logic ("your macaroon check should verify X instead of Y") and the change happens to miss a real exploit. Taking security testing advice from people whose systems we test is a conflict of interest.

**Policy:**
- Every test modification must cite the specific spec section or CVE it validates against
- "It works against my server" is not a valid justification for changing test logic
- If a contributor's server fails a test, the default assumption is the server has a vulnerability, not that the test is wrong
- Changes to test pass/fail logic require review by a maintainer who did not write the change

### 3. Prompt Injection via Issues and Comments

**Risk:** If AI coding agents read GitHub issues or comments as task context, carefully crafted content could influence generated code. An issue titled "Add L402 tests" could embed instruction-like content that biases the agent's output.

**Policy:**
- Maintainers extract technical requirements from community input and write agent prompts independently
- Raw issue/comment text is never passed directly as trusted input to coding agents
- AI-generated code receives the same review scrutiny as human-contributed code (no "the AI wrote it so it's probably fine")

### 4. Reputation Poisoning via Subtle Flaws

**Risk:** A PR that looks correct gets merged, then a subtle flaw is discovered. The project's credibility takes the damage.

**Policy:**
- All PRs require at least one review pass (human or automated static analysis)
- Security-critical code (test pass/fail logic, result reporting, statistical evaluation) requires manual review
- The CONTRIBUTING.md checklist must be completed before merge

### 5. False Pass / Silent Failure

**Risk:** A test reports PASS when it should report FAIL. This is the most dangerous failure mode for a security testing framework because it creates false confidence.

**Policy:**
- Tests must be validated in both directions: confirm they PASS against compliant behavior AND FAIL against known-vulnerable behavior
- When possible, include a "known-bad" test case that deliberately triggers a failure to verify the test catches it
- Statistical mode (--trials N) with confidence intervals is preferred over single-run pass/fail for any test with non-deterministic elements

## Reporting Security Issues

If you find a vulnerability in the framework itself (not in a system being tested), please report it responsibly:

- Email: research@cognitivethoughtengine.com
- Subject: "[SECURITY] red-team-blue-team-agent-fabric: brief description"
- Do NOT open a public GitHub issue for vulnerabilities in the framework itself
- We will acknowledge within 48 hours and provide a remediation timeline

## AI-Generated Code Policy

This project uses AI coding agents (Claude Code, Codex) for development. AI-generated code is treated as untrusted first-draft output:

- All AI-generated code must pass automated static analysis before review
- AI-generated test logic must be manually verified against the relevant protocol specification
- The commit message must indicate when code was AI-generated (e.g., "AI-assisted" tag)
- AI agents must not consume raw external input (issues, comments, emails) as trusted prompt context
