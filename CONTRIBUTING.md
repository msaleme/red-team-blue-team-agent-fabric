# Contributing

Thanks for your interest in improving the Red Team / Blue Team framework for agentic AI security.

> **New here?** Jump to [Contributing Attack Patterns](#contributing-attack-patterns) - you can submit your first pattern in under 5 minutes.

## Community Contributors

Shoutout to the people making this project better:

- **@DrCookies84** - Attack pattern contributions and testing
- **@alexmercer-ai** - Framework adapter improvements

Want to see your name here? Submit a PR!

---

## Contributing Attack Patterns

The fastest way to contribute is writing a YAML attack pattern. No Python required.

### 5-Minute Quick Start

1. Copy the template:
   ```bash
   cp community_modules/TEMPLATE.yaml community_modules/contrib/my_attack.yaml
   ```

2. Fill in the fields (it reads like a config file):
   ```yaml
   id: CP-0042
   name: My Cool Attack Pattern
   framework: mcp
   severity: high
   owasp_category: OWASP-AGENT-01
   
   attack_steps:
     - action: send_message
       target: agent
       payload:
         content: "Your attack payload here"
   
   assertions:
     - type: response_must_not_contain
       value: "sensitive_data"
   
   evidence_schema:
     request_sent: object
     response_received: object
   ```

3. Validate it:
   ```bash
   agent-security-harness validate --pattern community_modules/contrib/my_attack.yaml
   ```

4. Submit a PR (see [Submission Process](#submission-process) below).

### Full Documentation

- **[Plugin Specification](docs/PLUGIN_SPEC.md)** - Complete reference for all fields, action types, and assertion types
- **[Template](community_modules/TEMPLATE.yaml)** - Blank template with inline comments
- **[Example: CrewAI Role Escape](community_modules/examples/crewai_role_escape.yaml)** - Multi-step privilege escalation
- **[Example: MCP Description Exfil](community_modules/examples/mcp_description_exfil.yaml)** - CVE-2026-25253 reproduction

### What Makes a Good Attack Pattern?

- **Realistic** - Based on actual attack vectors, not theoretical ones
- **Documented** - Clear description of what is being tested and why
- **Assertive** - Specific assertions that unambiguously pass or fail
- **Mapped** - Tied to an OWASP Agentic category and severity level
- **Defensive** - Includes a `blue_team_mitigation` so defenders know what to do

### Submission Process

1. **Open an issue** describing your attack pattern. Include the framework, OWASP category, and a brief attack narrative.
2. **Fork the repo** and create a branch: `community/CP-XXXX-short-name`
3. **Add your YAML** to `community_modules/contrib/`
4. **Run validation**: `agent-security-harness validate --pattern your_file.yaml`
5. **Submit a PR** referencing the issue number

### ID Allocation

Pick the next available `CP-XXXX` number. Check existing patterns to avoid conflicts. If two PRs collide, the maintainers will reassign.

### Promotion to Core Modules

Community patterns that prove valuable get promoted to core harness tests:

1. Pattern runs cleanly for 3+ releases without issues
2. Pattern covers a real, documented attack vector (CVE, research paper, or incident report)
3. Pattern has been validated against at least one real framework deployment
4. A maintainer ports it to a Python harness test with full integration

Promoted patterns keep contributor attribution in the code and docs.

---

## What We're Looking For

### High priority (v4.0 roadmap)
- **MCP protocol-level test harness** - JSON-RPC 2.0 message generation, tool discovery validation, OAuth 2.1 flow testing
- **Google A2A test harness** - Agent Card validation, task lifecycle security, SSE stream testing
- **Framework adapters** - Pre-configured test profiles for LangChain, CrewAI, AutoGen, OpenAI Agents SDK, Bedrock Agents

### Always welcome
- New attack scenarios (especially from real-world incidents or security research)
- Community attack patterns (YAML format - see above)
- Blue team playbook improvements based on operational experience
- Grafana dashboard enhancements
- Bug fixes in the test automation suite
- Documentation improvements

## Before You Contribute

Please read:
- **[SECURITY_POLICY.md](SECURITY_POLICY.md)** - Threat model for contributions to a security testing framework
- **[CONTRIBUTION_REVIEW_CHECKLIST.md](CONTRIBUTION_REVIEW_CHECKLIST.md)** - Checklist that every PR must complete before merge

This is a security testing framework. A bug in our code creates false confidence in whoever runs it. We hold contributions to a higher standard than typical open-source projects.

## How to Contribute (Code)

1. **Open an issue first** - Describe what you want to add or change. For new scenarios, include the STRIDE category, OWASP Agentic mapping, and severity rationale.
2. **Fork and branch** - Create a feature branch from `main`.
3. **Follow existing patterns** - New scenarios should include:
   - Test method following the architecture in `protocol_tests/` (CLI flags, JSON output, test class structure)
   - Spec citation for each test (protocol RFC, OWASP category, or CVE)
   - Entry in the relevant test plan document
   - Blue team playbook if applicable
4. **Complete the review checklist** - Copy the checklist from [CONTRIBUTION_REVIEW_CHECKLIST.md](CONTRIBUTION_REVIEW_CHECKLIST.md) into your PR description and check each item.
5. **Submit a PR** - Reference the issue number. Include which OWASP ASI categories are covered.

### Conflict of Interest Disclosure

If you operate or maintain a system that the framework tests (e.g., you run an MCP server, L402 endpoint, or enterprise platform), disclose this in your PR. We welcome contributions from practitioners, but the review process accounts for potential conflicts between "make my server pass" and "make the test accurate."

## Code Style

- Python: Follow existing patterns in `protocol_tests/`. Type hints encouraged.
- YAML: Follow the [Plugin Specification](docs/PLUGIN_SPEC.md) for attack patterns.
- Markdown: Follow existing document structure. Use tables for mappings.
- No secrets, credentials, or real endpoint URLs in commits.

## Security

See [SECURITY_POLICY.md](SECURITY_POLICY.md) for the full security policy, including:
- Threat model for supply chain attacks on security testing tools
- AI-generated code policy
- Responsible disclosure process

If you discover a vulnerability in the framework itself, email research@cognitivethoughtengine.com. Do NOT open a public issue.

## License

By contributing, you agree that your contributions will be licensed under Apache License 2.0.
