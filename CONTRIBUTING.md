# Contributing

Thanks for your interest in improving the Red Team / Blue Team framework for agentic AI security.

## What we're looking for

### High priority (v3.0 roadmap)
- **MCP protocol-level test harness** — JSON-RPC 2.0 message generation, tool discovery validation, OAuth 2.1 flow testing
- **Google A2A test harness** — Agent Card validation, task lifecycle security, SSE stream testing
- **Framework adapters** — Pre-configured test profiles for LangChain, CrewAI, AutoGen, OpenAI Agents SDK, Bedrock Agents

### Always welcome
- New attack scenarios (especially from real-world incidents or security research)
- Blue team playbook improvements based on operational experience
- Grafana dashboard enhancements
- Bug fixes in the test automation suite
- Documentation improvements

## Before You Contribute

Please read:
- **[SECURITY_POLICY.md](SECURITY_POLICY.md)** - Threat model for contributions to a security testing framework
- **[CONTRIBUTION_REVIEW_CHECKLIST.md](CONTRIBUTION_REVIEW_CHECKLIST.md)** - Checklist that every PR must complete before merge

This is a security testing framework. A bug in our code creates false confidence in whoever runs it. We hold contributions to a higher standard than typical open-source projects.

## How to contribute

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

## Code style

- Python: Follow existing patterns in `red_team_automation.py`. Type hints encouraged.
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
