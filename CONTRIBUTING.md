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

## How to contribute

1. **Open an issue first** — Describe what you want to add or change. For new scenarios, include the STRIDE category, OWASP Agentic mapping, and severity rationale.
2. **Fork and branch** — Create a feature branch from `main`.
3. **Follow existing patterns** — New scenarios should include:
   - Test method in `red_team_automation.py` with STRIDE/OWASP mapping
   - Entry in `ENHANCED-RED-BLUE-TEAM-TEST-PLAN.md` with full attack description
   - Blue team playbook in `BLUE-TEAM-PLAYBOOKS.md`
   - README mapping table update
4. **Submit a PR** — Reference the issue number. Include which OWASP ASI categories are covered.

## Code style

- Python: Follow existing patterns in `red_team_automation.py`. Type hints encouraged.
- Markdown: Follow existing document structure. Use tables for mappings.
- No secrets, credentials, or real endpoint URLs in commits.

## Security

If you discover a security vulnerability in the framework itself (not the test scenarios, which are intentionally adversarial), please report it privately via GitHub Security Advisories rather than opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under Apache License 2.0.
