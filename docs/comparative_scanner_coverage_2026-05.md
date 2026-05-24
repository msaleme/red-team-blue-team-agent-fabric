# Comparative Scanner Coverage — May 2026

*VS-R01 research artifact. Public claims only — no execution, no insider knowledge, no roadmap commentary.*

## Methodology

This matrix records what each public scanner or framework *claims to detect*, sourced from each vendor's own public documentation as of 2026-05-24. Cells cite a primary source URL only. Inclusion is not endorsement; exclusion is not a finding. The matrix is a starting reference for operators choosing between control-plane offerings, not a competitive benchmark — and it is built on the principle that absence of a public claim is absence of a public claim, never absence of capability.

Vendor control planes increasingly converge on the same shape: discover the agents, govern the handoffs, audit the decisions. The differentiator is not the slogan but the cell — what the vendor's own documentation explicitly says the scanner *detects*. This matrix is the cell-level read.

## Scope

**Included:**
- Salesforce / MuleSoft Agent Fabric — Agent Scanners, Agent Registry, Agent Broker, AI Gateway, MCP Bridge, Trusted Agent Identity (public announcement and product-page claims only)
- Anthropic Claude Managed Agents — MCP Tunnels and Self-Hosted Sandboxes security primitives
- AWS Bedrock Guardrails plus AWS AgentCore Payments (x402 path) governance claims
- OWASP Agentic Security Initiative (ASI) Top 10 for Agentic Applications 2026 — framework reference, not a scanner
- NIST NCCoE Concept Paper on Software and AI Agent Identity and Authorization (2026-02-05) — framework reference, not a scanner
- `agent-security-harness` (msaleme) — coverage as reported in `docs/TEST-INVENTORY.md`

**NOT included (out of scope by design):**
- Agent Fabric internals, roadmap, unreleased capability, or any non-public detection logic
- Any individual Salesforce, MuleSoft, Anthropic, AWS, OWASP, or NIST contributor by name
- Authenticated-tenant documentation (`*.my.salesforce.com`, customer-only knowledge bases)
- Anything attributed to a vendor without a primary URL in the source list below

## Coverage matrix

The matrix records *what each vendor's public documentation claims the scanner detects.* Cells use:
- `✓` plus short claim phrase plus URL ref — explicit detection claim found in the public doc
- `partial` plus short qualifier plus URL ref — adjacent or implied coverage, not an explicit claim
- blank (`–`) — no claim found in the public docs (absence of claim, not absence of capability)
- `out-of-scope` — the category does not apply to that vendor's product class

URL references in cells map to the numbered list under **Source URLs** below.

| Detection category | Salesforce / MuleSoft Agent Fabric | Anthropic Claude Managed Agents (MCP Tunnels / Sandboxes) | AWS Bedrock Guardrails + AgentCore Payments | OWASP ASI Top 10 (2026) | NIST NCCoE Agent Identity Concept Paper | agent-security-harness (msaleme) |
|---|---|---|---|---|---|---|
| Agent inventory / unknown-agent discovery | ✓ "automatically detects and catalogs AI agents across platforms like Copilot, Vertex AI, Bedrock, and Agentforce" [1][2][8] | – | – | partial — ASI10 Rogue Agents framing [5][6] | – | partial — enterprise platform adapters cover 20+ platforms but do not auto-discover [11] |
| MCP server / tool registration scanning | ✓ Agent Scanners "support for MCP servers arrives in May" and curated third-party MCP servers in Registry [2][8] | partial — MCP Tunnels gate which private MCP servers are reachable, not a scanner [3][4] | – | partial — ASI04 Agentic Supply Chain Compromise [5][6] | – | ✓ MCP-001/002 tool list integrity + registration via call injection [11] |
| MCP tool description injection (oversized / hidden payload) | – | – | – | ✓ ASI04 Agentic Supply Chain Compromise [5][6] | – | ✓ MCP-011/012/013 oversized + padding + repetition detection [11] |
| MCP protocol-version downgrade | – | – | – | partial — ASI03 Identity & Privilege Abuse adjacency [5][6] | – | ✓ MCP-004 protocol version downgrade attack [11] |
| MCP resource-URI path traversal | – | – | – | partial — ASI04 [5][6] | – | ✓ MCP-005 [11] |
| MCP prompt-template injection (Prompts/Get) | – | – | ✓ "Prompt Injection — User prompts designed to ignore and override instructions" (model-layer, not MCP-layer) [9] | ✓ ASI01 Agent Goal Hijack [5][6] | partial — RFI references "controls to prevent and mitigate prompt injection techniques" [7] | ✓ MCP-006 [11] |
| MCP sampling-request context exfiltration | – | – | partial — Sensitive Information Filters (PII / regex mask) [10] | partial — ASI02 Tool Misuse & Exploitation [5][6] | – | ✓ MCP-007 [11] |
| MCP tool-call argument injection | – | – | ✓ Prompt-attack filter on injected user content [9] | ✓ ASI02 Tool Misuse & Exploitation [5][6] | – | ✓ MCP-010 [11] |
| MCP batch-request / JSON-RPC DoS | – | – | – | partial — ASI08 Cascading Agent Failures [5][6] | – | ✓ MCP-008/009 [11] |
| Sandbox tool execution isolation | – | ✓ Self-Hosted Sandboxes — "tool execution to run on infrastructure controlled by the customer" [3][4] | partial — AgentCore execution runtime exists (not detailed in cited docs) | partial — ASI05 Unexpected Code Execution [5][6] | – | – |
| Private-network / outbound-only agent egress | – | ✓ MCP Tunnels — "outbound encrypted connection" without "inbound firewall rules" [3][4] | – | partial — ASI07 Insecure Inter-Agent Communication [5][6] | – | – |
| A2A inter-agent authentication / trust boundary | – | – | – | ✓ ASI07 Insecure Inter-Agent Communication [5][6] | partial — agent-to-agent identity scope of NCCoE concept paper [7] | ✓ A2A harness, 12 tests including capability-profile escalation [11] |
| Rogue agent registration | ✓ Agent Registry + GoDaddy ANS verification "to help ensure the agents you discover are legitimate" [2][8] | – | – | ✓ ASI10 Rogue Agents [5][6] | partial — non-human identity lifecycle scope [7] | ✓ STRIDE Spoofing — rogue agent registration [11] |
| Tool overreach / capability escalation | ✓ "an AI can only do things it is allowed to do, just like a human employee has limited access" [8] | – | – | ✓ ASI02 + ASI03 [5][6] | partial — authorization scope of NCCoE concept paper [7] | ✓ MCP-003 capability escalation + capability profile harness [11] |
| Tool-chain authorization bypass | partial — Trusted Agent Identity "mobile authorization for high-risk agent actions" [1][8] | – | – | ✓ ASI03 + ASI07 [5][6] | ✓ authorization controls — scope of NCCoE concept paper [7] | ✓ Identity & Authorization harness (18 tests, NIST NCCoE-mapped) [11] |
| Decision-gate violation / autonomy boundary | ✓ Agent Script + Agent Broker — "define hard rules for critical handoffs" with bounded LLM reasoning [1] | – | partial — AgentCore policy spending caps as decision gate [13] | partial — ASI01 + ASI09 framing [5][6] | – | ✓ Decision Governance layer + constitutional-agent integration [11] |
| Prompt injection (direct, user-supplied) | – | – | ✓ "Jailbreaks" + "Prompt Injection" filter, NONE/LOW/MEDIUM/HIGH threshold [9][10] | ✓ ASI01 Agent Goal Hijack [5][6] | partial — RFI scope [7] | ✓ Jailbreak harness 25 tests + Over-Refusal 25 tests (FPR) [11] |
| Prompt leakage / system-prompt extraction | – | – | ✓ "Prompt Leakage (Standard tier only)" [9] | partial — ASI01 framing [5][6] | – | partial — included in jailbreak / GTG-1002 corpus [11] |
| Memory & context poisoning | – | – | partial — Contextual Grounding Checks (hallucination relevance) [10] | ✓ ASI06 Memory & Context Poisoning [5][6] | – | ✓ Return-channel poisoning harness (8 tests) + cascade corruption RT-005 [11] |
| Sensitive-info / PII leakage | – | – | ✓ Sensitive Information Filters — "block or mask sensitive information" [10] | partial — ASI02 / ASI09 [5][6] | – | ✓ Information-disclosure tests + x402 X4-017/018 leaked-key checks [11] |
| Hallucination / contextual grounding | – | – | ✓ Contextual Grounding Checks + Automated Reasoning Checks [10] | – | – | partial — InfraGard-derived LLM hallucination injection [11] |
| Harmful content / CBRN filtering | – | – | ✓ Content Filters (hate, insults, sex, violence, misconduct) [10] | partial — ASI01 outcome framing [5][6] | – | ✓ Harmful Output (10) + CBRN Prevention (8) [11] |
| x402 spend-policy / per-agent cap | – | – | ✓ AgentCore "per-agent and per-session spending limits" [13] | partial — ASI03 [5][6] | – | ✓ x402 X4-011-013 spending-limit exploitation [11] |
| x402 recipient / payTo manipulation | – | – | – | partial — ASI02 [5][6] | – | ✓ x402 X4-004-006 recipient manipulation [11] |
| x402 facilitator trust | – | – | partial — managed wallet provisioning abstracts facilitator [13] | partial — ASI04 [5][6] | – | ✓ x402 X4-014-016 facilitator trust [11] |
| x402 session-token / wallet security | – | – | ✓ AgentCore — "secure, scoped wallets … Developers never handle private keys" [13] | partial — ASI03 [5][6] | – | ✓ x402 X4-007-010 session security [11] |
| x402 receipt / cross-chain confusion | – | – | – | partial — ASI04 [5][6] | – | ✓ x402 X4-019-020 cross-chain confusion [11] |
| L402 / Lightning payment harness | out-of-scope | out-of-scope | out-of-scope | partial — ASI04 [5][6] | out-of-scope | ✓ L402 harness, 33 tests [11] |
| Audit trail / decision logging | ✓ "auditable trail for every privileged operation" [1] | ✓ Self-Hosted Sandboxes — "better control over … audit logging" [3][4] | ✓ AgentCore "Every payment decision is logged alongside the agent's reasoning trace" [13]; Bedrock guardrail trace [9] | partial — ASI09 framing [5][6] | partial — "auditing, non-repudiation" feedback area in concept paper [7] | partial — Incident Response harness (8 tests, AIUC-1 E001-E003) [11] |
| Audit-trail intent drift / normalization of deviance | – | – | – | ✓ ASI10 Rogue Agents (behavioral drift) [5][6] | – | ✓ Normalization of Deviance (RT-024) + InfraGard deviance-drift [11] |
| Cascading multi-agent failure | – | – | – | ✓ ASI08 Cascading Agent Failures [5][6] | – | ✓ RT-005 cascade corruption + DoS tests [11] |
| Human-agent trust exploitation / social engineering | partial — Trusted Agent Identity mobile-approval interrupt [1][8] | – | – | ✓ ASI09 Human-Agent Trust Exploitation [5][6] | – | ✓ RT-018 social engineering, RT-019 priority inflation [11] |
| Supply-chain / fake-provenance attestation | partial — GoDaddy ANS legitimacy check [2][8] | – | – | ✓ ASI04 Agentic Supply Chain Compromise [5][6] | – | ✓ Provenance & Attestation harness, 15 tests [11] |
| CVE-2026-25253 reproduction (MCP marketplace) | – | – | – | partial — ASI04 reference [5][6] | – | ✓ CVE-2026-25253 reproduction harness, 8 tests [11] |
| GTG-1002 APT campaign simulation | – | – | – | partial — ASI01 + ASI08 [5][6] | – | ✓ GTG-1002 APT simulation, 17 tests [11] |
| Token usage / cost governance | ✓ AI Gateway — "manage token usage, enforce routing rules, or track spend" [1] | – | – | – | – | – |

## Categories included and how chosen

Each row in the matrix appears in at least one public document from at least one column. Categories were drawn from three sources, in this order:

1. **OWASP ASI 2026 Top 10** — the ten categories provide the framework taxonomy and most of the cross-vendor rows.
2. **Each vendor's own product page or announcement** — categories the vendor explicitly named (e.g., AWS prompt-attack filter tiers, Anthropic outbound-only egress, MuleSoft agent inventory) are added even when only that vendor names them.
3. **`docs/TEST-INVENTORY.md` from `agent-security-harness`** — the harness contributes wire-protocol granular rows (MCP-001 through MCP-013, x402 X4-001 through X4-020) that finer-grained framework taxonomies do not name at the category level.

A category was excluded only when it failed all three filters. The L402 row is retained and marked `out-of-scope` for non-payment vendors because Lightning-payment testing is the harness's coverage but explicitly not in scope for Bedrock or Agent Fabric.

## Source URLs

1. *Salesforce Advances Agent Fabric: New Guided Determinism and Governance Controls* — https://www.salesforce.com/news/stories/agent-fabric-control-plane-announcement/ *(direct WebFetch returned HTTP 403; primary claims verified via web search snippet from same canonical URL)*
2. *Salesforce Expands MuleSoft Agent Fabric with Automated Discovery* — https://www.salesforce.com/news/stories/mulesoft-agent-fabric-automated-agent-discovery/ *(direct WebFetch returned HTTP 403; primary claims verified via web search snippet from same canonical URL)*
3. *Anthropic Introduces MCP Tunnels for Private Agent Access to Internal Systems* — https://www.infoq.com/news/2026/05/claude-mcp-tunnels/
4. *Anthropic debuts MCP tunnels and self-hosted sandboxes* — https://thenewstack.io/anthropic-mcp-tunnels-sandboxes/ *(article body not retrievable via WebFetch; secondary corroboration via The Decoder and 9to5Mac coverage referenced in web search)*
5. *OWASP Top 10 for Agentic Applications for 2026* — https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
6. *OWASP Agentic Security Initiative* — https://genai.owasp.org/initiatives/agentic-security-initiative/
7. *NIST NCCoE Concept Paper — Accelerating the Adoption of Software and AI Agent Identity and Authorization* (2026-02-05) — https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd
8. *Salesforce Expands Agent Fabric as AI Agents Multiply (UC Today)* — https://www.uctoday.com/employee-engagement-recognition/salesforce-agent-fabric-expansion/
9. *Detect prompt attacks with Amazon Bedrock Guardrails* (AWS Docs) — https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-prompt-attack.html
10. *Amazon Bedrock Guardrails — product page* — https://aws.amazon.com/bedrock/guardrails/
11. *agent-security-harness — TEST-INVENTORY.md* — `docs/TEST-INVENTORY.md` in this repository
12. *Salesforce Stakes Out Multi-Vendor Agent Control Plane (Futurum Group)* — https://futurumgroup.com/insights/salesforce-stakes-out-multi-vendor-agent-control-plane-determinism-governance-enforcement-remains-the-test/ *(direct WebFetch returned HTTP 403; analyst position summarized from web search snippet)*
13. *x402 and Agentic Commerce — AWS Industries Blog* — https://aws.amazon.com/blogs/industries/x402-and-agentic-commerce-redefining-autonomous-payments-in-financial-services/
14. *MuleSoft debuts Agent Scanners (CIO)* — https://www.cio.com/article/4119814/mulesoft-debuts-agent-scanners-to-rein-in-enterprise-ai-chaos.html
15. *NIST AI Agent Standards Initiative* (umbrella page) — https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative

## Reviewer note for Mike

The hardest cells to verify were the Agent Fabric rows. Three of the four Salesforce-linked URLs in the input list (`salesforce.com/news/stories/*` and `futurumgroup.com/insights/*`) returned HTTP 403 to direct WebFetch and could only be read via web-search snippets pulling from the same canonical URLs. The matrix conservatively records only the claims that appeared in both the search snippet and a secondary source (UC Today, MuleSoft.com search snippet, CIO). The Agent Fabric column is deliberately sparse for that reason — and because the public docs themselves are deliberately product-narrative, not detection-spec.

The NIST column tracks the **NCCoE Concept Paper, 2026-02-05** — "Accelerating the Adoption of Software and AI Agent Identity and Authorization" — because that publication is specifically about agent identity and authorization, the scope of this matrix. The matrix also cites the umbrella NIST AI Agent Standards Initiative page.

A separate NIST publication, **NIST AI 800-2 IPD** (January 2026), "Practices for Automated Benchmark Evaluations of Language Models" (DOI [10.6028/NIST.AI.800-2.ipd](https://doi.org/10.6028/NIST.AI.800-2.ipd)), is the framework the harness aligns to for *statistical-reporting practices* — Wilson 95% CIs, multi-trial evaluation, result-management discipline. It is referenced 19+ times in the repo (`EVALUATION_PROTOCOL.md`, `protocol_tests/statistical.py`, CLI `--trials` help). It is **not** in this matrix because 800-2 governs benchmark methodology, not agent identity / authorization. The "NIST AI 800-2 aligned" claim in the repo's About description and SKILL.md is correct and well-supported.

**URLs that need follow-up before publish:**
- `salesforce.com/news/stories/agent-fabric-control-plane-announcement/` — 403 to WebFetch (verified via search snippet only)
- `salesforce.com/news/stories/mulesoft-agent-fabric-automated-agent-discovery/` — 403 to WebFetch (verified via search snippet only)
- `futurumgroup.com/insights/...` — 403 to WebFetch (verified via search snippet only)
- `thenewstack.io/anthropic-mcp-tunnels-sandboxes/` — page returned newsletter shell rather than article body (claims cross-checked against InfoQ [3])
- `nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization` — 403 to WebFetch (claims cross-checked against [7] CSRC concept-paper page)

The matrix would benefit from a second-source comparison on three rows where vendors publish thin claims:
1. **AgentCore execution sandboxing** — the x402 blog covers payment governance only; a separate AgentCore Runtime doc would tighten the "Sandbox tool execution isolation" row.
2. **MCP Tunnels payload-layer guarantees** — the InfoQ and TNS coverage describe transport and reachability, not payload-content detection; Anthropic's own product page (when accessible) should be the canonical source.
3. **Agent Scanners metadata schema** — the public claims describe *that* metadata is extracted but not *what schema* — a docs.mulesoft.com page would tighten every Salesforce row.

No vendor's column should be read as a coverage ceiling. Vendors document selectively for product marketing reasons. This matrix records what is *said in public*, not what each scanner is *capable of doing*.
