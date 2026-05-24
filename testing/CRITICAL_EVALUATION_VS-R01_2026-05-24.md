# Critical Evaluation — VS-R01 (Vendor Surface Eval)

**Date:** 2026-05-24 (scaffolded; execution pending credentials)
**Evaluator:** Claude Opus 4.7 (Mike's harness — independent audit lineage)
**Version:** v4.4.2 (post v4.4.2 release tag, df3aaf9)
**Round type:** Vendor surface evaluation (distinct from internal-QA round lineage R29–R32). See scope at `~/vault/projects/harness-vs-r01-scope.md`.

---

## VS-R01 scope (recap)

Vendor surfaces under evaluation:

1. **Anthropic MCP Tunnels + Self-Hosted Sandboxes** — research preview / public beta announced 2026-05-19.
2. **AWS Bedrock AgentCore Payments** — preview, x402 + Coinbase/Stripe, announced 2026-04 / 2026-05.
3. **Salesforce Agent Scanners (public claim-matrix only)** — Mike's employment filter restricts this surface to documentation comparison; no execution.

Per scope-doc recommendation, **Surface 3 may be deferred to Round 24** if the claim-matrix carries any insider-knowledge risk by end of Day 1.

---

## Skeleton status (2026-05-24, end of day)

| Surface | Module(s) | LOC est. | Stubs | Status |
|---|---|---|---|---|
| Surface 1 (MCP Tunnels) | `protocol_tests/mcp_tunnel_harness.py` | ~400 | 4 | Skeleton scaffolded — TBD on agent return |
| Surface 1 (Sandboxes) | `protocol_tests/sandbox_isolation_harness.py` | ~300 | 3 | Skeleton scaffolded — TBD on agent return |
| Surface 2 (AgentCore Payments) | `protocol_tests/agentcore_payments_harness.py` | ~700 | 8 | Skeleton scaffolded — TBD on agent return |
| Surface 3 (Salesforce claim-matrix) | `docs/comparative_scanner_coverage_2026-05.md` | n/a | 1 artifact | Research-only — TBD on agent return |

All skeletons are skip-decorated with `awaiting VS-R01 credential provisioning`. None registered in `protocol_tests/cli.py` HARNESSES dict yet — registration deferred to execution-phase pass to avoid count drift.

---

## Credential provisioning state (2026-05-24)

| Need | State | Blocker |
|---|---|---|
| AWS CLI installed | MISSING | `aws not found` |
| AWS account + sandbox region (us-east-1 / us-west-2 / eu-central-1 / ap-southeast-2) | MISSING | No `~/.aws/credentials` |
| Stripe Privy testnet credentials OR Coinbase CDP testnet | MISSING | Not in env, no CLI |
| Modal account | MISSING | `modal not found` |
| Cloudflare account (wrangler) | MISSING | `wrangler not found` |
| Anthropic API key (for tunnel + sandbox stubs) | MISSING | No `ANTHROPIC_API_KEY` in env |
| MCP Tunnels research-preview access | NOT REQUESTED | Manual web form: https://platform.claude.com/docs/en/agents-and-tools/mcp-tunnels/overview |

All seven blockers are Mike-actions. See task #15.

---

## What Changed Since R32 (Internal-QA lineage)

VS-R01 is the **vendor-surface** lineage (new); the internal-audit lineage continues from R32 (2026-04-08, v3.9.0 dev) and is unaffected by VS-R01. v4.4.2 release (2026-05-24) was docs-only — no new internal-audit round needed.

---

## Issues Found (placeholder — populates during execution phase)

### Against the harness itself
*(none yet — execution pending)*

### Against vendor surfaces
*(none yet — execution pending; will follow responsible-disclosure window for any CRITICAL/HIGH findings)*

---

## Pre-execution sanity gates (run before tagging VS-R01 complete)

- [ ] All 3 new harness modules importable cleanly (no top-level live-API calls)
- [ ] Skip-decorators present on every test until creds provisioned
- [ ] Hard-coded testnet guards in place (`LIVE_NET_DISABLED = True`, `TESTNET_ONLY = True`, etc.)
- [ ] No imports of `boto3` / `anthropic` / `modal` at module-load time (gated behind try/except)
- [ ] No references to Salesforce-internal endpoints in any file
- [ ] `docs/comparative_scanner_coverage_2026-05.md` cites only public URLs (every `✓` traceable)
- [ ] Salesforce column claims only what's in the four cited public docs
- [ ] No individual Salesforce/MuleSoft engineers named anywhere
- [ ] No live execution attempted before scope-doc safety guards in place

## Post-execution registration gates (after credentials wire up + stubs run cleanly)

- [ ] Register new modules in `protocol_tests/cli.py:169` HARNESSES dict
- [ ] Add to `testing/test_code_quality.py` MODULES list
- [ ] Update README test count (470 → 470 + N where N = stubs that ran cleanly)
- [ ] Run `scripts/count_tests.py` to verify single source of truth
- [ ] Update `protocol_tests/version.py` if bumping
- [ ] Run full `pytest testing/` suite to catch registration drift

---

## Publishable artifact plan (per scope doc)

**Will publish (after Mike's review):**
- Moltbook post: VS-R01 coverage matrix
- dev.to summary: pattern-level commentary, no exploit chains
- arxiv update: append AgentCore Payments + MCP Tunnels rows to scanner-coverage preprint
- `docs/comparative_scanner_coverage_2026-05.md` (Surface 3 claim-matrix only)

**Will NOT publish:**
- Working exploit chains within 90 days of responsible-disclosure window
- Anything naming Salesforce / MuleSoft / Agentforce engineers, internal teams, or unreleased capability
- Raw Bazaar endpoint fingerprints that single out third-party x402 operators by name
- Tunnel-token replay artifacts that could be misread as 0-day against Anthropic infra

---

## Risk register

- **Authority-signal damage** from a single sloppy finding > value of any single test. Drop stubs from publishable artifact if not cleanly reproducible.
- **Live-net spend** — hard-coded testnet guards; environment-variable kill-switch.
- **ToS friction** with Coinbase Bazaar / Stripe Privy — passive scans rate-limited, no payment to listed endpoints.
- **Salesforce employment scrutiny** — Surface 3 is documentation-only; defer to Round 24 if any insider-knowledge risk surfaces during draft.
- **MCP Tunnels research-preview access** — may not arrive within the week; sandbox-only fallback (3/7 Surface-1 tests still run).
