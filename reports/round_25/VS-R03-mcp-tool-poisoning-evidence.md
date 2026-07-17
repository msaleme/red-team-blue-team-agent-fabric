# VS-R03 Evidence Package — MCP composition + runtime tool poisoning, AP2 authority binding

- **Round:** VS-R03 (reports/round_25)
- **Date:** 2026-07-16
- **Scope:** MCP-019 (composition / ShareLock-class), MCP-020 (runtime identity / MSTI), AP2 mandate-chain authority binding (AP2-001..017)
- **Machine artifact:** `vsr03-mcp-tool-poisoning-evidence.json`
- **Method:** MCP cases run against fixed/sequenced transports; AP2 against the offline reference verifier (`simulate=True`). No network dependency; every verdict is independently recomputable.

## Why this round

The signed-evidence *format* for agent actions is converging fast, but a record being format-valid is not the same as its claim being true under an adversary. This round produces the evidence for that distinction across three surfaces, focusing on the cases a per-unit or signature-only check accepts while the artifact is jointly hostile.

## 1. Composition (MCP tool descriptions) — format-valid but hostile

The four tool descriptions carrying the ShareLock shares are each individually clean; the single-tool scanner passes them, the composite scanner reconstructs the payload.

| Check | Target | Verdict | Detail |
|---|---|---|---|
| MCP-014 (per-tool) | 4 ShareLock shares | PASS (sees nothing) | "No injection patterns detected in 4 tool descriptions" |
| MCP-019 (composite) | 4 ShareLock shares | FAIL (attack caught) | `['hidden_instruction', 'url']` surfaced only in aggregate, in no single description |
| MCP-019 (composite) | 3 benign tools | PASS (no false positive) | "No cross-tool reconstruction across 3 tool descriptions" |

## 2. Runtime identity (MCP mid-session rebinding)

| Check | Scenario | Verdict | Detail |
|---|---|---|---|
| MCP-020 | same-name swap, no origin binding | FAIL (attack caught) | 1 tool re-registered under a stable name, changed definition, no origin binding |
| MCP-020 | stable server (identical snapshots) | PASS | No unbound rebinding |
| MCP-020 | origin-bound legitimate update | PASS (no false positive) | change carries a persistent origin id; not flagged |

## 3. Payment authority binding (AP2 mandate chain)

The AP2 mandate-chain reference verifier rejected 17 of 17 adversarial mandates (each PASS = an attack correctly rejected): AP2-001 checkout-hash tamper, 002 stale/cross-session cart, 003 amount-cap escalation, 004 merchant allowlist, 005 SKU constraint, 006 unknown-constraint fail-closed, 007 mandate chain link, 008 open-mandate substitution, 009 agent-key forgery, 010 missing user signature, 011 payment replay, 012 expired mandate, 013 double-spend, 014 deterministic signature, 015 funding-instrument scope, 016 premature credential release, 017 vct exact-match.

## Reproduce

```bash
# MCP composition + runtime clusters
python3 -m unittest testing.test_vsr03_verdict_correctness.TestMCP019CompositePoisoning
python3 -m unittest testing.test_vsr03_verdict_correctness.TestMCP020MidSessionRebinding
# AP2 authority binding (offline reference verifier)
python3 -c "from protocol_tests.ap2_harness import AP2MandateTests; \
[print(r.test_id, r.passed) for r in AP2MandateTests(simulate=True).run_all()]"
```

## Use

This round is the empirical basis for the "red-team the receipt" adversarial-conformance methodology: a record's format being verifiable does not establish that its authorization and check-integrity claims hold under attack. Composition (MCP-019) and runtime (MCP-020) together cover the two tool-poisoning altitudes that single-tool inspection misses.
