# VS-R04 Evidence Package — Receipt claim-level verification

- **Round:** VS-R04 (reports/round_26)
- **Date:** 2026-07-17
- **Module:** `protocol_tests/receipt_claim_harness.py` (RCL-001..008)
- **Artifact:** `vsr04-receipt-claim-evidence.json`
- **Method:** offline, stdlib-only (HMAC-SHA256 models the envelope signature and each authority's attestation). Deterministic; independently recomputable.

## The property demonstrated

A **format-valid, correctly signed receipt** can still be **claim-invalid**. For each negative vector the receipt's *envelope signature verifies*, yet the claim-level verifier rejects it on semantic grounds, each for its own distinct reason. This is the executable form of the four-property receipt decomposition: signing supports integrity/provenance only; occurrence, authorization, and check-integrity require attestations from distinct trust domains (checker, authorization, execution/settlement), not from the receipt emitter.

| Test | Negative vector | Envelope valid | Claim verdict |
|---|---|---|---|
| RCL-001 | Omitted mandatory evidence (no occurrence) | yes | reject: occurrence missing |
| RCL-002 | Substituted evidence, re-signed envelope | yes | reject: checker attestation does not verify |
| RCL-003 | Stale checker transcript | yes | reject: outside freshness window |
| RCL-004 | Check bound to the wrong tool-set digest | yes | reject: wrong input binding |
| RCL-005 | Authorization bound to different parameters | yes | reject: params mismatch |
| RCL-006 | Execution ack bound to another action | yes | reject: acknowledgment for another action |
| RCL-007 | Emitter self-assertion (no checker authority) | yes | reject: attested by emitter, not checker |
| RCL-008 | Fully-supported receipt (positive control) | yes | **accept** |

Result (generic): 8/8. Seven claim-invalid receipts rejected despite valid envelopes; one fully-supported receipt accepted.

## Family wiring (RCL-009..011): MCP-019 verdict → receipt `check` field

The loop from a real detector (MCP-019 composite poisoning) through the receipt `check` evidence to claim-level accept/reject:

| Test | Wired scenario | Claim verdict |
|---|---|---|
| RCL-009 | clean tool set, MCP-019 pass, honestly carried | **accept** |
| RCL-010 | ShareLock tool set, MCP-019 finds composite (fail) | reject (check output not a pass) |
| RCL-011 | passing MCP-019 attestation bound to the wrong (clean) tool set while the action uses the ShareLock set | reject (check bound to wrong tool-set digest) |

Result (wired): 3/3. A failing real check cannot be laundered into an authorizing receipt, and a passing check over the wrong tool set does not authorize a different action. Total 11/11.

## Reproduce

```bash
python3 -m protocol_tests.receipt_claim_harness --simulate
python3 -m unittest testing.test_receipt_claim
```

## Significance

This closes the gap the position note (Section 4/8) identified as its central missing experiment: it shows the claim-level verifier rejecting validly-signed-but-claim-invalid receipts, turning the four-property distinction from prose into executable evidence.
