# Receipt-claim conformance vectors (RCL)

Portable, machine-readable conformance vectors for **claim-level receipt verification**: each vector is a receipt whose **envelope signature verifies** but whose **claims are (in)valid on semantic grounds**. A conforming verifier must reach the recorded decision by recomputing evidence bindings, not by checking the signature.

These are generated from this repo's own claim-level verifier ([`protocol_tests/receipt_claim_harness.py`](../../protocol_tests/receipt_claim_harness.py), the RCL family), so `expected_result` and `harness_reason` are ground-truth verifier output rather than hand-authored expectations. Any receipt/trust-envelope implementation can run its own verifier over the same fixtures and compare.

## The model

An action receipt decomposes into four separately assessable properties, and signing supports only the first:

```
integrity/provenance | authorization | occurrence | check (execution + integrity)
```

Evidence for the last three must be attested by **distinct trust domains** (authorization authority, execution/settlement authority, independent checker authority), never by the receipt emitter, which the threat model permits to lie. The emitter can validly re-sign its own envelope; it cannot forge another authority's attestation (Ed25519, one keypair per domain, verifier holds only the public keys).

## Contents

**9 reject vectors + 2 acceptance controls.** The acceptance controls (`RCL-008`, `RCL-009`) exist so an implementation cannot pass by rejecting everything.

Each fixture carries an `evidence_binding` descriptor naming exactly what a verifier must recompute from referenced evidence, so a vector is not satisfiable with string-level checks: the admitted action digest, the action's tool-set digest, per-property attestor + independence flag, the check's `policy_digest`, and the freshness window.

| ID | Result | Phase | Recomputation the verifier must fail | Reason code |
|---|---|---|---|---|
| RCL-001 | reject | post-execution | occurrence evidence omitted | `OCCURRENCE_EVIDENCE_MISSING` |
| RCL-002 | reject | admission | check evidence tampered after attestation | `CHECK_EVIDENCE_TAMPERED` |
| RCL-003 | reject | admission | check transcript outside the freshness window | `CHECK_TRANSCRIPT_STALE` |
| RCL-004 | reject | admission | check `input_digest` != action tool-set digest | `CHECK_TOOLSET_DIGEST_MISMATCH` |
| RCL-005 | reject | admission | authorization bound to different params than requested | `AUTHORIZATION_PARAMS_MISMATCH` |
| RCL-006 | reject | post-execution | occurrence ack `action_digest` != admitted action | `OCCURRENCE_ACTION_LINKAGE_MISMATCH` |
| RCL-007 | reject | admission | check attested by the emitter, not an independent authority | `CHECK_ATTESTOR_NOT_INDEPENDENT` |
| RCL-008 | **accept** | admission+post-execution | control: all four properties independently supported | `ACCEPT_ALL_PROPERTIES_SUPPORTED` |
| RCL-009 | **accept** | admission | control: clean wired MCP-019 check, verdict pass | `ACCEPT_ALL_PROPERTIES_SUPPORTED` |
| RCL-010 | reject | admission | wired MCP-019 verdict is fail, carried honestly | `CHECK_OUTPUT_FAIL` |
| RCL-011 | reject | admission | passing check bound to a different tool set than the action uses | `CHECK_TOOLSET_DIGEST_MISMATCH` |

`RCL-005` and `RCL-006` are the phase pair: `RCL-005` fails at **admission** because the authorization evidence does not authorize the requested action before execution; `RCL-006` fails at **post-execution** because the execution acknowledgement does not link back to the admitted action. Same trust problem, different phase, different invariant.

`RCL-009/010/011` bind the **MCP-019 composite tool-poisoning** detector through the receipt path, so a receipt claiming "the admitted tool set was checked" is accepted only when a verifier can recompute that the check covered the same tool-set digest and that the verdict supports the claim.

## Files

- `fixtures/RCL-0NN.json` — one per case: the full receipt, the `evidence_binding` descriptor, the expected decision/phase/reason, and the verbatim `harness_reason`.
- `fixtures/index.json` — summary index.
- `generate.py` — regenerates the fixtures from the verifier.
- `verify_fixtures.py` — replays every fixture through the verifier and asserts the recorded result (exits non-zero on mismatch).

## Reproducibility

Deterministic Ed25519 test keys (fixed seeds) and a fixed timestamp make the fixtures reproducible byte-for-byte from the verifier. The signatures are the harness's own test-domain keys; the vectors' value is the **evidence-binding structure and the recomputation each verifier must perform**, which is signature-scheme independent, so the reason codes here map cleanly onto external receipt / trust-envelope models.
