# External attestation records

Records whose **system under test is someone else's system**, so the independence level is
stated relative to them rather than to this project.

## 2026-08-17 — VERITAS Omega, independent result recomputation

The first **I1** record this project has produced.

| | |
|---|---|
| System under test | `VrtxOmega/veritas-agent-trust-lab` public contract @ `0f3c71fd` |
| Track | `independent-result-recomputation` (Break VERITAS External Verification Challenge v1) |
| Evidence class | E2 |
| Independence level | **I1**, relative to VERITAS |
| Cases | 12 (6 CLEAN positive controls, 6 TAMPERED hostile) |
| `verification_hash` | `98961d7f8ace7a30eac1cafcc7e3dcc4e4b7d12e706e38910f8ad2b69425c778` |

I1 because the implementation was written from their **published contract**, not from their
code, per rule 2 of their challenge: `lib/trust-engine.js` was not imported, called, wrapped,
transpiled, or vendored. The reference engine was used only as a comparison oracle.

Source evidence and the implementation: [`conformance/external/veritas-omega/`](../../conformance/external/veritas-omega/).

## What it does not establish

**I1 is a claim this record states, not one it proves.** A reader must still confirm the
implementation separation independently; a signature cannot demonstrate that two implementations
were written apart. The verifier says so.

It also establishes nothing about the Agent Security Harness. The system under test here is
VERITAS. Citing this record as validation of our own work would invert the axis, which is the
error `docs/EVIDENCE-CLASS-TAXONOMY.md` exists to prevent.

## Verify

```bash
python3 scripts/verify_attestation_record.py \
  attestations/external/2026-08-17-veritas-recomputation-record.json
```
