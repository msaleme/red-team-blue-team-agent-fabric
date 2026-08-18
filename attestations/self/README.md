# First attestation record

The first attestation record this project has ever produced. Its purpose is to test whether
the format survives contact with its own first use, per #384.

## What is here

| File | What it is |
|---|---|
| `2026-08-17-receipt-claim-report.json` | The attestation report: 11 `receipt-claim` results from a real run |
| `2026-08-17-receipt-claim-record.json` | The signed envelope v2 record built from that report |

- Suite: `receipt-claim`, 11/11 passed, including both positive controls (RCL-008, RCL-009).
- Target: offline fixture corpus. No network target, so no verdict here rests on an unserviced host.
- Harness version 4.15.0, repository commit `6a0277df768ae308dd1b0597ee83df1a50384866`.
- `verification_hash`: `e69e70f89fe32c48f5db83a49ecf43ea802a3b79f8d10d4a002bf78689f10674`

## What it establishes

**I0 and nothing more.** We ran our own harness against our own corpus and authored the oracle.
Per §1 of `docs/ATTESTATION-REGISTRY-SERVER-CONTRACT.md`, that is true regardless of how the
record is distributed. The signature proves the record was not altered. It proves nothing about
the target.

## Reproduce the verification

```bash
python3 scripts/verify_attestation_record.py attestations/self/2026-08-17-receipt-claim-record.json
```

Steps 1 to 4 of §9 pass: the hash matches the canonical payload bytes, the public key matches its
fingerprint, and the Ed25519 signature verifies. Step 5, key-to-identity binding, is out of scope
and the verifier says so. Step 6 prints the independence caveat.

## Known gaps this record exposes

Recorded in #384. In short: the record reports `independence_level 'unstated'` and
`system_under_test 'unstated'`, because the generator emits neither and the schema does not
carry them, while §1 of the contract requires every stored record to have both. It was also
produced without the shipped publish API, which cannot emit a record without a registry.
