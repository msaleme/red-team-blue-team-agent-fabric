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
- `verification_hash`: `48235d1b77d097f37dd88cd5716e0bcf9a6829cf7acb113404cbbfd51bb9a5ff`

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

Recorded in #384. **The independence gap recorded here originally is now closed** by #386
(`2c7a9ec`, "a record states its own independence, inside the signature"). The signed payload
now carries `independence_level: I0` and
`system_under_test: agent-security-harness receipt-claim suite`, and
`protocol_tests/attestation.py` rejects an `independence_level` set without a
`system_under_test`, so the schema now requires the pair rather than omitting it. Running the
verifier prints both, read `from: signed payload`.

What remains open:

- **Key-to-identity binding.** The verifier says so itself: the checks prove *a holder of this
  key* signed this payload, not *whose* key it is. This is the blocker #384 names, and no
  amount of hosting closes it.
- **The publish path.** This record was produced without the shipped publish API
  (`protocol_tests/attestation_registry.py:publish_attestation`), which submits to a registry
  and returns a `registry_id`/`registry_url`. It still cannot emit a record without one.
