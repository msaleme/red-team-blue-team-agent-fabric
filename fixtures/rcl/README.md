# RCL oracle fixtures

Eleven receipt-claim vectors as portable data, for running an independent
verifier against. Generated from `protocol_tests/receipt_claim_harness.py`.

```bash
python -m protocol_tests.rcl_fixture_export          # regenerate in place
python -m protocol_tests.rcl_fixture_export --stdout # print
```

## What these test

A receipt asserts several different things at once. This set separates them
into four **claim families**, so a verifier can be checked on each
independently:

| Family | The claim | Established by |
|---|---|---|
| `integrity_provenance` | the artifact has not changed since signing | envelope signature, action digest |
| `occurrence` | the action actually happened | execution/settlement authority attestation |
| `authorization` | the action was permitted, with these exact parameters | authorization authority attestation |
| `check_execution` | the claimed control ran, and passed, over this action's inputs | independent checker attestation |

**Every fixture's envelope signature verifies.** That is the point of the
set: signature validity establishes that the artifact has not changed since
it was signed. It does not establish that the action occurred, was
authorized, or passed the control it claims to have passed.

## How to use it

For each entry, run your verifier over `receipt` and compare with
`expected.verdict`.

```python
import json
data = json.load(open("fixtures/rcl/rcl-oracle-fixtures.v1.json"))
for f in data["fixtures"]:
    got = my_verifier(f["receipt"])           # "accept" | "reject"
    assert got == f["expected"]["verdict"], f["id"]
```

`expected.claim_family` names which property failed, so a partial
implementation can score itself per family rather than pass/fail overall.

**Keep the accept cases.** The set is **9 reject and 2 accept**, not eleven
negatives. A verifier that rejects all eleven has not demonstrated correct
claim validation, it has demonstrated that it rejects things. `RCL-008` and
`RCL-009` are what make the other nine mean something.

## Schema

Top level:

| Field | Meaning |
|---|---|
| `schema_version` | `"1.0"` |
| `evaluation_time` | Unix seconds the fixtures were built at. Freshness cases are relative to this, so pass it to your verifier as "now" |
| `freshness_window_seconds` | how long a checker transcript stays fresh |
| `signature_algorithm` | Ed25519 (RFC 8032) over **sorted compact JSON**, not JCS. The signing payload is `json.dumps(obj, sort_keys=True, separators=(",", ":"))` encoded UTF-8. It coincides with JCS (RFC 8785) for the ASCII-only, integer-valued payloads in this corpus, but diverges on number canonicalisation and non-ASCII escaping. Verify with the encoding named in the field, not with JCS |
| `public_keys` | hex Ed25519 public keys per authority: `emitter`, `checker`, `authz`, `exec`. Enough to verify every signature in the file. No private material is exported |
| `key_material` | states plainly that these are test authorities, not trust anchors |
| `claim_families` | the four families above |
| `counts` | `{total, accept, reject}` |
| `coverage_gaps` | families the verifier enforces that no vector currently exercises |
| `scope` | see below |

Each fixture:

| Field | Meaning |
|---|---|
| `id` | `RCL-001` … `RCL-011` |
| `name` | one-line description |
| `envelope_valid` | always `true` |
| `receipt` | the receipt, as data |
| `expected.verdict` | `accept` or `reject` |
| `expected.claim_family` | family that failed; `null` for an accept |
| `expected.reason` | the reference verifier's reason string |

## Expected values are executed, not asserted

Every `expected` block is produced by running `ClaimLevelVerifier` over the
built receipt at export time. Nothing hand-writes a verdict or a family;
`claim_family` comes from the verifier's own rejection-reason prefix.

This matters because a hand-assigned expectation is a label, not a result.
This project published an audit about exactly that failure in a different
corpus, where a hand-assigned boolean was inverted and reported as a
measurement (`benchmarks/CHANGELOG.md`).

Output is byte-stable: keys are derived from fixed seeds and
`evaluation_time` is pinned, so regenerating produces an identical file and
any diff is a real behavioural change. Enforced by
`tests/test_rcl_fixture_export.py`, which also verifies every signature
using only the public keys in the file.

## Known coverage gap

`integrity_provenance` is enforced by the verifier but **no current vector
exercises it** — every vector is envelope-valid by construction, which is
the property the set was built to isolate. So these fixtures do not test a
verifier's integrity checking. Declared in `coverage_gaps` rather than left
for a reader to discover.

## The keys are not secrets, and not trust anchors

Only public keys are exported, and a test asserts no seed material is present.
The matching private seeds are derived in the open as
`sha256("agent-security-harness/receipt-authority/" + name)`, so anyone can
recompute them. That is deliberate: it keeps the fixtures reproducible.

It also means these keys authenticate **nothing outside this fixture set**.
They sign fictional authorities. Do not wire them into anything.

A secret scanner will flag the public keys as high-entropy strings.
`.gitguardian.yaml` records why that is a false positive rather than
suppressing it silently.

## Scope

These vectors establish **whether a receipt supports its asserted claims.**
They do not establish that any particular implementation produces defective
receipts. If they are used as oracle cases, that distinction is worth
preserving in how results are described.

The vectors, the reference verifier, and this packaging share one author.
Independent evaluation design and reproduction are the outstanding checks.
