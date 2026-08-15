# Attestation Registry Server Contract

Status: draft, resolves #333. Related: #114, #137, `docs/EVIDENCE-CLASS-TAXONOMY.md`,
`docs/attestation-registry.md`, `protocol_tests/attestation_registry.py`.

This document specifies the **receiving** half of the attestation registry. The client half
already exists and ships. What did not exist, until this document, was any statement of what
a server must do, which meant no second organization could stand one up and no third party
could check a record without asking the operator to vouch for it.

**This project operates no registry.** It specifies one. That distinction is load-bearing and
is repeated in the design rules below.

---

## 1. What a submission establishes

A submission establishes **I0** under `docs/EVIDENCE-CLASS-TAXONOMY.md`, and nothing more,
**regardless of which organization submitted it**.

The submitter ran a harness they obtained, against a target they control, and authored the
oracle. Routing that result through a server does not change who produced the oracle. A
registry that presents a submission as third-party verification manufactures independence it
never measured, which is the exact failure the taxonomy exists to prevent.

Two consequences bind the rest of this contract:

- Every stored record MUST carry an explicit `evidence_class` and `independence_level`, and
  MUST name the **system under test** the level is relative to. An I-level without a named
  system under test is not a claim, because the axis is relative (see the taxonomy's
  "Relative independence in practice"). A registry that stores a bare `"I0"` has stored
  nothing checkable.
- A server MUST NOT emit language of the form "verified", "certified", "approved", or
  "independently confirmed" for a submitted record. The shipping client already enforces the
  correct label on the badge it generates: `Tested with Agent Security Harness`. A server
  MUST NOT serve a badge whose text asserts more than that.

Raising a record above I0 requires a **separate** record produced by a different party from
the specification rather than from the code (I1), or a channel the system under test does not
author (I2). Those are different submissions with their own provenance, not a status flag an
operator can set. See §7.

## 2. Design rules

**R1. No default endpoint. Ever.**
`resolve_registry_endpoint()` requires `AGENT_SECURITY_REGISTRY_URL` and has no fallback. That
absence is a security property, not an oversight. Until 2026-08-04 this client defaulted to a
hostname the project did not own, and every publish with no override posted a signed
attestation, including an optional user-supplied contact email, to a third party. A conforming
server MUST NOT be published as a well-known host, MUST NOT be baked into a client default,
and MUST NOT be advertised in a way that invites one. Operators configure their own.

**R2. A verifier must never need to trust the operator.**
Every guarantee in §5 is checkable from the bytes the server returns, offline, without a second
call to that server. Where the current wire format does not permit this, §4.1 says so plainly
rather than papering over it.

**R3. Do not fork the schema.**
`schemas/attestation-report.json` is the payload format and #137 targets it at a standards
venue. A server MUST accept a report that validates against that schema and MUST NOT require
registry-specific fields inside `payload.report`. Registry-specific metadata lives in the
envelope, outside the report.

**R4. Contract before UI.**
Per `ROADMAP.md`, the evidence artifact is the product. A conforming server needs three
endpoints. A browsable index, search, or dashboard is out of scope and MUST NOT be a
precondition for conformance.

**R5. Targets are not identifiable.**
The client's `strip_sensitive_fields()` removes any key matching `url`, `endpoint`, `host`,
`address`, or `path` as a substring, plus an explicit list including `request_sent`,
`response_received`, `headers`, `auth_token`, and `api_key`. A server MUST reject a submission
whose `payload.report` still contains such a key (§5.4). This is defense in depth: the client
already stripped them, so their presence means the submission did not come from a conforming
client.

## 3. Endpoints

A conforming server exposes exactly three. `{base}` is the value of
`AGENT_SECURITY_REGISTRY_URL`.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `{base}` | Accept a submission envelope. Returns `{"id": "..."}`. |
| `GET` | `{base}/{registry_id}` | Return the stored record. |
| `GET` | `{base}/badge/{registry_id}` | Return a badge image. |

These paths are not chosen; they are what the shipping client already calls. `publish_attestation()`
POSTs to `{base}` itself, `verify_attestation()` GETs `{base}/{registry_id}`, and the badge URL is
built as `{scheme}://{netloc}/badge/{registry_id}`.

Note that the badge URL derives from **scheme and netloc only**, discarding any path component
of `{base}`. A server mounted at `https://example.org/registry` will receive badge requests at
`https://example.org/badge/{id}`. A server SHOULD mount at the origin root, or serve
`/badge/{id}` at the origin in addition to its path prefix.

`registry_id` MUST match `^[A-Za-z0-9\-]+$`. The client validates this before URL construction
and a server MUST re-validate rather than rely on it.

## 4. The submission envelope

What the shipping client POSTs, verbatim:

```json
{
  "payload": {
    "server_name": "<string, ^[A-Za-z0-9\\-\\. ]+$, max 200>",
    "contact": "<email or null>",
    "report": { "...": "attestation report, sensitive fields stripped" },
    "published_at": "<YYYY-MM-DDTHH:MM:SSZ>"
  },
  "signature": "<Ed25519 signature over the canonical payload bytes>",
  "verification_hash": "<sha256 hex of the canonical payload bytes>",
  "public_key_fingerprint": "<first 16 hex chars of sha256 of the signer's public key PEM>"
}
```

### 4.1 Canonical payload bytes

The signature and `verification_hash` are computed over:

```python
json.dumps(payload_dict, sort_keys=True).encode()
```

**Default separators.** That is `", "` and `": "`, not the compact form. This has never been
written down anywhere, and it is the single most likely cause of an independent
reimplementation failing to verify a signature it should accept. It is pinned here because a
canonicalization that lives only in one implementation is not a contract.

This basis sorts keys and does not define duplicate-key rejection, Unicode normalization, or
number normalization. Do not relabel it RFC 8785 / JCS. If a future revision moves to JCS, the
envelope MUST carry a version discriminator and both sides MUST be updated together.

### 4.2 Envelope v2: carrying the public key (closed 2026-08-15, #371)

**The submission carries `public_key_fingerprint` but never the public key.**

A fingerprint is `sha256(public_key_pem)[:16]`. From it, a verifier can confirm that a key they
already hold is the right one. They cannot recover the key, and therefore cannot check the
Ed25519 signature. Any third party who fetches a record from a registry today can verify the
`verification_hash` against the payload bytes, which proves only internal consistency, and can
verify nothing about **who** signed it.

That defeats R2. An operator could store a payload they authored, compute a matching hash
themselves, and serve a record indistinguishable from a genuine one.

**Required client change.** The submission envelope gains `public_key`, carrying the signer's
PEM-encoded Ed25519 public key, and an `envelope_version` discriminator:

```json
{
  "envelope_version": "2",
  "payload": { "...": "unchanged" },
  "signature": "...",
  "verification_hash": "...",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "public_key_fingerprint": "..."
}
```

`public_key_fingerprint` is retained and MUST equal `sha256(public_key)[:16]`, so a server can
reject a mismatched pair and existing consumers of the field keep working.

A server MUST accept `envelope_version: "2"`. A server MAY accept an envelope with no
`envelope_version` and no `public_key` for compatibility with the currently shipping client,
and if it does, it MUST mark the stored record `signature_verifiable: false`. A record that
cannot be verified without the operator MUST say so about itself.

This gap is a finding about the existing client, not a design choice. It is filed rather than
silently fixed here because the client change belongs in its own reviewed commit.

## 5. Server obligations on POST

In order. Any failure is a rejection; a server MUST NOT store a partially validated record.

1. **Shape.** `payload`, `signature`, `verification_hash` present. `payload.server_name` and
   `payload.published_at` present. Reject with `400` otherwise.
2. **Field validation.** `server_name` against `^[A-Za-z0-9\-\. ]+$`, max 200 chars. `contact`,
   if non-null, against `^[^@\s]+@[^@\s]+\.[^@\s]+$`, max 200. These mirror the client's
   validators; a server that trusts the client to have run them is trusting an unauthenticated
   party.
3. **Hash.** Recompute the canonical bytes per §4.1 and confirm `verification_hash` matches.
   Reject with `400` on mismatch. This catches transport corruption and re-serialization
   damage, and nothing else.
4. **Sensitive-field scan.** Walk `payload.report` and reject with `422` if any key matches the
   client's sensitive set. A submission that still contains a `target_url` did not come from a
   conforming client, and storing it would publish infrastructure the submitter did not intend
   to publish.
5. **Schema.** Validate `payload.report` against `schemas/attestation-report.json`. Reject with
   `422` on failure. Do not require fields the schema does not require (R3).
6. **Signature.** If `public_key` is present, verify the Ed25519 signature over the canonical
   bytes and reject with `400` if it fails. If absent, store `signature_verifiable: false`
   (§4.2). A server MUST NOT report a record as signature-verified when it never checked one.
7. **Classification.** Store `independence_level: "I0"` and the named system under test. A
   server MUST NOT accept a submitter-supplied level above I0 (§7).
8. **Assign an id.** Any string matching `^[A-Za-z0-9\-]+$`. Using `verification_hash[:12]` is
   RECOMMENDED because it makes the id derivable from the record, and the client already falls
   back to exactly that value when a response omits `id`.

Response is `201` with at minimum `{"id": "<registry_id>"}`. A server MAY return the full
stored record.

**Idempotency.** Two submissions with equal `verification_hash` are the same record. A server
SHOULD return the existing id with `200` rather than creating a duplicate.

## 6. Server obligations on GET

`GET {base}/{registry_id}` returns the stored record. It MUST include everything an offline
verifier needs:

```json
{
  "id": "...",
  "payload": { "...": "byte-identical to what was submitted" },
  "signature": "...",
  "verification_hash": "...",
  "public_key": "...",
  "public_key_fingerprint": "...",
  "envelope_version": "2",
  "signature_verifiable": true,
  "evidence_class": "E1",
  "independence_level": "I0",
  "system_under_test": "<name the level is relative to>",
  "received_at": "<server timestamp, RFC 3339>",
  "claim_label": "Tested with Agent Security Harness"
}
```

`payload` MUST round-trip to the same canonical bytes that were signed. A server that
normalizes, reorders, or re-encodes `payload` destroys the signature and breaks every
downstream verification. Store the payload; do not improve it.

`received_at` is the server's own observation and is **not** signed by the submitter. It is
therefore an operator claim, and a verifier MUST treat it as such. Only `payload.published_at`
is inside the signature.

## 7. Independence is a separate record, not a flag

A server MUST NOT expose an endpoint, field, or administrative action that raises a record's
`independence_level`.

An I1 claim is a distinct submission: a second party reproduced a pinned corpus using an
implementation written from the published contract rather than from this code, and their
result is its own record with its own signature. The relationship between the two records is
expressed by the reproducer referencing the original's `verification_hash` inside their own
signed payload, so the link is inside the signature rather than asserted by the operator.

`#304` is the shape of a real I1 event: an outside party reproduced 11/11 RCL verdicts and
surfaced two fixture-contract defects the author had not declared. Note what made it evidence.
Not that it agreed, but that it **disagreed in two places**. A registry that only records
agreement is measuring the wrong thing, so a conforming server MUST accept and serve records
whose result is a mismatch, and MUST NOT rank, hide, or filter them relative to agreeing
records.

## 8. Operating posture

Hosting a registry is an operational commitment: availability, data handling for the optional
contact email, and a retention answer. **Self-hosted-only is a conforming answer, and is the
default this project recommends.** An operator running one for their own organization owes
their submitters a stated retention period and a deletion path; the contract does not require
either of those to be public, only to exist.

If an operator publishes a registry for others, they SHOULD state: retention period, deletion
path, whether `contact` is served publicly, and their answer to §4.2 (whether unverifiable
records are accepted). None of that is checkable by a verifier, which is the point of R2:
nothing in §5 or §6 requires trusting the answer.

## 9. Verification without trusting the operator

The full offline path, given a record fetched from any registry:

1. Recompute the canonical bytes from `payload` per §4.1.
2. Confirm `sha256(bytes).hexdigest() == verification_hash`. Establishes internal consistency.
3. Confirm `sha256(public_key)[:16] == public_key_fingerprint`. Establishes the key matches its
   advertised fingerprint.
4. Verify `signature` over the bytes with `public_key`. Establishes that the holder of that key
   signed this payload.
5. Independently establish that the key belongs to who you think it does. **The registry cannot
   help with this and MUST NOT claim to.** Key-to-identity binding is out of scope for this
   contract; a verifier gets it from the submitter directly, from a published fingerprint, or
   not at all.
6. Read `independence_level` and `system_under_test`. If the level is I0, the record is
   self-authored evidence and steps 1 through 4 do not change that. They prove the record was
   not altered. They prove nothing about the target.

Step 6 is the one most likely to be skipped by a reader who watched the first five succeed. A
cryptographically impeccable I0 record is still a vendor testing itself.

`scripts/verify_attestation_record.py` implements steps 1 through 4 and prints step 6 as a
statement rather than a check.

## 10. Reference implementation

`scripts/registry_reference_server.py`, Python standard library only, single file, in-memory
store. It is a conformance reference, not a deployment target: no persistence, no auth, no
TLS, no rate limiting.

```bash
python3 scripts/registry_reference_server.py --port 8787
export AGENT_SECURITY_REGISTRY_URL="http://localhost:8787"
```

`localhost` is permitted by the client's https-or-localhost guard, so the loop is runnable
end to end offline.

## Conformance checklist

- [ ] `POST {base}` performs all eight checks in §5 in order
- [ ] Rejects a submission whose `verification_hash` does not match the canonical bytes
- [ ] Rejects a report containing a sensitive key
- [ ] Verifies the Ed25519 signature when `public_key` is present
- [ ] Marks `signature_verifiable: false` when it is absent, rather than omitting the question
- [ ] Stores `independence_level: "I0"` and a named `system_under_test`
- [ ] Exposes no mechanism to raise `independence_level`
- [ ] Returns `payload` byte-identically, so the signature still verifies
- [ ] Serves `/badge/{id}` with claim text no stronger than "Tested with Agent Security Harness"
- [ ] Accepts and serves records whose result is a mismatch, unranked
- [ ] Is not published as a well-known host and is not a client default
