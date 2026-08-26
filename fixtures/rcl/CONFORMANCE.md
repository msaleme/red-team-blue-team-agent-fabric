# RCL conformance suite — v0.1

**What a verifier must do to be conformant with the RCL oracle corpus, and how to state a result.**

This document extends [`README.md`](README.md); it does not restate it. The README covers the claim
families, the schema, how to run the fixtures, the key material, and the coverage gap. Read it first.
This file adds only what a *conformance* claim needs: the normative requirements, the traps the corpus
is built around, and the language in which a result may honestly be reported.

---

## 0. Status, and what this is not

**This is not a standard.** It is one corpus, from one author, with a reference verifier by the same
author. Conformance in any meaningful sense would need more independent implementations, broader
vector coverage, and a governance process. None of those exist.

Two implementations agreeing on a pinned corpus is an **interop data point**. It is a useful one —
it establishes that the contract is specified precisely enough to implement from the document alone —
and it is not evidence that any product is safe.

**Why it exists.** Vendors are shipping controls for composed and cross-session agent risk. Dai et al.
characterised the cross-session attack (*Stateful Agent Backdoor*, arXiv:2605.06158, 2026-05-07), and
Microsoft acknowledges the same variant in
[`agent-governance-toolkit/docs/LIMITATIONS.md`](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/LIMITATIONS.md)
(2026-05-19), with sequence-level policy listed as planned work. Controls will exist. What does not
yet exist is a vendor-neutral way to check whether a given implementation does what it claims. This
corpus is an attempt at that half of the problem, and nothing here claims priority over either source.

---

## 1. Corpus identity — pin it, and say which one you ran

A conformance result is meaningless without naming the exact artifact it was obtained against.

| | |
|---|---|
| File | `fixtures/rcl/rcl-oracle-fixtures.v1.json` |
| `schema_version` | **`1.0`** |
| Counts | `{"total": 11, "accept": 2, "reject": 9}` |
| Pinned `evaluation_time` | `1750000000` |
| `freshness_window_seconds` | `300` |

```bash
sha256sum fixtures/rcl/rcl-oracle-fixtures.v1.json
```

### Two hashes exist, and they are not interchangeable

| SHA-256 | Ref | Status |
|---|---|---|
| `4164151383605d9d68230d81cc9ae1dd31eb5cfb3fb1348289abf71ee64773ea` | current `main` | **use this** |
| `0bc47dab20d1c45100f5525a1798fd84df3fd979d1febb2b5fc1c5a69846befb` | `5e25bc6465ccced079ca6a6b8f54e065a1677a69` | historical; the recorded interop result in §6 was obtained against it |

The file changed once, in **#307**, which corrected the `signature_algorithm` *label* (it named the
encoding as JCS; it is not JCS). **No verdict, claim family, reason string or count changed** — the
two files are semantically identical and differ by three lines of metadata. A result obtained against
either is a result about the same eleven vectors.

They are listed separately anyway, because reporting a hash that does not match the file a reader
downloads leaves them unable to tell whether the fixture or their verifier is wrong — the same
failure mode §4 describes for canonicalisation.

---

## 2. What a conforming verifier must do

Given **only** the fixture file and the public keys it exports, a conforming verifier reproduces all
eleven recorded outcomes — verdict, `claim_family`, `reason`, and envelope-validity expectation. Not
merely accept/reject.

It MUST:

1. Verify envelope and authority **Ed25519** signatures using only the exported public keys.
2. **Recompute** action and parameter digests. A declared label is not authoritative.
3. Check authorization and occurrence linkage **to the exact action**, not to the receipt in general.
4. Check checker authority, freshness, tool-set binding, and recorded output.
5. Use the **pinned `evaluation_time`** as "now". Not wall clock. See §3.

A verifier that satisfies 1 but not 2–4 will look rigorous and establish almost nothing: every
envelope in the corpus is valid by construction, which is exactly the property the set isolates.

---

## 3. Three traps, and why they are there

A superficially-correct verifier fails all three. They are the reason the corpus is worth running.

| Trap | The failure it catches |
|---|---|
| **Independent recomputation** of each evidence binding | Treating a valid outer signature as proof of authorization, occurrence, or check execution. |
| **Both acceptance controls preserved** — `RCL-008`, `RCL-009` | The reject-everything verifier. Rejecting all eleven scores 9/11 on the rejection cases and is worthless. These two exist solely to catch it. |
| **Pinned `evaluation_time`** | Wall-clock evaluation. Both acceptance controls carry checker timestamps at `1750000000`; evaluated against wall clock they fall outside the 300-second freshness window and age out — silently collapsing the corpus to eleven rejections and producing a verifier that appears to work while checking nothing. |

The third is the one most likely to be missed. Passing it without coordinating with this repository is
the strongest single indicator that the contract is specified precisely enough to implement from the
document alone.

---

## 4. Declared limits

These are the corpus's limits, listed because a conformance artifact that hides its coverage gaps is
worse than none. They are also machine-readable in the fixture's own `coverage_gaps` field.

- **Encoding is sorted compact JSON, not JCS.** The signing payload is
  `json.dumps(obj, sort_keys=True, separators=(",", ":"))`, UTF-8 encoded. It *coincides* with
  RFC 8785 for this corpus's ASCII-only, integer-valued payloads, but diverges on number
  canonicalisation (`1.0` stays `1.0`, not `1`) and on non-ASCII escaping. A verifier canonicalising
  per RFC 8785 against a **future** corpus carrying non-ASCII or non-integer values would hit a
  signature mismatch with no way to tell whether the fixture or the verifier was at fault. The label
  was corrected in #307; the encoding did not change.
- **Freshness is exercised only in the stale direction** (`RCL-003`). The corpus does not establish
  how a verifier should treat a check attested *ahead of* `evaluation_time`.
- **No negative `integrity_provenance` vector.** That family is enforced by the verifier but
  unexercised here, because every vector is envelope-valid by construction.
- **Tool-set evidence is partial.** A declared tool-set digest is exposed; not every underlying tool
  set is. A verifier can check the signed check-to-digest binding. It cannot reconstruct evidence
  that is not present.

Adding vectors for the first two gaps would change the corpus hash and invalidate existing results.
That is a deliberate reason to prefer **another independent implementation** over more vectors.

---

## 5. How to state a result — accurate and inaccurate phrasings

The corpus, the reference verifier, and this document share one author. Independent implementation
and reproduction are the outstanding checks, and how a result is described has to reflect that.

**Accurate:**

- "a published cross-implementation result"
- "two independent implementations agree on 11/11 verdicts against the pinned corpus"
- "an external reproduction of the fixture corpus"
- "conformant with the RCL oracle corpus v1.0 at `<sha256>`"

**Not accurate, and not to be used:**

- ~~"independently validated"~~ · ~~"externally verified"~~ · ~~"third-party endorsed"~~
- ~~"certified"~~ · ~~"audited"~~
- any construction implying an implementer vouches for this project, or that conformance means a
  product is safe

Naming another implementer requires their consent. Absent it, state only that an independent
implementation exists.

---

## 6. Interop results

| Implementation | Language | Corpus ref | Verdicts | Acceptance controls | Notes |
|---|---|---|---|---|---|
| Reference (`ClaimLevelVerifier`, this repo) | Python | `1.0` @ `4164151383…` | 11/11 | preserved | expectations are executed at export, not hand-written |
| Independent implementation (unnamed pending consent) | Node | `1.0` @ `0bc47dab…` | 11/11 | preserved | written from the published contract alone; surfaced two contract-description defects, corrected in #307 |

**The second row is deliberately unnamed.** The implementer scoped their own result conservatively
and has not consented to being cited. Do not add their name, repository, or a link to this table
without that consent. If it is granted, the row may name them and nothing else about it changes.

The second row's result was obtained against the historical hash; see §1 for why that is the same
eleven vectors.

---

## 7. Contributing an implementation

A third independent implementation is worth more to this corpus than any additional vector.

1. Implement a verifier from [`README.md`](README.md) and the fixture file alone. **Do not read
   `protocol_tests/receipt_claim_harness.py` first** — reading the reference implementation converts
   an independent result into a port, and the value is in the independence.
2. Run it over all eleven vectors using the pinned `evaluation_time`.
3. Report which of verdict, `claim_family`, and `reason` you reproduce, the corpus hash you ran
   against, and anything the contract failed to specify clearly enough to implement.

**Disagreements are the most valuable output.** Both defects corrected in #307 came from an outside
implementer disagreeing with the documentation, not from agreeing with it.
