# Evidence Class Taxonomy

This taxonomy states what a security or governance artifact permits its author
to claim. It is intentionally conservative: evidence of a lower level does not
support language reserved for a higher one.

## Levels

| Level | Evidence required | Permitted claim language | Does not establish |
| --- | --- | --- | --- |
| **E1 - Observation** | A versioned artifact, configuration, source record, or documentation snapshot with its identifier and retrieval context. | "The artifact describes…", "The record contains…" | Runtime behavior, control operation, or security effect. |
| **E2 - Runtime characterization** | A reproducible invocation with environment, inputs, timestamps, and captured result sufficient to characterize the observed execution path. | "Under these conditions, the system returned…", "The run observed…" | That a control enforced a policy, persisted through restart, or isolated a boundary. |
| **E3 - Enforcement** | E2 evidence plus a recorded decision or transaction at the control point showing an action was allowed, refused, or constrained. | "The control enforced…", "The action was refused at…" | Persistence, replay resistance, or isolation beyond the tested path. |
| **E4 - Persistence and replay resistance** | E3 evidence plus a replay, restart, recovery, or retained-state check demonstrating that the relevant decision/state survives the claimed lifecycle. | "The decision persisted across…", "The replay was refused…" | Isolation from other principals, tenants, processes, or trust boundaries. |
| **E5 - Isolation and security boundary** | E4 evidence plus an adversarial boundary test that demonstrates the claimed separation or containment under the stated conditions. | "The boundary isolated…", "The attempted cross-boundary action was contained…" | A universal guarantee outside the tested configuration and threat model. |

Each level subsumes the levels before it. A result may be useful at E1 or E2;
it must not be described as enforcement, persistence, replay resistance, or
isolation without the corresponding evidence.

## Required provenance for any class

Every claim should identify the artifact version, method or command, inputs
that materially affect the result, execution environment, timestamp, and the
retained output used to support the claim. When a claim concerns a third-party
system, distinguish author-performed testing from independent verification.

## Evidence status

E1-E5 describes the strength of a result and I0-I2 describes the independence
of its oracle. Neither axis states where an item sits in an assurance workflow.
Use these status terms separately:

| Status | Establishes | Does not establish |
| --- | --- | --- |
| **Mapped** | A documented relationship between an artifact and a requirement. | That the artifact was executed, a target passed, or the relationship is sufficient for a decision. |
| **Executed** | A recorded run against an identified target from a pinned revision, with relevant inputs and outputs retained. | That the evidence is applicable or sufficient, or that the run was independently reviewed. |
| **Independently reviewed** | A qualified party assessed whether the evidence was applicable and sufficient for the stated purpose. | Certification, unless the reviewing party is authorized to issue it. |
| **Certified** | An authorized certification process concluded that applicable requirements were satisfied for a defined scope. | A universal claim outside that scope or standard version. |

These statuses are not interchangeable. A mapping is E1-level material
regardless of how many requirements it covers. An executed result still needs
an E-class and I-class, and independent review does not itself issue a
certificate.

## Claim discipline

- Describe the tested configuration and threat model, not an entire product or
  protocol.
- Treat an unreachable target, an incomplete trace, or an ambiguous response as
  inconclusive.
- Do not promote an E1/E2 observation into an E3 enforcement claim.
- Do not promote an E3 result into E4 persistence/replay resistance or E5
  isolation without the corresponding lifecycle and boundary evidence.
- Record negative and null results alongside favorable results.

This document is a methodology definition, not a certification framework or a
claim that every harness result satisfies E5.

## Independence axis (I0-I2)

E1-E5 states how strong a result is. It does not state **who produced the
oracle**, and that is a separate failure mode. A result can be E5 and still be
worthless if the check and the thing it checks were derived from the same
assumption.

| Level | Who produced the oracle | Catches | Does not catch |
| --- | --- | --- | --- |
| **I0 - Self-authored** | The same author, and often the same source, as the implementation under test. | Coding errors the author did not intend. | Any assumption the author did not know they were making. |
| **I1 - Independent implementation** | A second implementation of the same published contract, written by a different party from the specification rather than from the code. | A shared assumption between a check and its implementation. Divergence is the signal; agreement is weak evidence. | A target that misreports its own state. Both implementations read the same channel and will agree while both are wrong. |
| **I2 - Independent sensor** | A channel the system under test does not author: kernel event log, network capture, hardware trace, out-of-band ledger. | A system whose self-report does not match its behavior. | Nothing about correctness of the specification itself. |

The axis is orthogonal to E1-E5. Cite both: an author-performed enforcement
result is **E3/I0**, and a separately reimplemented replay of a pinned corpus is
**E2/I1**. An author-performed E5 is still I0 and is not independent
verification.

### Why the axis exists

Two measured cases in this repository, both recorded rather than hypothetical.

**I0 failure, 2026-08-02.** The human-oversight module shipped with a guard that
treated only a transport failure as "no answer." A regression test existed for
exactly that defect and mocked a transport failure, which was the same
assumption the implementation made. The oracle and the code were two copies of
one belief, so the suite stayed green while the defect was live. Measured
against a live host answering 404, 401, 500, and a JSON-RPC error inside an
HTTP 200: **20 false passes across four status classes**, and 0 after the fix.

**I1 in practice, 2026-08-01.** A separate Node verifier, written from the
published contract by a party unknown to the author, replayed the pinned RCL
oracle corpus and matched 11/11 verdicts (issue #304). The agreement was not the
useful part. The exercise produced two corrections to this repository's own
artifacts: the fixture declared RFC 8785 JCS canonicalisation while the code
emitted Python-style sorted compact JSON, encodings that coincide only for
ASCII-only, integer-valued payloads; and the corpus did not declare that
freshness was exercised only in the stale direction. Both were fixed in #307.

Who found what is part of the case. The reimplementation did not report the
canonicalisation mismatch. The author identified it while reviewing the outside
report, and the reporting party confirmed it. What the exercise supplied was a
second implementation written from the published contract, which is what made
the gap between declaration and behaviour legible. Neither correction is one an
I0 test in this repository could have surfaced, because every one of them was
written against the implementation.

### Claim discipline for the axis

- State the I-level next to the E-level. Omitting it defaults the reader to
  assuming independence that was not established.
- **I1 agreement is not validation.** Report the divergences found, or state
  that none were found and that this is weak evidence.
- Do not describe an I1 cross-evaluation as independent validation,
  certification, endorsement, or adoption. Preserve the scope the second party
  set for their own work.
- This harness holds **no I2 evidence**. It reads protocol responses, which the
  target emits, so its observations remain inside the boundary a dishonest
  target controls. Where that limit matters to a claim, say so.
