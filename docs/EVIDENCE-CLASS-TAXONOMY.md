# Evidence Class Taxonomy

This taxonomy states what a security or governance artifact permits its author
to claim. It is intentionally conservative: evidence of a lower level does not
support language reserved for a higher one.

## Levels

| Level | Evidence required | Permitted claim language | Does not establish |
| --- | --- | --- | --- |
| **E1 - Observation** | A versioned artifact, configuration, source record, or documentation snapshot with its identifier and retrieval context. | "The artifact describes…", "The record contains…" | Runtime behavior, control operation, or security effect. |
| **E2 - Runtime characterization** | A reproducible invocation with environment, inputs, timestamps, and captured result sufficient to characterize the observed execution path. | "Under these conditions, the system returned…", "The run observed…" | That a control enforced a policy, persisted through restart, or isolated a boundary. |
| **E3 - Enforcement** | E2 evidence plus a recorded decision or transaction at the control point showing an action was allowed, refused, or constrained. | "The control enforced…", "The action was refused at…" | Persistence, replay resistance, or isolation beyond the tested path. **Also does not establish that the control cannot be disabled, bypassed, or reconfigured by the system under test.** That is an E5 isolation question. |
| **E4 - Persistence and replay resistance** | E3 evidence plus a replay, restart, recovery, or retained-state check demonstrating that the relevant decision/state survives the claimed lifecycle. | "The decision persisted across…", "The replay was refused…" | Isolation from other principals, tenants, processes, or trust boundaries. |
| **E5 - Isolation and security boundary** | E4 evidence plus an adversarial boundary test that demonstrates the claimed separation or containment under the stated conditions. The boundary may be between principals, tenants or processes, **or between a system and its own control plane**. | "The boundary isolated…", "The attempted cross-boundary action was contained…" | A universal guarantee outside the tested configuration and threat model. |

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
- **An architectural claim that a control cannot be bypassed is an assertion,
  not evidence.** Where the control point sits changes what the architecture
  predicts about future runs. It does not change what an E3 record demonstrates
  about the run observed. Test it and cite E5, or state it as an untested design
  property.
- Record negative and null results alongside favorable results.
- **A record's absence is a claim about the record set, not about the
  world.** Presence does not establish that an action was authorized;
  absence does not establish that it did not occur. See below.

This document is a methodology definition, not a certification framework or a
claim that every harness result satisfies E5.

### What a record's absence permits

The taxonomy already says a record's **presence** is weak: an E1 artifact
describes, and describing is not enforcing. The mirror case is easier to get
wrong, because it does not look like a claim at all.

```
a record exists          does not establish the action was authorized
no record exists         does not establish the action did not occur
```

Reading a missing entry as a negative result requires a property the record set
usually does not have: that every in-scope action would have produced an entry,
and that no entry can be removed afterwards. Neither holds by default. An entry
may be absent because the action never happened, because the recorder was not
running, because the action fell outside what the recorder observes, or because
the entry was deleted by a party permitted to delete it. Those four are
indistinguishable from the outside, and only the first supports a claim.

**Measured, 2026-08-30.** Four modules in this repository graded a security
control as holding on exactly this reasoning, computing verdicts of the form
`passed = not <indicator matched in the response>`. Against an agent that
complied with every request without using a listed word, `return_channel_harness`
reported 8 of 8 controls holding, and `capability_profile_harness` reported 8 of
10, five of those P0-Critical. Nothing was blocked. No marker was emitted. The
absence was read as the control.

The repair is not a better word list. It is to stop treating absence as a
result: an observed refusal is a PASS, an observed violation is a FAIL, and a
response that is neither is **INCONCLUSIVE**. `testing/test_refusal_establishes_a_pass.py`
asserts both directions, because a module that downgraded everything to
INCONCLUSIVE would satisfy the first half and be useless.

**For any record-based claim, state which of these the record set supports.**

| Claim | Requires |
| --- | --- |
| "This action was recorded." | The entry, with its provenance. |
| "This action was authorized." | The entry **plus** the authorization decision it references, and an integrity method binding them. |
| "This action did not occur." | Completeness of the record set over the claimed scope **and** either immutability or a separately auditable record of deletions. |

The third is the expensive one and is usually not available. Where a record set
permits deletion by the subject of the record, or by the principal the record is
about, a negative claim over it is not supported at any E-level. Say so rather
than inferring non-occurrence, and treat the gap as an open design question for
the profile rather than a property of the run.

### Where the control point sits (resolves #343)

A recurring question: two systems can enforce the same limit, one with a rule
the governed system could switch off and one with a boundary it cannot reach,
and both produce an E3 record. Does the scale need a way to tell them apart?

No, and the reason is worth stating because the mistake is easy to make.

**This scale classifies evidence, not architecture.** Two systems with the same
evidence get the same label, and that is correct rather than a defect. An
external boundary is a stronger *design*, but until someone tests that the
governed system cannot reach it, the claim "it cannot be bypassed" has no
evidence behind it. It is an assertion about the architecture, and the promotion
rule above already refuses to credit it.

What the external boundary buys is a prediction about runs nobody observed.
E3 licenses a claim about the run that was observed. Those are different claims
and the scale keeps them apart on purpose.

So the distinction is real and it lands on the existing axis:

| What you have | Class |
| --- | --- |
| A recorded refusal at the control point | E3 |
| The same, plus an adversarial test that the system under test cannot disable or bypass that control | E5 |

If the boundary is untested, say so. An untested external boundary and an
untested internal one are both E3, and the honest description of the difference
is architectural rather than evidentiary.

## Independence axis (I0-I2)

E1-E5 states how strong a result is. It does not state **who produced the
oracle**, and that is a separate failure mode. A result can be E5 and still be
worthless if the check and the thing it checks were derived from the same
assumption.

**An I-level is not a property of a record. It is a property of the relationship
between a record and a named system under test.** The same artifact takes a
different level depending on who is making the claim: a payment issuer's ledger
is I2 evidence for the cardholder and I0 evidence for the issuer. State the
system under test whenever you state an I-level, or the level means nothing.

| Level | Who produced the oracle | Catches | Does not catch |
| --- | --- | --- | --- |
| **I0 - Self-authored** | The same author, and often the same source, as the implementation under test. | Coding errors the author did not intend. | Any assumption the author did not know they were making. |
| **I1 - Independent implementation** | A second implementation of the same published contract, written by a different party from the specification rather than from the code. | A shared assumption between a check and its implementation. Divergence is the signal; agreement is weak evidence. | A target that misreports its own state. Both implementations read the same channel and will agree while both are wrong. |
| **I2 - Independent sensor** | A channel the system under test does not author: kernel event log, network capture, hardware trace, or a ledger held out-of-band **relative to that system**. The same ledger is I0 for whoever operates it. | A system whose self-report does not match its behavior. | Nothing about correctness of the specification itself. |

The axis is orthogonal to E1-E5. Cite both: an author-performed enforcement
result is **E3/I0**, and a separately reimplemented replay of a pinned corpus is
**E2/I1**. An author-performed E5 is still I0 and is not independent
verification.

Because the I-level is relative, a citation is only complete with the system
under test named: "E3/I0 for this harness" rather than a bare "E3/I0".

### Relative independence in practice (resolves #346)

Recorded rather than hypothetical, and found from outside.

**2026-08-06.** An operator running an agent under a written spending cap
described their setup in [microsoft/autogen#7823](https://github.com/microsoft/autogen/discussions/7823):
purchases flow through a prepaid card the agent cannot access, and the agent
keeps its own compliance log. Asked to classify their own evidence with this
axis, they reached a conclusion this document had not stated:

> it's I2 for the entity operating the instrument, I0 for me until I go get
> independent confirmation

Their balance figure is owner-reported rather than pulled from an issuer API, so
it sits in the same class as the compliance claim it was meant to anchor. The
issuer's ledger would be I2 for them, but they have no access to it, so the
strongest available evidence for the boundary is still self-authored.

Two things follow, and both are now stated above rather than left implicit.

The level is relative. Before this, the I2 row named "out-of-band ledger" as an
example without saying out-of-band from whom, which invites reading I2 as
something an artifact carries with it.

And the same operator reported a **live 30-cent discrepancy** between the
owner-reported balance and their own computed one, flagged and deliberately left
open because neither record could settle it. That is the detection-without-
adjudication state. A system holding one record would have reported a clean
balance and produced no discrepancy at all, which is worse and looks better.

Both findings came from someone applying the axis to their own system, not from
review inside this repository. That is the same pattern the I0 row describes: an
assumption the author did not know they were making.

### Assessor independence is a second dimension (and it disagrees)

I0-I2 asks **who produced the oracle**. It does not ask **who funds or controls
the party doing the assessing**, and those come apart.

An assessment can be I1 by authorship and still worthless if the assessor is
owned by, controlled by, or economically dependent on the party being assessed.
Conversely a genuinely disinterested reviewer who reimplements from the same
misread specification is independent on the second axis and still I0-equivalent
in effect. Neither axis substitutes for the other, so track both:

| Axis | Question | Failure it catches |
| --- | --- | --- |
| **Authorship** (I0-I2) | Who wrote the oracle, and from what? | A shared assumption between a check and the thing it checks. |
| **Assessor interest** | Who owns, controls, or funds the assessing party? | Corroboration that is structurally guaranteed to agree. |

The operational form of the second axis, as used by regulators recognising
conformity-assessment bodies, is an ownership, control, and
revenue-concentration test: an assessor is not independent if it is owned or
controlled by, or derives a majority of its revenue from, any single party it
assesses. That is a sharper and more checkable criterion than "separately
authored," and it is the one worth applying to any body whose sign-off would
carry weight.

**Recorded, 2026-08-30, and found in review rather than from outside.** A
competitive assessment written inside this project scored an external effort as
better-evidenced on five separate rows, and recommended acting on it. Every one
of the five rows resolved to the same author's artifact set: an implementation
count asserted by that author in their own still-open issue; a standards
artifact owned by a second account that publicly verifies the first; the
corpus itself; a contribution that party authored into a third-party project;
and a cross-verification whose only source was the same issue as row one.
Five rows read as five confirmations. They were one party counted five ways,
and one of the five was independently real, which is what made the set
persuasive.

Two things generalise from it.

**Collapse a scoreboard by author before believing it.** Any comparison table
that treats rows as independent corroboration should resolve each row to the
account that authored the artifact and merge rows that share one. A table
without an author column cannot show that it is not counting one party
repeatedly.

**Apply the independence standard symmetrically.** The failure was not that the
axis was unknown. It was applied rigorously to this project's own artifacts,
correctly downgrading them, and not at all to the sources being used to displace
them. Asymmetric application is how a disciplined instrument reaches a wrong
conclusion with every individual step defensible.

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
- **Assessor interest is not authorship.** State who funds and controls a
  party whose assessment you cite. An I1 result from an assessor economically
  dependent on the assessed party is not independent evidence.
- **Independence does two different jobs and they come apart.** *Detection*: two
  records that disagree establish that something is wrong. *Adjudication*: an
  independent record establishes which one is wrong. Two I0 records in
  disagreement give the first without the second. That is a real state, not a
  broken one, and it should be reported as an unresolved discrepancy rather than
  closed by choosing the more convenient record.
