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
