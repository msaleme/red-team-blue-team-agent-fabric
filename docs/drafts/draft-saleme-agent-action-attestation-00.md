# Agent Action Attestation: A Provider-Neutral Schema for Verifiable Agent Decisions

- **Document:** draft-saleme-agent-action-attestation-00 (working draft)
- **Intended status:** Informational
- **Stream (proposed):** IETF Independent Submission
- **Author:** Michael K. Saleme (ORCID 0009-0003-6736-1900)
- **Status:** WORKING DRAFT — not submitted. Submission to a standards body is gated on author sign-off (see §9).

## Abstract

This document defines a minimal, transport-agnostic JSON schema for attesting that an
autonomous agent's action was authorized, evaluated, and recorded — independent of any single
framework, identity provider, or payment rail. The schema binds an action reference to (a) the
authority under which the action was taken, (b) the verdict that admitted it, and (c) evidence
sufficient to reconstruct that verdict offline. It standardizes the *record*, not the enforcement
mechanism, so heterogeneous agents and independent auditors can interoperate without trusting a
single steward.

## 1. Introduction

Agent-commerce and agent-identity layers are consolidating onto shared infrastructure: the x402
payment protocol moved to the Linux Foundation, and MCP security guidance now issues from NSA,
NIST, and CoSAI. Consolidation standardizes how agents *act* and *pay*, but leaves a gap: there is
no provider-neutral record of *why an action was admitted* that an outside party can verify without
trusting the infrastructure's stewards.

This document fills that gap as an informational reference. It does not propose a new enforcement
runtime, identity scheme, or payment rail. It defines the attestation a compliant system emits so
that the admission decision is auditable after the fact and across providers.

## 2. Terminology

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as described in BCP 14
(RFC 2119, RFC 8174).

- **action_ref**: an opaque, collision-resistant identifier for the agent action being attested.
- **authority binding**: the credential, mandate, or capability grant under which the action was taken.
- **verdict**: the admission decision — one of `allow`, `deny`, or `no-verdict`.
- **evidence digest**: a canonical hash over the inputs sufficient to re-derive the verdict offline.

## 3. The Attestation Object

A conforming attestation is a JSON object canonicalized per JCS (RFC 8785). Required and optional
fields:

| Field | Req | Description |
|---|---|---|
| `action_ref` | MUST | Opaque identifier of the attested action |
| `authority` | MUST | Authority binding (mandate id, capability grant, or token reference) |
| `verdict` | MUST | One of `allow` / `deny` / `no-verdict` |
| `evidence_digest` | MUST | JCS-canonical hash over the verdict inputs |
| `verifier` | MUST | Identifier of the component that produced the verdict |
| `issued_at` | MUST | RFC 3339 timestamp |
| `validity_window` | MAY | `not_before` / `not_after` for time-scoped actions |
| `parent_ref` | MAY | For delegated chains: the action_ref this derives from |

## 4. Offline Reconstructability (normative)

A verdict MUST be re-derivable from the evidence referenced by `evidence_digest` without contacting
the issuing system. An attestation whose verdict cannot be reconstructed from its own evidence is
non-conforming. This requirement exists so that an auditor can verify an admission decision after
the issuing platform is offline, compromised, or adversarial — the failure mode shared identity and
payment layers do not currently close.

## 5. The `no-verdict` State (normative)

`verdict` MUST support `no-verdict` as a first-class outcome, distinct from both `allow` and `deny`.
`no-verdict` denotes that the admission control could not reach a decision under its resource budget
(timeout, token exhaustion, or fault). Collapsing `no-verdict` into `allow` (fail-open) or `deny`
(fail-closed) MUST NOT be done silently at the attestation layer; the exhaustion MUST be recorded as
`no-verdict`. This guards against the guardrail denial-of-service class described in
arXiv:2606.14517, where an admission control driven past its budget would otherwise be recorded as a
clean allow or deny.

## 6. Security Considerations

- **Evidence-provider spoofing.** A forged `verifier` or evidence source can manufacture a false
  `allow`. Implementations SHOULD bind `verifier` identity to a key the auditor can validate.
- **Replay.** `issued_at` + `validity_window` + `action_ref` uniqueness mitigate replay of a stale
  `allow`.
- **Attestation forgery.** The attestation SHOULD be signed; the schema is signature-scheme agnostic.
- **Verdict inversion.** Per §5, an exhausted control MUST NOT be recorded as `allow`/`deny`.

## 7. Relationship to Existing Work

- **OWASP State of Agentic AI Security and Governance v2.01** — this schema supplies the auditable
  record its governance/maturity mapping presumes.
- **Skill Security Protocol (SSP)** — see issue #99; SSP enforcement events can populate this record.
- This document is descriptive of the open-source agent-security-harness attestation work and does
  not bind it to any third-party framework.

## 8. IANA Considerations

This document requests no IANA actions in its current form. A future revision MAY request a media
type registration for `application/agent-attestation+json`.

## 9. Status / Submission Gate

This is a working draft staged for review. **It MUST NOT be submitted to the IETF Independent
Submission stream, OASIS, or any other body until the author signs off** on a final wording and
authorship-metadata pass. Recommended venue: IETF Independent Submission (ISE review, no working-group
capture, preserves provider neutrality).

_Drafted via strategic-sweep 2026-06-17 (Move 3). Tracks #137; cross-links #99._
