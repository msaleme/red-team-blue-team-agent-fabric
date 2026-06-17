# Agent Action Attestation: A Provider-Neutral Schema for Verifiable Agent Decisions

- **Document:** draft-saleme-agent-action-attestation-01 (working draft)
- **Intended status:** Informational
- **Stream (proposed):** IETF Independent Submission
- **Author:** Michael K. Saleme (ORCID 0009-0003-6736-1900)
- **Status:** WORKING DRAFT — not submitted. Submission to a standards body is gated on author sign-off (§10).

## Status of This Memo

This is a working draft, not an Internet-Draft submission. It does not yet carry the boilerplate
required by RFC 7841 for the Independent Submission stream; that boilerplate, the xml2rfc/idnits
conversion, and the Author's Address block are added only at submission time (§10). Distribution is
limited to review within the agent-security-harness project until then.

## Abstract

This document defines a minimal, transport-agnostic JSON schema for attesting that an autonomous
agent's action was authorized, evaluated, and recorded — independent of any single framework,
identity provider, or payment rail. The attestation binds an action reference to (a) the authority
under which the action was taken, (b) the verdict that admitted it, and (c) a retrievable, digest-
committed evidence bundle sufficient to reconstruct that verdict offline. It standardizes the
*record*, not the enforcement mechanism, so heterogeneous agents and independent auditors can
interoperate without trusting a single steward.

## 1. Introduction

Agent-commerce and agent-identity layers are consolidating onto shared infrastructure: the x402
payment protocol moved to the Linux Foundation, and MCP security guidance now issues from NSA,
NIST, and CoSAI. Consolidation standardizes how agents *act* and *pay* but leaves a gap: there is no
provider-neutral record of *why an action was admitted* that an outside party can verify without
trusting the infrastructure's stewards.

This document fills that gap as an informational reference. It defines no enforcement runtime,
identity scheme, or payment rail; it defines the attestation a compliant system emits so the
admission decision is auditable after the fact and across providers.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown
here.

- **action_ref**: a collision-resistant identifier for the agent action being attested.
- **authority binding**: the credential, mandate, or capability grant under which the action was taken.
- **verdict**: the admission decision — one of `allow`, `refer`, `deny`, or `no-verdict` (§5).
- **evidence bundle**: the ordered set of inputs the verifier consumed to reach the verdict.
- **evidence_ref**: a resolvable locator (URI or content address) for the evidence bundle.
- **evidence_digest**: an algorithm-tagged hash committing to the evidence bundle (§3.1).

## 3. The Attestation Object

A conforming attestation is a JSON object. Required and optional fields:

| Field | Req | Description |
|---|---|---|
| `action_ref` | MUST | Collision-resistant identifier (e.g. UUIDv4 or a hash-based id). MUST NOT collide across distinct actions |
| `authority` | MUST | Authority binding (mandate id, capability grant, or token reference) |
| `verdict` | MUST | One of `allow` / `refer` / `deny` / `no-verdict` (§5) |
| `evidence_ref` | MUST | Resolvable locator for the evidence bundle (§3.1) |
| `evidence_digest` | MUST | Algorithm-tagged hash over the evidence bundle, e.g. `sha256:<hex>` (§3.1) |
| `verifier` | MUST | Identifier of the component that produced the verdict; SHOULD be bound to a key the auditor can validate |
| `issued_at` | MUST | RFC 3339 [RFC3339] timestamp (see §6 on clock trust) |
| `validity_window` | MAY | `not_before` / `not_after` for time-scoped actions |
| `parent_ref` | MAY | For delegated chains: the `action_ref` this derives from (§6 traversal rules) |

### 3.1. Evidence binding and canonicalization (resolves the reconstructability requirement)

`evidence_digest` MUST be computed over the **evidence bundle** — the inputs the verifier consumed,
serialized as a JSON value and canonicalized per JCS [RFC8785] — NOT over the attestation object
itself. This avoids any circular dependency: the attestation object carries the digest but is not
its input.

`evidence_digest` MUST be algorithm-tagged in the form `<alg>:<hex>` and implementations MUST use
SHA-256 or stronger (`sha256`, `sha384`, `sha512`, `sha3-256`). Weaker algorithms (MD5, SHA-1) MUST
NOT be used; collision resistance is load-bearing for the integrity guarantee in §4.

`evidence_ref` MUST resolve to the exact byte sequence that `evidence_digest` commits to. A content-
addressed locator (where the locator IS the digest, e.g. a CIDv1) satisfies both fields with one value.

## 4. Offline Reconstructability (normative)

An auditor MUST be able to (1) fetch the evidence bundle via `evidence_ref`, (2) confirm it matches
`evidence_digest`, and (3) re-derive the recorded `verdict` from that bundle — all without contacting
the issuing system. An attestation whose bundle is unreachable, whose bundle does not match its
digest, or whose verdict cannot be re-derived from the bundle is non-conforming.

This requirement exists so an admission decision survives an issuing platform that is offline,
compromised, or adversarial — the failure mode shared identity and payment layers do not currently
close.

## 5. The `refer` and `no-verdict` States (normative)

`verdict` distinguishes two non-`allow`/`deny` outcomes that MUST NOT be conflated:

- **`refer`** — an *intentional* deferral to a higher authority or human. A policy outcome, not a
  failure. Consistent with the ALLOW / REFER / DENY admission model used in the agent-security-harness.
- **`no-verdict`** — the admission control could *not reach a decision* within its resource budget
  (timeout, token exhaustion, fault). An operational condition, not a policy choice.

An exhausted control MUST be recorded as `no-verdict` and MUST NOT be silently collapsed into `allow`
(fail-open), `deny` (fail-closed), or `refer`. This guards the guardrail denial-of-service class
[GuardrailDoS], where a control driven past its budget would otherwise be recorded as a clean verdict.

## 6. Security Considerations

- **Hash strength (per §3.1).** A weak `evidence_digest` algorithm lets an attacker substitute a
  colliding evidence bundle. SHA-256+ is mandatory; the algorithm tag preserves agility.
- **Delegation-chain laundering.** `parent_ref` chains MUST be traversed to the root, and the root
  verdict's scope MUST be verified to cover the leaf action; otherwise a legitimate root `allow` can
  launder an unauthorized leaf action. Implementations SHOULD enforce a maximum chain depth.
- **Clock trust.** `issued_at` carries no inherent clock-source assertion; an attester controlling
  its clock can backdate a stale `allow` into a valid `validity_window`. Relying parties that use
  `validity_window` for security SHOULD require a trusted timestamp (RFC 3161 TSA countersignature).
- **Post-issuance revocation.** An attestation is a point-in-time record; it does NOT reflect later
  revocation of the `authority` binding. Relying parties MUST check authority validity independently
  when post-issuance revocation is in scope.
- **Verifier / evidence-provider spoofing.** A forged `verifier` or evidence source can manufacture
  a false `allow`. The attestation SHOULD be signed; the schema is signature-scheme agnostic.
- **Verdict inversion.** Per §5, an exhausted control MUST NOT be recorded as `allow`/`deny`/`refer`.

## 7. IANA Considerations

This document requests no IANA actions in its current form. A future revision MAY request a media
type registration for `application/agent-attestation+json`.

## 8. Relationship to Existing Work

- **OWASP State of Agentic AI Security and Governance v2.01** — this schema supplies the auditable
  record its governance/maturity mapping presumes.
- **Skill Security Protocol (SSP)** — see issue #99; SSP enforcement events can populate this record.
- Descriptive of the open-source agent-security-harness attestation work; does not bind it to any
  third-party framework.

## 9. References

### 9.1. Normative References
- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174.
- [RFC3339] Klyne, G. and C. Newman, "Date and Time on the Internet: Timestamps", RFC 3339.
- [RFC8785] Rundgren, A. et al., "JSON Canonicalization Scheme (JCS)", RFC 8785.

### 9.2. Informative References
- [RFC3161] Adams, C. et al., "Internet X.509 PKI Time-Stamp Protocol (TSP)", RFC 3161.
- [GuardrailDoS] Zhou, Y., Wang, X., et al., "From Shield to Target: Denial-of-Service Attacks on
  LLM-Based Agent Guardrails", arXiv:2606.14517, 2026. (Verify public accessibility before citing
  in a submitted draft.)

## 10. Status / Submission Gate

Working draft staged for review. It MUST NOT be submitted to the IETF Independent Submission stream,
OASIS, or any other body until the author signs off on a final wording and authorship-metadata pass,
at which point the RFC 7841 "Status of This Memo", BCP 78/79 copyright notice, bracketed-anchor
reference toolchain (idnits/xml2rfc), and Author's Address block are added. Recommended venue: IETF
Independent Submission (ISE review, no working-group capture, preserves provider neutrality).

_Revised via strategic-sweep follow-up 2026-06-17 (Move 3, -01). Tracks #137; cross-links #99._
