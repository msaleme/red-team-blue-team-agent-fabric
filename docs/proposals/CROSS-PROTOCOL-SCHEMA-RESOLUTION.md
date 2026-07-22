# Cross-Protocol Schema-Resolution Test Family

## Status

Initial fixture layer implemented in `protocol_tests/schema_resolution.py` and
`testing/test_schema_resolution.py`. This family is not a finding against A2A,
MCP, or a particular implementation. It describes consumer-side conformance
and hardening tests prompted by schema-generation defects such as unresolved
relative `$ref` values, draft-keyword inconsistencies, and field-name ambiguity.

## Security boundary

JSON Schema permits external references. An external `$ref` is not, by itself,
evidence that a consumer fetches it or that a vulnerability exists. The security
property under test is the consumer's resolver policy:

> An unresolved schema reference must not cause implicit network, filesystem,
> package-registry, or mutable dependency acquisition.

The control is not merely local canonicalization. Canonicalization does not
establish resource provenance or integrity. Consumers should resolve only from
an allowlisted, locally registered, version-pinned schema set, and fail closed
when a reference is unavailable or not authorized.

## Scope

The same fixtures run against A2A and MCP consumer paths that validate Agent
Cards, task/input artifacts, tool definitions, resource metadata, or other
protocol-declared schemas. A run must identify the consumer being evaluated
(gateway, SDK, receiving agent, or validator library) and the resolver policy
it is expected to enforce.

No live public endpoint should be used as a reference target. Fixtures use a
test-controlled loopback HTTP listener, a test-controlled local file, and a
registered pinned bundle so resolver behavior can be observed directly.

## Test boundaries

### 1. Resolution policy

- **XSR-001 - unresolved HTTP reference:** present an otherwise valid document
  whose `$ref` points to a controlled HTTP listener. Pass when validation fails
  closed without contacting the listener.
- **XSR-002 - unresolved filesystem reference:** present a `file:` reference to
  a controlled sentinel. Pass when validation fails closed without opening the
  sentinel.
- **XSR-003 - mutable registry reference:** resolve an identifier whose content
  changes between validation attempts. Pass only when an allowlisted,
  version-pinned local registration is used and the mutation is not accepted.
- **XSR-004 - self-contained bundle control:** validate the same document as a
  compound Draft 2020-12 schema using local `$defs`. Pass when no external
  acquisition occurs and the document is interpreted consistently.

### 2. Validator differential

- **XSR-005 - draft keyword differential:** run the same fixture through each
  declared validation boundary with `$schema`, legacy `definitions`, and Draft
  2020-12 `$defs` variants. Fail when accept/reject outcomes differ without an
  explicit compatibility policy.
- **XSR-006 - pattern-property differential:** compare gateway, SDK, and
  receiving-agent interpretation of `patternProperties`, `additionalProperties`,
  and explicit properties. Fail when an unrecognized property reaches a
  downstream value despite being rejected or ignored upstream.

### 3. Wire-format ambiguity

- **XSR-007 - equivalent-field collision:** provide camelCase and snake_case
  spellings of one semantic field in the same payload. Pass only when the
  contract rejects the collision or applies one documented, consistent rule.
- **XSR-008 - split-path propagation:** send each spelling independently through
  gateway, SDK, and receiving agent. Fail when equivalent semantic input reaches
  materially different downstream values without an explicit versioned contract.

## Evidence and reporting

Each result records:

- protocol and consumer boundary evaluated;
- schema identifier, allowed registry entry, and immutable version or digest;
- attempted acquisition channel and whether it was actually contacted;
- validator outcome at each boundary and downstream normalized value;
- fixture-only evidence, not an attribution to the protocol specification.

An unexpected external acquisition is a consumer hardening failure. It is not
reported as a protocol vulnerability unless a reproducible, scoped consumer
impact is demonstrated. A validator differential is an interoperability finding
until it demonstrates a security-relevant downstream divergence.

## Recommended publication posture

Generated protocol schemas should be published as self-contained bundles. Until
then, consumers should disable dynamic external `$ref` retrieval and resolve
references only from an allowlisted, locally registered, version-pinned schema
set. Unresolved references should fail closed.
