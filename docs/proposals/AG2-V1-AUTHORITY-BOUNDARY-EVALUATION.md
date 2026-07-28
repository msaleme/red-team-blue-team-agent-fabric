# AG2 v1 Authority-Boundary Evaluation Proposal

## Status

Content-frontier and shallow-adapter proposal only. Tracked by harness issue
#288. No AG2 product behavior has been tested, and this document does not
assign harness test identifiers or make a vulnerability claim.

## Version gate

The target must be a publicly verifiable, stable AG2 v1 release with immutable
package and source provenance. The public AG2 release page observed on
2026-07-26 listed `v1.0.0b0` as the latest release and described it as a beta.
Consequently, do not use an announcement alone as evidence of a v1.0.0 GA
target. If a stable target cannot be confirmed, close this proposal as
unready rather than testing an ambiguous moving target.

This follows the harness scope decision in issue #214: a newly stable protocol
surface may justify a thin adapter, but it does not justify a speculative new
test family.

## Purpose

Determine whether existing protocol- and authority-boundary evaluation patterns
can run against an authorized local AG2 deployment through a thin adapter. The
goal is portability evidence for the harness, not vendor-specific coverage or
external promotion.

## Work packages

### 1. Target provenance and minimal local deployment

- Record package version, immutable source revision, dependency lock, supported
  protocols, and configuration.
- Run only an authorized local target using non-sensitive fixtures.
- Establish positive and negative controls before adversarial inputs.

### 2. ACP delegated-authority boundary

- Identify the authority presented when AG2 drives a CLI coding agent.
- Check that a task cannot inherit workspace, shell, file, or approval scope
  from an unrelated task or profile.
- Check cancellation, retry, and resume behavior for authority persistence.

### 3. MCP gateway and deferred tool discovery

- Apply existing tool-description and capability-boundary patterns to the
  gateway and server-side search path.
- Check whether deferred loading changes authorization, provenance, or
  disclosure of a tool's declared capabilities.
- Treat tool metadata as untrusted input; do not test external services.

### 4. Assistant profile, folder-grant, and scheduled-task isolation

- Verify profile-to-profile separation of file grants, memory, configured MCP
  servers, and scheduled-task state.
- Verify revocation and post-restart behavior with synthetic fixtures.
- Keep observability records scoped so traces do not disclose fixture contents
  or credentials.

## Acceptance gates

An implementation PR requires all of the following:

1. Stable target provenance captured.
2. Authorized local reproducibility with positive and negative controls.
3. Existing harness measurement model maps cleanly without inventing a new
   protocol family or test-count claim.
4. Evidence record states whether a result is configuration-specific,
   runtime-specific, or generalizable.
5. Independent review of claim language before any public statement.

## Explicit non-goals

- No AG2-repo issues, comments, or promotional replies.
- No live-account, third-party, or production-system testing.
- No installation of third-party skill packages without separate supply-chain
  provenance review.
- No claim that a permission-first design is secure until the target and
  controls are actually characterized.
