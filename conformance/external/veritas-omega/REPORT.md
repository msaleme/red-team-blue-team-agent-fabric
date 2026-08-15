# Independent verification of the VERITAS Omega public contract

**Challenge:** Break VERITAS: External Verification Challenge v1
**Track:** `independent-result-recomputation`
**Baseline:** `0f3c71fdb0e9078d8a5d8684411d0318fe600bb1`

## Artifact hashes (rule 1)

Recomputed locally at the pinned commit; all three match the declared table.

```
lib/trust-engine.js              60c8d7e26fa0a352401b391015618c56b9be39d59c4b7cc4d5b24ec3f8d726c2  OK
public/verification-packet.json  87ff8f3784f7509e05ae19bc8f72236f061bff32ce79777c65343ac56609b54f  OK
lib/challenge-receipt.js         21b8f565ee6155b7eec93e3fa490506f66453cfed7fb2b3c19eea8d4f0f4229e  OK
```

## Implementation separation (rules 2, 3)

`verify_veritas.py` is a from-scratch implementation in **Python 3, standard library only**,
against a JavaScript / Web-Crypto reference. Nothing from `lib/trust-engine.js` is imported,
called, wrapped, transpiled, or vendored by it. The reference source was read, which rule 3
permits.

## Result

12 evaluations: 6 positive controls (CLEAN) and 6 hostile cases (TAMPERED).

| | |
|---|---|
| Positive controls, all ALLOW | 6/6 |
| Hostile cases, all BLOCK or REVOKED | 6/6 |
| Required result fields present on all 12 | yes |
| `execution_authorized` false everywhere | yes |

Compared against the reference engine, used **only as a comparison oracle** and not by the
submitted implementation:

```
cases compared            : 12
decision fields compared  : 48
SHA-256 digests compared  : 14   matched: 14
total divergences         : 0
```

## Finding: the track's pass condition cannot detect a canonicalisation divergence

Canonicalisation affects the track's 14 packet digests. Where a decision compares digests,
both operands come from the same canonicaliser, so a consistently wrong implementation
preserves their equality or inequality. In the other case families the decision does not
depend on canonicalisation at all: `forged-verdict` compares claimed and recomputed states,
`nonce-replay` checks prior consumption, `correlated-quorum` counts independent groups, and
`silent-monitor` compares heartbeat age against a TTL.

Either way, an implementation that gets `canonicalize` wrong still produces all twelve
correct decisions.

Demonstrated by re-running the implementation with a deliberately wrong canonicalisation
(pretty-printed rather than `JSON.stringify`'s compact separators, the single most likely
error an independent implementer makes):

```
decision-field divergences from the correct run : 0    <- all 12 cases still decide identically
digest divergences                              : 14   <- every digest is wrong
```

The `packet` digests are the only outputs that catch it. `required_result_fields` includes
`packet`, but the protocol does not state that the digest values inside it must be compared,
so a submission could satisfy the stated criteria while having reproduced none of the
serialisation contract.

This is the same shape as the challenge's own rule 5 — a verifier that rejects everything has
not reproduced the contract — applied one level up: a verifier that decides everything
correctly has not necessarily reproduced the contract either.

**Suggested fix:** require the `packet` digest values in the submitted artifact and compare
them, or add one case whose decision depends on a digest *equality* against a fixed expected
value rather than on an inequality between two computed ones.

## Untested boundaries

- Tracks 2 (`action-boundary-mutation`) and 3 (`monitoring-and-revocation`) were not attempted.
- The browser UI, blind-challenge sealing, local label storage, and `challenge-receipt.js`
  were not exercised.
- No claim is made about the V4 kernel, which the challenge excludes.
- Nothing was executed against any hosted system. `execution_authorized` is false and was
  respected.

## Disclosures

- No compensation, no commercial relationship, no reused code, no shared dependencies
  (standard library only).
- **Prior interaction:** I maintain `msaleme/red-team-blue-team-agent-fabric`. VrtxOmega
  independently reproduced that project's RCL oracle corpus in its issue #304. This
  submission is reciprocity for that, and should be weighed knowing it.
- **AI assistance:** implementation, analysis, and this report were produced with Claude.
- The reference engine was executed once under Node 22 to obtain comparison values. The
  submitted implementation does not invoke it.
