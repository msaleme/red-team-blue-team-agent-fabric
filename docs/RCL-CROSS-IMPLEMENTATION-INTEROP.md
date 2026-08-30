# RCL oracle fixtures: a cross-implementation interop result

**Status:** interop data point. Not a standard, not validation of this
repository, not certification, endorsement, or adoption.
**Evidence class:** **E2/I1 for the RCL fixture corpus.** I1 attaches to the
*corpus*, not to the harness: a second implementation reproducing recorded
verdicts establishes that the fixtures encode what they claim to encode. It
establishes nothing about the security of any target, and nothing about the
remaining 608 tests in this repository, which stay I0.

---

## What was measured

A separately written verifier, implemented in Node against the published
fixture format rather than against this repository's Python, was run over a
byte-pinned corpus.

| | |
|---|---|
| Corpus commit | `5e25bc6465ccced079ca6a6b8f54e065a1677a69` |
| Fixture | `fixtures/rcl/rcl-oracle-fixtures.v1.json` |
| Fixture SHA-256 | `0bc47dab20d1c45100f5525a1798fd84df3fd979d1febb2b5fc1c5a69846befb` |
| Primary source | [issue #304](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/304) |

**The digest was recomputed for this note rather than quoted.**
`git show 5e25bc64:fixtures/rcl/rcl-oracle-fixtures.v1.json | sha256sum`
reproduces `0bc47dab…` at that pin.

## Result

11 of 11 recorded verdicts matched, together with claim families, reason
strings, and envelope-validity expectations:

- 9 rejection vectors detected
- **2 acceptance controls preserved** (`RCL-008`, `RCL-009`)
- declared corpus counts reproduced
- `execution_authorized: false`

The second item is the one that carries weight. A verifier that rejected
everything would match 9 of the 11 vectors and be worthless; preserving the
acceptance controls is what distinguishes agreement from a stuck oracle. This
is the same property `testing/test_refusal_establishes_a_pass.py` asserts one
layer up, and the reason a verdict has to be able to be right as well as wrong.

## The corpus has moved since

The fixture on `main` today hashes `41641513…`, not `0bc47dab…`. The
reproduction was performed before [#307](https://github.com/msaleme/red-team-blue-team-agent-fabric/pull/307),
which corrected the fixture's signing-encoding label, and after
[#305](https://github.com/msaleme/red-team-blue-team-agent-fabric/pull/305)
exported the fixtures in versioned form.

**Anyone re-running this against `main` will not reproduce these digests.** The
result is valid for the stated pin and for no other revision. That is the point
of pinning it, and stating it here is cheaper than letting a reader discover it.

## Limits declared by the implementer, preserved verbatim in scope

The reproduction did not cover:

- a negative `integrity_provenance` vector
- a future-dated checker timestamp
- full tool-set exposure (partial only)
- full RFC 8785 canonicalisation (sorted compact JSON was used)

Two limits the cross-evaluation surfaced in this repository's own material were
corrected in #307: the canonicalisation labelling, and freshness coverage that
tested only the stale direction.

## Attribution

**The implementer is not named here.** They published their report themselves,
under their own account, in [issue #304](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/304),
which is public and linked above. A reader who wants to know who ran it can
follow the link.

Permission to cite them by name in a citable artifact was requested on
2026-08-26 with the explicit statement that no obligation was attached, and that
if they would rather not be named, this note would record only that an external
implementation exists. No reply was received. **That is not a refusal and is not
recorded as one.** It is the default branch of a promise that was made when the
question was asked, and it stays available to revise if they would prefer to be
cited.

Citing the public issue is a reference to a public primary source. Naming a
party as a co-signer of one's own claim is a different act and needs their
affirmative agreement, which is why this note does the first and not the second.

## What this does not establish

- Not independent validation of this repository or of any harness verdict.
- Not a security audit, certification, adoption signal, or endorsement.
- Not a claim about any target's security.
- Not a standard. Two implementations agreeing is an interop data point; a
  conformance suite needs more than two and a governance process neither party
  has proposed.
- Not I1 for anything outside the RCL fixture corpus at the stated pin.
