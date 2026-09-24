# interop/

Reproductions of **other projects'** published vectors, run against this harness.

Nothing here is a test of this harness, so nothing here is in `testing/` and nothing
here is counted by `scripts/count_tests.py`. These scripts answer a narrower question:
when an independently built implementation is pointed at someone else's negative
vector, does it return the same verdict for the same reason?

Two rules apply to everything in this directory.

**A reproduction carries a positive control.** A verifier that rejects everything has
reproduced nothing. Each script repairs the one defect the vector encodes, changes
nothing else, and shows the same verifier accepting the repaired artifact.

**Fixtures are read from their author's pinned commit, not vendored.** Several of
these projects publish no LICENSE at all, so there is no explicit permission to
redistribute their artifacts, and adding an unlicensed file to this tree would
misstate the terms it is served under. Each script pins the upstream commit and
records the SHA-256 of the exact bytes, which keeps the author's copy as the
reference artifact while checking that each run uses the bytes the script was written
against. A digest mismatch aborts rather than warns. Running them therefore needs
network access; each takes `--fixture PATH` for offline use.

## Contents

| Script | Vector | Upstream | Verdict |
|---|---|---|---|
| `lumen_scope_binding_repro.py` | CognOS LUMEN v0.1 scope-binding mismatch | [`acprofessionale/CognOS-Constitutional-Engineering-Framework`](https://github.com/acprofessionale/CognOS-Constitutional-Engineering-Framework) @ `c7c4f7d` | REJECT, then ACCEPT on the control |
| `run_external_fixture.py` | Any fixture set, through a pinned checker and an adapter in `adapters/` | Pinned by `--fixture-commit` / `--checker-commit` | Raw per-vector bundle; see [`docs/EXTERNAL-FIXTURES.md`](../docs/EXTERNAL-FIXTURES.md) |

Raised as [#576](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/576).

```
python3 interop/lumen_scope_binding_repro.py
```

`run_external_fixture.py` is the generic form. It takes a fixture directory, a checker and an
adapter, verifies both pins byte-for-byte, and writes `results.json`, `run.log` and
`SHA256SUMS`. A run in which no acceptance control was accepted is labelled NOT A RESULT.
Its positive control is Approval Binding Vectors v0.1.2 reproducing its own published
13/13 with 3 controls accepted; the procedure is in
[`docs/EXTERNAL-FIXTURES.md`](../docs/EXTERNAL-FIXTURES.md).

## Boundary

Two implementations agreeing on one vector is evidence the vector is well-formed. It
is not evidence that either verifier is correct, and it is not validation of this
harness or of the project whose vector is reproduced.
