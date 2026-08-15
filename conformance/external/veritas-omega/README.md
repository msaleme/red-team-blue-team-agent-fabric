# Independent verification of an external contract: VERITAS Omega

This directory is **not** part of the harness. It is evidence: an independent
implementation of somebody else's published verification contract, kept here because it is
one of the recorded instances of the defect class described in
[`docs/VERIFICATION-DESIGN-DEFECT.md`](../../../docs/VERIFICATION-DESIGN-DEFECT.md).

**Subject:** [VrtxOmega/veritas-agent-trust-lab](https://github.com/VrtxOmega/veritas-agent-trust-lab),
*Break VERITAS: External Verification Challenge v1*, track `independent-result-recomputation`,
baseline `0f3c71fdb0e9078d8a5d8684411d0318fe600bb1`.

**Result:** full agreement — 12 cases, 48 decision fields, 14 SHA-256 digests, zero
divergences.

**Finding:** the track's pass condition cannot detect a canonicalisation divergence. Every
decision derives from a digest *inequality*, which holds whenever inputs differ regardless of
how they were serialised. An implementation with a wrong `canonicalize` still produces all
twelve correct decisions. Demonstrated, not asserted: see `REPORT.md`.

**Independence:** Python 3 standard library only, against a JavaScript / Web-Crypto reference.
Nothing from the reference is imported, called, wrapped, transpiled, or vendored by
`verify_veritas.py`.

```bash
python3 verify_veritas.py --json result-artifact.json
```

**Reciprocity, disclosed.** VrtxOmega independently reproduced this project's RCL oracle
corpus in issue #304 — the only external reproduction this project has received. This work
was done in return, and that relationship is disclosed in the submitted report rather than
left to be discovered.

Their code is not vendored here. Nothing in this directory claims their contract is correct,
certifies their system, or is endorsed by them.
