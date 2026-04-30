# JCS Byte-Match Conformance

Independent byte-match verification of the CTEF v0.3.1 substrate referenced in
[a2aproject/A2A#1786](https://github.com/a2aproject/A2A/issues/1786).

## What this is

A reproducible test that pulls three published JSON Canonicalization Scheme
(RFC 8785) fixture sources, runs them through a clean-room canonicalizer
(`trailofbits/rfc8785.py`), and compares the resulting canonical bytes and
SHA-256 to the values the fixture authors publish.

A match means an independent verifier confirms the canonicalizer substrate.
A divergence is a finding — silent passes from shared canonicalizer code
are exactly what the byte-match is meant to catch.

## What this is not

Full A2A spec verifier conformance. This covers only the JCS canonicalizer
layer — the prerequisite for everything downstream (verdict composition,
delegation chain root, claim_type-tagged compliance). Those are separate
modules.

## Sources covered

| Source | Vectors | Bytes published? |
|---|---|---|
| AgentGraph CTEF v0.3.1 inline (`agentgraph.co/.well-known/cte-test-vectors.json`) | 4 | yes (UTF-8) |
| APS bilateral-delegation (`aeoess/agent-passport-system/fixtures/bilateral-delegation/canonicalize-fixture-v1.json`) | 10 | yes (hex) |
| APS rotation-attestation (`aeoess.com/fixtures/rotation-attestation/`) | 5 | no (SHA-256 only) |

Total: 19 vectors.

## Run

```bash
pip install -r tests/jcs/requirements.txt
python tests/jcs/run_bytematch.py
```

Exits 0 if all vectors match, 1 otherwise. Fixtures are fetched live and
cached under `tests/jcs/.fixtures/` on first run. Delete the cache to refetch.

## Result as of branch creation

19/19 PASS. Canonicalizer: `rfc8785` v0.1.4. The four AgentGraph and ten APS
bilateral-delegation vectors reproduce byte-exact; the five APS
rotation-attestation fixtures (which publish only SHA-256, not bytes) reproduce
SHA-256-exact.

## Why a clean-room canonicalizer matters

Per @aeoess in [a2aproject/A2A#1672](https://github.com/a2aproject/A2A/issues/1672):

> Three harnesses that would all silently pass if they shared a canonicalizer
> implementation are worth one harness that catches the drift.

`rfc8785.py` is published by Trail of Bits and has no implementation overlap
with AgentGraph, APS, AgentID, Nobulex/crypto, or HiveTrust. Independent
agreement against the fixtures is meaningful precisely because the
canonicalizer was written without reference to any of them.
