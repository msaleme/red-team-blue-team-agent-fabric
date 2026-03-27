# OATR Sample Fixtures

These fixtures provide ready-to-use Operator Attestation Registry (OATR) artifacts for the x402 identity verification tests (X4-021 through X4-025).

| File | Contents | Usage |
| --- | --- | --- |
| `manifest.sample.json` | Minimal manifest with two issuers (one active, one revoked) and EdDSA keys | Feed into test harnesses or mock services that expect a signed manifest |
| `revocation.sample.json` | Sample issuer/key revocation list (5-minute TTL semantic) | Use when validating X4-023 behaviors |
| `attestations.sample.json` | Pre-built JWTs covering happy-path, wrong audience, revoked issuer, unknown issuer, and invalid signature scenarios | Useful for local/offline testing of X4-021, X4-022, and X4-025 |

These files are derived from the [Open Agent Trust Registry](https://github.com/FransDevelopment/open-agent-trust-registry) references cited in issue #51. The JWTs are fixture-only: they are syntactically valid and shaped like EdDSA attestation tokens but contain random signatures so they can **never** validate against a real registry. Use them as scaffolding for tests or to illustrate the expected structure when implementing your own generator.

> Tip: Run `python -m protocol_tests.x402_harness --dump-oatr-fixtures` to print all of the bundled fixture data from the CLI.
