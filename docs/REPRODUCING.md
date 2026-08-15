# Reproducing this harness, and disagreeing with it

This document exists because the harness has been reproduced independently **once**, in
[#304](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/304), and once is
not a track record. Everything below is written to make the second time cheaper than the
first.

## The commitment

**We will publish a reproduction that contradicts ours, in full, without negotiating it
down first.** If your implementation disagrees with a recorded verdict, that result gets
its own issue, stays open until it is resolved on the merits, and is linked from the
corpus it disputes. If we are wrong, the corpus changes.

This is not generosity. Under
[`docs/EVIDENCE-CLASS-TAXONOMY.md`](EVIDENCE-CLASS-TAXONOMY.md), agreement between two
implementations is **weak** evidence — both may share the same wrong assumption, which is
the I1 row's stated blind spot. **Divergence is the signal.** A project that only
publishes confirmations is measuring whether people agree with it, not whether it is
right.

## What counts as independent, and what does not

| You did | I-level for this harness | Citable as independent |
| --- | --- | --- |
| Wrote a second implementation from the published contract, without reading ours | **I1** | Yes |
| Wrote one after reading our implementation | I0 | No — shared assumptions survive |
| Ran *our* code against *your* target | I0 for you | No |
| Observed via a channel our code does not author | **I2** | Yes, and rarer |

The I-level is **relative to a named system under test**. A result that is I2 for you may
be I0 for us. State the system you are making the claim about, or the level means nothing.

## The reproducible surface

The receipt-claim (RCL) oracle corpus is the piece designed for outside reproduction: it is
a single pinned file, it needs no network target, and it carries acceptance controls so an
implementation cannot pass by rejecting everything.

```bash
git clone https://github.com/msaleme/red-team-blue-team-agent-fabric
cd red-team-blue-team-agent-fabric

# Pin what you consumed, and record the digest you computed yourself.
git rev-parse HEAD
sha256sum fixtures/rcl/rcl-oracle-fixtures.v1.json
```

At the time of writing that file is
`4164151383605d9d68230d81cc9ae1dd31eb5cfb3fb1348289abf71ee64773ea`. **Compute it yourself
rather than quoting this line** — a digest you did not calculate is a claim you are
repeating, not evidence you hold.

The corpus contains nine validly signed receipts a conforming verifier must **reject**, and
two acceptance controls it must **accept**. The controls are the point: a verifier that
rejects everything scores nine out of nine on the reject cases and is worthless.

Contract for what the fields mean:
[`docs/ATTESTATION-REGISTRY-SERVER-CONTRACT.md`](ATTESTATION-REGISTRY-SERVER-CONTRACT.md)
§4.1 pins the canonical byte basis, which is the single most common reason an independent
implementation computes a different digest for material it read correctly.

## What a good report looks like

[#304](https://github.com/msaleme/red-team-blue-team-agent-fabric/issues/304) is the model,
and it is worth being precise about *why*. It matched 11/11 recorded verdicts — and it also
surfaced **two undeclared fixture-contract defects**. Those two are the reason it counted as
evidence. Had it only agreed, it would have established that two implementations shared a
reading.

Use the [Reproduction Report](../../issues/new?template=reproduction-report.yml) template.
It asks for the pinned commit, the digest you computed, how your implementation was
produced, what it actually checks, expected versus actual **including every divergence**,
and a link to artifacts **in your own repository**. We will not vendor your code, and your
report is not a contribution.

## What we will not do

- **Claim your result as validation of the harness.** A reproduction establishes that a
  second implementation read the same corpus the same way. It does not establish that the
  corpus is correct, that any product is secure, or that anything is certified.
- **Quietly fix a divergence and close your issue.** If your finding changes the corpus,
  the change references your report.
- **Ask you to soften a finding.** If the disagreement is real, it is published as you
  wrote it.

## Verifying an attestation you were handed

If someone gives you a published attestation record rather than a corpus, you can check it
offline without trusting whoever served it:

```bash
curl -s "$AGENT_SECURITY_REGISTRY_URL/<id>" \
  | python3 scripts/verify_attestation_record.py -
```

That checks the canonical bytes, the key against its advertised fingerprint, and the
Ed25519 signature. It deliberately does **not** tell you whose key it is — key-to-identity
binding is out of scope, and no registry can supply it. It also prints, after every check
passes, that an I0 record still proves nothing about the target. That last line is the one
readers skip.
