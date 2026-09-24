# Running someone else's fixtures, and publishing what the checker returned

**Status:** procedure. `interop/run_external_fixture.py` runs an externally published
fixture set through a pinned checker and writes a result bundle: raw per-vector output,
the run environment, and SHA-256 digests of every input and output. It reports. It does
not interpret, certify or endorse.

## What a bundle claims, and what it does not

It claims one thing per vector: **the outcome the fixture's author declared, and the
outcome the named checker, at the named revision, actually returned**, with the checker's
own output kept verbatim beside it.

It does not claim:

- that the checker is correct. Agreement between a fixture and a checker is evidence that
  the two read the property the same way. Both can be wrong in the same direction
  ([`REPRODUCING.md`](REPRODUCING.md), I1 row).
- that the fixture is correct. A `fail` row is a disagreement. Which side is wrong is left
  to a reader.
- anything about the fixture author's protocol. A bundle is not a certification,
  endorsement or validation of any protocol, product or project, and must not be cited as
  one. `results.json` carries that sentence in its `claims` field so it travels with the
  numbers.

## Per-vector states

The four states follow [`RESULT-SEMANTICS.md`](RESULT-SEMANTICS.md). The runner uses
`inconclusive` where other tools say "indeterminate".

| State | Means | Counted as a pass |
|---|---|---|
| `pass` | The checker's verdict equals the declared verdict, and, for a rejection that declares a reason, its reason equals the declared reason. | yes |
| `fail` | The checker returned a different verdict, or the same verdict for a different declared reason. | no |
| `inconclusive` | No comparison was possible: the vector declares no expected outcome, or the checker gave no readable verdict, or the fixture declares a reason and the checker reports none. | no |
| `error` | The instrument failed: the checker crashed, timed out or printed nothing readable, the vector would not parse, or the checker's own report of its result contradicts the runner's comparison. | no |

Comparison is exact string equality after lowercasing. The runner does not treat `ALLOW`
as `accept` or map one reason vocabulary onto another. Where a mapping is needed it lives
in the **adapter**. That is a separate file, and its SHA-256 goes into the bundle, so a
reader can see the mapping and dispute it.

`--verdict-only` compares verdicts and records declared reasons without comparing them.
The summary then says `compared on verdict-only`, so a reader can see how much was checked.

## Positive controls: when a run is not a result

A vector whose declared verdict is an acceptance (`accept` or `allow` by default; an adapter
may set `ACCEPT_VERDICTS`) is a **positive control**. The summary states how many were
declared and how many were accepted. Two cases are labelled **NOT A RESULT**, exit 2,
whatever the negative vectors did:

- the fixture declares no positive control;
- none of the declared controls was accepted.

A checker that rejects everything passes every negative vector ever written. This is the
rule [Approval Binding Vectors](https://github.com/msaleme/approval-binding-vectors) states
in its own `check.py`: a run with 0 controls accepted is not a result.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | A result; every vector `pass`. |
| 1 | A result; at least one vector is `fail`, `inconclusive` or `error`. |
| 2 | NOT A RESULT (see above). A bundle is still written. |
| 3 | Aborted before running: a pin did not match, or `--out` is not empty. No bundle. |
| 64 | Usage error. |

## Pinning the checker and the fixtures

```
--checker-commit REV   refuse unless the checker file is byte-identical to its copy at REV
--fixture-commit REV   refuse unless every fixture file is byte-identical to its copy at REV
```

The check is **byte identity with the pinned revision**. It is not "HEAD equals the pin",
because a checker inside this repository is normally read from a later HEAD. A mismatch
aborts; it never warns. `REV` may be a tag. The bundle records the resolved commit.

A pin covers the named file. If the checker imports other code from its repository, that
code comes from what is on disk. To make that visible, the bundle lists every file in the
checker's repository that differs from the pin (`checker.pin.repo_files_changed_since_pin`).
For the strongest pin, run from a checkout at the pinned commit.

Without a pin, the log prints `NOT PINNED` and the bundle records the repository HEAD and a
dirty flag.

## Adapters

The runner never parses a checker's output itself. An adapter is a Python file that defines:

```python
ADAPTER_ID = "..."                      # recorded in the bundle
ACCEPT_VERDICTS = frozenset({"accept"}) # optional; which declared verdicts are controls

def run(checker: Path, vector_path: Path, timeout: float) -> dict:
    # returns {"observed": {"verdict": str, "reason_code": str | None} | None,
    #          "raw": {...verbatim argv, exit_code, stdout, stderr...},
    #          "error": str | None,
    #          "self_report": "pass" | "fail" | None}   # optional second opinion

def expected(vector: dict) -> dict | None:  # optional; default reads vector["expect"]
def vector_id(vector: dict, path: Path) -> str:  # optional; default vector["id"] or stem
```

`interop/adapters/abv_reference.py` is the reference adapter. It runs ABV's `check.py` twice
per vector, each time in a fresh subprocess. The first call is `verify()`, which gives the
verdict and predicate. The second is the checker's CLI, which prints its own `PASS`/`FAIL`
against the fixture. If the two instruments disagree the row is `error`; the runner cannot
tell which one is wrong.

For a checker built on this harness's own models, such as `ClaimLevelVerifier` in
`protocol_tests/receipt_claim_harness.py`, the adapter has to transliterate each vector
onto the harness record shape, as `interop/lumen_scope_binding_repro.py` does. That mapping
is interpretation. Keep it in the adapter, keep it small, and state in the published result
that the mapping is yours.

## The bundle

```
results.json   run metadata, per-vector rows (expected, observed, raw, state, why), summary
run.log        the same, as plain text; also printed to stdout
SHA256SUMS     inputs/fixtures/*, inputs/checker/<file>, inputs/adapter/<file>,
               results.json, run.log
inputs/...     only with --copy-inputs
```

`results.json` also records the start and finish time in UTC, the Python version and
executable, the platform, and the harness commit with a dirty flag.

Verify a bundle:

```bash
sha256sum -c --ignore-missing SHA256SUMS      # outputs, and inputs if copied
```

Without `--copy-inputs`, the `inputs/` lines are checked against the fixture author's own
pinned copy. Do this by fetching it at the pinned commit and comparing digests. **Only pass
`--copy-inputs` when the fixture's licence permits redistribution.** Several projects
publish no licence. This is the same reason `interop/` reads fixtures from their author's
commit and does not vendor them.

## Positive control for the runner itself: ABV v0.1.2

Approval Binding Vectors, tag `v0.1.2`
([commit](https://github.com/msaleme/approval-binding-vectors/commit/50c64293c12d99f15de65626124006fd81aaba17)),
publishes 13 vectors (10 negative, 3 acceptance controls) and a reference `check.py` that
reports `13/13 vectors behaved as specified` with 3 controls accepted. The runner has to
reproduce that before its output on anything else means anything:

```bash
git clone https://github.com/msaleme/approval-binding-vectors ../approval-binding-vectors
python3 interop/run_external_fixture.py \
    --fixtures ../approval-binding-vectors/vectors --fixture-commit v0.1.2 \
    --adapter interop/adapters/abv_reference.py \
    --checker ../approval-binding-vectors/check.py --checker-commit v0.1.2 \
    --out /tmp/abv-run
```

```
13/13 vectors: observed outcome matches the fixture's declared expectation
  fail 0, inconclusive 0, error 0; compared on verdict and declared reason
acceptance controls: 3 of 3 declared were accepted
RESULT (raw; not a certification of the checker, the fixture, or the fixture author's protocol)
```

`testing/test_external_fixture_runner.py` runs the same reproduction offline. It uses a copy
of the v0.1.2 files vendored under `testing/fixtures/abv-v0.1.2/`. ABV is MIT and its licence
is copied alongside. The copy is pinned to the upstream `SHA256SUMS`. The same file holds the
negative controls: an altered expectation, an accept-everything checker, a reject-everything
checker, a crashing checker, a checker whose self-report contradicts its verdict, a missing
expectation, a missing reason, a corpus with no controls, and a pin mismatch. Each one must
come out as `fail`, `inconclusive`, `error`, NOT A RESULT or ABORTED, and never as a pass.

## Publishing a result

1. Pin both sides: `--fixture-commit` to the commit or tag the fixture author published, and
   `--checker-commit` to the revision you said you would run.
2. Run once. Do not re-run until the numbers look better. If you re-run, publish every
   bundle.
3. Publish the bundle unedited, with `run.log` quoted in full or linked. Report `fail`,
   `inconclusive` and `error` rows with the same weight as `pass`, and report the control
   count first.
4. If an adapter did any mapping, say so in the same place as the result.
5. Invite the fixture author to rerun it. The bundle names every commit and digest needed to
   do so.
