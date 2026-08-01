# DGB portable corpus bundle

`dgb-corpus-bundle.v1.json` is the Decision Governance Benchmark packaged so
someone outside this project can check it without running, trusting, or even
installing this package.

It exists because the benchmark's own changelog says the most valuable
outstanding check is **independent fixture review**, and that the corpus, both
scanners, the tool fixtures and the grounding audit all share one author. That
is not a check the author can perform. This file is the thing a reviewer needs
in order to perform it.

Regenerate with:

```bash
python -m benchmarks.dgb_bundle_export
```

## What a reviewer can do with this file alone

1. **Read the corpus as data.** All 52 cases, every field, plus the 85
   tool-registry entries that accompany them. No Python import required.
2. **Write an independent scanner** and run it over `cases[].tools`, then
   compare against `cases[].expected_scanner`. Those verdicts are produced by
   executing the two scanners in this repository at export time. They are not
   hand-assigned — a hand-assigned label was exactly the defect that got the
   old `scanner_passes` field retired.
3. **Go straight to the weak cases.** `cases[].grounding` records, per case,
   whether the cited source actually substantiates it. You do not have to
   re-derive that audit to know where the corpus is soft.

## The numbers this bundle does not hide

| | |
|---|---|
| Cases with **full external** evidence fit | **1 of 52** (`DBC-009`) |
| Source located but does **not** substantiate the case | 10 |
| Source could **not** be located | 12 |
| Provisional (source located, no per-case locator established) | 13 |
| Real support but the wording outruns it | 9 |
| Substantiated **but internally authored** | 7 |
| Misdescribed relative to source | 7 |
| Invalid identifier | 1 (`DBC-032`) |
| `executable_test` does not cover the case | 24 of 52 |

The regex metadata scanner flags **1 of 52**. The capability-rule scanner flags
**17 of 52**. Both figures come from execution, and both are in the file.

## Field reference

| Field | Meaning |
|---|---|
| `schema_version` | bundle format version |
| `generated_by` / `source_modules` | what produced this and from where |
| `corpus_release` | the corpus tag these cases correspond to |
| `grounding_audit` | which audit the per-case grounding came from, its date, and the corpus commit it read |
| `counts` | totals, tool entries, and breakdown by category and severity |
| `evidence_fit_distribution` | how many cases fall in each evidence-fit class |
| `record_defect_distribution` | misdescription, invalid identifier, untraceable source, or none |
| `provenance_distribution` | external, internal, untraceable, or mixed |
| `scanner_baseline` | executed detection counts for both scanners |
| `known_limitations` | single-author threat, evidence fit, `executable_test` coverage, record defects, stub-agent configs, and what this bundle is not |
| `scope` / `usage` | what the cases establish, and how to compare a verifier against them |
| `cases[]` | every `BenchmarkCase` field, plus `grounding`, `tools`, `fixture_rationale`, `expected_scanner` |

### `cases[].grounding`

Vocabulary is the audit's own, not a re-coding of it.

- `provenance` — `external`, `internal`, `untraceable`, `untrace+ext`, `untrace+int`
- `evidence_fit` — `full`, `full (internal)`, `partial`, `none`, `provisional`, `unresolved`
- `record_defect` — `misdescription`, `invalid identifier`, `untraceable source`, or `—`
- `note` — the audit's per-case adjudication
- `externally_corroborated` — true only for external provenance **and** full fit

`provisional` means the source was located but a per-case locator was not
established. It is not a finding of support, and it is not a finding of absence.
No case is claimed to have a fabricated source; some sources are uncited and
could not be located.

## Boundaries

This bundle contains no live agent run, no Config D result, and no scoring. The
Config A and Config B figures published elsewhere in this repository come from
deterministic stub agents, not live models; only the scanner arm is measured.

Nothing here is independent corroboration of the corpus. It is the corpus,
its fixtures, its executed scanner verdicts, and an honest account of where its
grounding is thin — assembled so that someone else can supply the corroboration
it does not have.

If you review this and find something wrong, a technical correction is the most
useful thing you can send. The last time an outside reviewer did that for the
receipt-claim fixtures, they found a real specification defect in the first
pass.
