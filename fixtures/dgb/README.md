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

**Read the currency note first.** The grounding audit read the corpus on
2026-07-26 at commit `6c5d617`. A remediation pass landed the next day and
revised **25 of 52** source fields. The table below is therefore *as audited*,
not *as it stands*. Every case reports `source_revised_since_audit`, and the
bundle's `grounding_currency` block gives the split.

| As audited on 2026-07-27 | Cases |
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

| Currency | Cases |
|---|---|
| Source text **unchanged** since the audit — verdict still describes what you are reading | 20 |
| Source text **revised** after the audit, then **re-adjudicated** on 2026-08-02 | 24 |
| **Repaired** because the audit's finding was accepted | **8** |
| Carrying a defect verdict **and** still unrevised | **0** |
| Revised but never looked at again | **0** |

**Read those last rows together.** The zero is not "nothing was wrong". Eight
cases cited a published source that does not cover them; the citations were
withdrawn. Seven — `DBC-014`, `DBC-016`, `DBC-031`, `DBC-038`, `DBC-039`,
`DBC-040`, `DBC-044` — lost every form of support and now read
`Author-constructed: no external source located …`. The eighth, `DBC-026`, lost
only the external half of a compound citation and still rests on an internal run.

Repair here means **a false claim was removed, not that support was found.**
`grounding.provenance` still reads as the audit transcribed it, because that is a
record of the claim as it stood; `grounding.provenance_after_repair` records what
is true now.

## Re-adjudication (2026-08-02)

The audit read the corpus at `6c5d617`. A remediation pass landed the next day
and revised 25 source fields, so for half the corpus the recorded verdict
described text that no longer existed. Those 25 have now been re-read against
their **current** wording, and where that wording names an external source, the
source itself was re-fetched rather than trusting the audit's transcription.

| After re-adjudication | Cases |
|---|---|
| `external — verified` — source re-read, current text supported by it | 8 |
| `internal — unpublished` — rests on an internal run whose data is not published | 12 |
| `internal — inspectable` — rests on an artifact present in this repo | 3 |
| `external — partial` — source supports the class, not the case's specifics | 2 |
| `none — outstanding` — a defect still live after this pass | 0 |

`outstanding` is empty, and `found_defective_by_this_pass` names `DBC-026` — one
defect found and repaired inside this pass. Those two fields are reported
together on purpose: an empty outstanding list on its own reads as *we looked and
found nothing*, which is the opposite of what happened.

Sources re-read: [Berkeley RDI](https://rdi.berkeley.edu/blog/trustworthy-benchmarks/),
[OX Security](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/),
[CVE-2026-35625](https://nvd.nist.gov/vuln/detail/CVE-2026-35625),
[CVE-2026-35629](https://nvd.nist.gov/vuln/detail/CVE-2026-35629),
[METR](https://metr.org/blog/2025-06-05-recent-reward-hacking/),
[AI Incident Database 1442](https://incidentdatabase.ai/cite/1442/).

Two cases the audit had left *provisional* purely for want of a locator —
`DBC-007` (Kiro/Amazon) and `DBC-050` (METR) — are now verified against the
source and carry one. Every case marked `external — verified` names a URL or CVE
you can follow; a test enforces that, because "verified" with nothing to check is
just a stronger word for "asserted".

**`DBC-026` is the finding this pass produced that the currency machinery could
not.** Its source cited an internal run *and* OX Security. Revising the internal
half changed the case's source digest, which marked the whole case "revised" and
moved it out of the flagged bucket — while the OX half sat untouched and
disproved. A compound citation defeats a per-case digest. Re-reading the advisory
confirmed it does not cover cross-agent or cross-session memory contamination,
and the external half is now withdrawn.

**This pass was performed by the corpus author. It is not independent review and
does not discharge the single-author limitation.** What it changes is that every
verdict now points at a named, fetchable locator instead of asking you to accept
an unexamined "stale". A revision is still not evidence of a verified repair —
but you can now check which is which.

## Does the named harness test actually cover the case?

Every case carries `executable_test`, and that field has never claimed the named
test *exercises* the scenario. `cases[].executable_test_link` now makes the gap
measurable instead of leaving it as a sentence in the limitations block. It is
resolved against `protocol_tests/` at export time — deliberately not against
`HARNESS_TEST_CATALOG.md`, which is a dated extract and would reintroduce the
staleness the check exists to detect.

| Linkage | Cases |
|---|---|
| Names a resolvable test id | 49 of 52 |
| Names something else entirely (a harness, or several ids) | **3** — `DBC-034`, `DBC-035`, `DBC-052` |
| Names a test whose OWASP ASI category disagrees with the case's | **17** |

A disagreeing category is a reason to check the mapping, not a finding on its
own: a case can legitimately map to a test filed under a different heading. What
the number does establish is that this link was never machine-verified. Some of
the disagreements are stark — `DBC-016` is a cross-agent prompt injection relay
pointing at `MCP-015`, *SSRF via URI Parameter*. If you are looking for somewhere
to push, `executable_test_link` is the field with the least prior scrutiny.

The regex metadata scanner flags **1 of 52**. The capability-rule scanner flags
**17 of 52**. Both figures come from execution against the current corpus, and
both are in the file.

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
| `grounding_currency` | the three-way split: as-audited, revised, repaired — and how many defect verdicts are still live |
| `executable_test_linkage` | whether each case's named harness test resolves, and where its OWASP category disagrees |
| `cases[]` | every `BenchmarkCase` field, plus `grounding`, `executable_test_link`, `tools`, `fixture_rationale`, `expected_scanner` |

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
