# Evidence-integrity operating rules

Three rules, agreed with the independent reviewer on 2026-09-01 after a review
cycle in which each of them was learned from a specific failure rather than
proposed as principle.

> Every evidence-integrity register must report its derived numerator and
> surveyed denominator; every new detector must prove it can catch a seeded
> violation; every D∩E result is classified by evidence type before it is
> treated as a candidate for change.

Each rule names where it is enforced. A rule with no enforcement point is a
convention, and this repository has watched conventions drift.

---

## 1. A register reports a numerator and a derived denominator

**Enforced by** `testing/test_evidence_integrity_registers.py`.

A register reported as a bare count cannot distinguish two opposite situations:

```text
the debt shrank                 good
the surveyed universe shrank    bad, and reads identically
```

Both look like `7 → 3`.

This repository has produced the second. `KNOWN_DUPLICATES` listed three
instances of a construction; deriving the population from source found **six**,
and three of those sat in a file that had been repaired for the same defect
hours earlier. The queue was a sample drawn by an instrument that shared the
blind spot.

`PREFIX_ONLY` shows it from the other side. Its denominator moved 21 → 28 as
modules gained the structural field and entered the surveyed class, while the
numerator stayed 0. Only the pair is legible.

**The denominator must be derived at call time.** A literal denominator is the
defect this rule exists to prevent.

## 2. A static detector must catch a seeded violation

**Enforced by** `testing/test_static_detectors_can_fire.py`.

A green static scan is not evidence until the detector has been shown to
discriminate. The suppression guard in this repository took three attempts:

- **v1** read raw lines and fired on **prose describing the defect** — including
  the examples in its own helper's docstring. A check that fails on an accurate
  description of what it forbids is a check that gets muted.
- **v2** tokenised and dropped `STRING` tokens, removing the literal the pattern
  needed, and **passed against a deliberately seeded violation**.
- **v3** excludes docstrings and comments by position, and was verified by
  seeding.

Only seeding revealed v2. So every registered detector carries a violation it
must flag **and** a legitimate control it must not — and two of the current
controls deliberately contain prose describing the violation, because that is
what v1 fired on.

## 3. A D∩E result is classified before it is a change candidate

**Written down here**; applied in every review.

Any test ID that passes under **both** shape D (`BLAND_COMPLIANCE`) and shape E
(`NEGATED_REFUSAL_PLUS_HARM`) is **unverified until read**. It is a read
trigger — never a finding, a debt count, or a repair queue.

The instrument has survived external use once: an independent review classified
**45** such IDs and **no guessed-vocabulary defect survived source inspection**.
An earlier application to two modules narrowed seven passes to four candidates,
of which exactly one was a defect. Reported as a count it would have claimed four.

Every such ID resolves to one of four kinds:

| Kind | What it is | Sound? |
|---|---|---|
| **Planted canary** | a value the harness *chose* and looks for exactly — e.g. a fresh `SECRET_TOKEN_<uuid>` planted in one session, sought in another | **Yes**, and fully harness-controlled |
| **Specific artifact** | the exact output the attack *would produce* — `/etc/passwd` content, a forged watermark | **Yes**, but depends on the target's output format |
| **Structural measurement** | status codes, timing, resource state — anything not prose | **Yes**; prose-independence is the point |
| **Guessed vocabulary** | phrases the target *might* use — `"admin_override"`, `"full system access"` | **No.** This is the defect |

The canary and the artifact are both sound and differ in one property worth
keeping visible: **only the canary is fully under the harness's control**, so
only the canary stays sound if the target changes how it phrases things.

All four spell `passed = not <thing>`. Telling them apart is the whole read, and
a rule that flagged every `not <thing>` would have demanded three false repairs
on `a2a_harness` alone.

### A fifth class, reported separately

**`OVER_REFUSAL_EXPECTED`** — recorded in source as `LEGITIMATELY_PERMISSIVE`.

For most families a permissive target accepting the request is concerning. For
over-refusal it is the **desired healthy condition**: the suite exists to detect
a target that refuses too much, so a permissive target passing all 25 is correct.

These must be reported as their own class, not folded into structural
measurement, so that a future reader does not "repair" correct tests. The current
permissive figure reads:

```text
53 passes = 28 read list + 25 declared expected
```

`testing/test_evidence_integrity_registers.py` asserts the split stays declared.

---

## What these rules do not do

They govern how this repository measures itself. They establish nothing about
whether any harness detects a real vulnerability, and they do not move any
evidence class. Independent re-derivation of observable repository properties is
**I0** — it confirms two parties read the same tree the same way.

The RCL fixture corpus is the one bounded area carrying external **I1**
reproduction evidence. The wider test suite does not inherit that status.
