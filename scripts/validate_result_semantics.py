#!/usr/bin/env python3
"""Fail when the predeclared result semantics are absent, malformed, or drifted.

## Why this exists

An external-auditor requirement reads: *PASS / FAIL / INCONCLUSIVE defined BEFORE
running; an inconclusive result must never aggregate into PASS.*

The second half is now expressible. `schemas/attestation-report.json` carries
`inconclusive` in its result enum, `generate_attestation_report` counts it in its
own bucket and emits that bucket at zero, and `run_summary()` computes rates over
`serviced` rather than `total`. What was still missing is the FIRST half. The
meaning of each outcome lived in docstrings, in a taxonomy document, and in the
shape of four helper functions -- all of it correct, none of it a thing a reader
could point at and say *this was fixed before the run*.

Semantics recovered from prose after the fact are semantics the author can adjust
after seeing the numbers. That adjustment does not feel like misconduct while it
is happening; it feels like clarifying what a bucket always meant. This repository
has the measured version of the same move at the aggregation step, where
`failed = total - passed` silently redefined "the control did not hold" to mean
"we did not observe it holding" (#402), and at the serialization step, where
`"pass" if r.get("passed") else "fail"` did it again on the way out the door
(#404).

`docs/result-semantics.json` is the declaration. This script is what makes it a
constraint rather than a document.

## What it checks

    SCHEMA       The declaration validates against schemas/result-semantics.schema.json.
    INVARIANTS   Every required invariant is present, names an executable check
                 here, and that check passes against the outcomes table.
    DRIFT        The declared outcome names are exactly the attestation schema's
                 `result` enum, and every declared bucket exists in the report
                 summary. Two vocabularies for one set of states is how the third
                 state was lost the first time.

## Exit codes

    0   valid
    1   invalid -- a declared meaning is missing, malformed, violated, or drifted
    2   could not check -- the declaration, the schema, the attestation schema, or
        `jsonschema` is unavailable

2 is deliberately not 0. "The mechanism did not run" reported as success is the
defect class this repository tracks; `validate_attestation_report` had exactly
that bug until #384 (a missing `jsonschema` returned an empty error list, so "no
errors" meant either "validated" or "nothing validated it").

## What this does not establish

That any run honored these semantics. This checks that the declaration exists, is
internally consistent, and agrees with the serialization vocabulary. Whether a
given module classifies a given response correctly is a different question,
answered by testing/test_serviced_guard.py, testing/test_refusal_establishes_a_pass.py
and tests/test_attestation_can_say_inconclusive.py.

## Usage

    python3 scripts/validate_result_semantics.py
    python3 scripts/validate_result_semantics.py --declaration path/to/other.json
    python3 scripts/validate_result_semantics.py --json

## From an installed copy

The two schemas are resolved through `protocol_tests.package_data` and are in
the wheel. The default declaration, `docs/result-semantics.json`, is
checkout-only: without `--declaration` an installed copy exits 2 with one line
saying so (never a traceback, never a pass).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.package_data import data_path  # noqa: E402

#: Checkout-only default (not in the wheel); see "From an installed copy".
DECLARATION = REPO_ROOT / "docs" / "result-semantics.json"
SCHEMA = data_path("schemas", "result-semantics.schema.json")
ATTESTATION_SCHEMA = data_path("schemas", "attestation-report.json")

OK, BAD = "PASS", "FAIL"

EXIT_VALID, EXIT_INVALID, EXIT_CANNOT_CHECK = 0, 1, 2

#: Invariants that must be present in any declaration this repository ships.
#:
#: Listed here rather than only in the JSON so that DELETING an invariant is a
#: failure. A declaration that can be weakened by removing a line from it is not a
#: constraint; the auditor requirement names the first of these explicitly, and
#: the other four are the conditions under which the first can be satisfied on
#: paper and violated in the arithmetic.
REQUIRED_INVARIANTS = (
    "inconclusive-never-aggregates-into-pass",
    "inconclusive-is-not-a-fail",
    "absence-of-observed-attack-is-not-a-pass",
    "denominator-excludes-unserviced",
    "buckets-partition-total",
)

#: Buckets that exist in run_summary() but not in the attestation report summary.
#:
#: `serviced` is the rate denominator and is emitted in-process; the attestation
#: summary does not carry it. Allowing it explicitly, rather than loosening the
#: drift check, keeps the check able to reject a bucket name that is simply a typo.
RUN_SUMMARY_ONLY_BUCKETS = frozenset({"serviced"})


class CannotCheck(Exception):
    """A precondition for checking is missing. Never reported as valid."""


def _load(path: Path, what: str) -> dict:
    if not path.is_file():
        raise CannotCheck(f"{what} not found at {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise CannotCheck(f"{what} at {path} is not valid JSON: {exc}") from exc


# ---------------------------------------------------------------------------
# Executable invariant checks
# ---------------------------------------------------------------------------
#
# Each takes the declaration and returns a list of violation strings. The names
# are the `check` values in the declaration, so an invariant cannot be declared
# without naming the code that enforces it, and code cannot enforce an invariant
# nobody declared.


def _by_name(declaration: dict) -> dict[str, dict]:
    return {o["name"]: o for o in declaration["outcomes"]}


def check_inconclusive_never_aggregates_into_pass(declaration: dict) -> list[str]:
    """The auditor requirement, stated against the aggregation table.

    Two ways to violate it and both are checked, because closing one alone leaves
    the outcome reachable: the bucket list can name `passed`, or the numerator
    flag can be set while the bucket list stays honest.
    """
    out = []
    o = _by_name(declaration).get("inconclusive")
    if o is None:
        return ["no `inconclusive` outcome is declared at all"]
    agg = o["aggregation"]
    if "passed" in agg["summary_buckets"]:
        out.append("inconclusive declares that it increments the `passed` bucket")
    if agg["pass_numerator"]:
        out.append("inconclusive declares pass_numerator: true")
    return out


def check_inconclusive_is_not_a_fail(declaration: dict) -> list[str]:
    """`failed` must be counted, never residual.

    Checked both directly (inconclusive must not name the bucket) and structurally
    (`fail` must be the only outcome that does), because `failed = total - passed`
    is expressible as a declaration in which nothing names `failed` at all.
    """
    out = []
    outcomes = _by_name(declaration)
    inconclusive = outcomes.get("inconclusive")
    if inconclusive is None:
        return ["no `inconclusive` outcome is declared at all"]
    if "failed" in inconclusive["aggregation"]["summary_buckets"]:
        out.append("inconclusive declares that it increments the `failed` bucket")
    owners = [n for n, o in outcomes.items()
              if "failed" in o["aggregation"]["summary_buckets"]]
    if owners != ["fail"]:
        out.append(f"the `failed` bucket must be incremented by `fail` alone, got {owners!r}")
    return out


def check_absence_of_observed_attack_is_not_a_pass(declaration: dict) -> list[str]:
    """A pass must require a positive observation; the absence outcomes must not.

    The second half matters as much as the first. A declaration that marked every
    outcome `observation_required: true` would satisfy the letter of the rule and
    describe a harness that cannot report an unreachable target.
    """
    out = []
    outcomes = _by_name(declaration)
    p = outcomes.get("pass")
    if p is None:
        return ["no `pass` outcome is declared at all"]
    if not p["observation_required"]:
        out.append("pass declares observation_required: false, so it may be reached "
                   "from the absence of a detected attack")
    for name in ("inconclusive", "error", "skip"):
        o = outcomes.get(name)
        if o is not None and o["observation_required"]:
            out.append(f"{name} declares observation_required: true, which makes the "
                       f"unobserved case unreportable")
    return out


def check_denominator_excludes_unserviced(declaration: dict) -> list[str]:
    """Per-outcome flags and the declared exclusion list must agree.

    Cross-checked in both directions so the two cannot drift: an outcome that is
    not serviced must be out of the denominator, and the `excluded_outcomes` list
    must be exactly the set of such outcomes rather than a hand-maintained
    approximation of it.
    """
    out = []
    outcomes = _by_name(declaration)
    for name, o in outcomes.items():
        agg = o["aggregation"]
        if not agg["counts_as_serviced"] and agg["rate_denominator"]:
            out.append(f"{name} is not serviced but declares rate_denominator: true")
        if agg["counts_as_serviced"] and not agg["rate_denominator"]:
            out.append(f"{name} is serviced but is excluded from the rate denominator")
        if agg["counts_as_serviced"] and "serviced" not in agg["summary_buckets"]:
            out.append(f"{name} counts as serviced but does not increment the "
                       f"`serviced` bucket")
    declared_excluded = set(declaration["rate_denominator"]["excluded_outcomes"])
    actual_excluded = {n for n, o in outcomes.items()
                       if not o["aggregation"]["counts_as_serviced"]}
    if declared_excluded != actual_excluded:
        out.append(f"rate_denominator.excluded_outcomes is {sorted(declared_excluded)} "
                   f"but the per-outcome flags say {sorted(actual_excluded)}")
    when_empty = declaration["rate_denominator"]["when_empty"]
    if "null" not in when_empty.lower():
        out.append("rate_denominator.when_empty does not say the rate is null when "
                   "nothing was serviced. A rate of zero is a claim; absence is not.")
    return out


def check_buckets_partition_total(declaration: dict) -> list[str]:
    """Every outcome increments `total` and exactly one counting bucket.

    `serviced` is excluded from the count because it is a denominator that spans
    two outcomes, not a bucket of its own.
    """
    out = []
    seen: dict[str, str] = {}
    for name, o in _by_name(declaration).items():
        buckets = o["aggregation"]["summary_buckets"]
        if "total" not in buckets:
            out.append(f"{name} does not increment `total`")
        counting = [b for b in buckets if b not in ("total", "serviced")]
        if len(counting) != 1:
            out.append(f"{name} increments {len(counting)} counting buckets "
                       f"({counting!r}); it must increment exactly one")
            continue
        bucket = counting[0]
        if bucket in seen:
            out.append(f"`{bucket}` is claimed by both {seen[bucket]} and {name}, "
                       f"so the buckets do not partition the run")
        seen[bucket] = name
    return out


CHECKS = {
    "inconclusive-never-aggregates-into-pass": check_inconclusive_never_aggregates_into_pass,
    "inconclusive-is-not-a-fail": check_inconclusive_is_not_a_fail,
    "absence-of-observed-attack-is-not-a-pass": check_absence_of_observed_attack_is_not_a_pass,
    "denominator-excludes-unserviced": check_denominator_excludes_unserviced,
    "buckets-partition-total": check_buckets_partition_total,
}


# ---------------------------------------------------------------------------
# Check phases
# ---------------------------------------------------------------------------

def validate_schema(declaration: dict) -> list[tuple[str, str, str]]:
    """Structural validation. A missing `jsonschema` raises rather than passing."""
    try:
        import jsonschema  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise CannotCheck(
            "jsonschema is not installed, so the declaration was NOT validated. "
            "This is reported as could-not-check rather than as success."
        ) from exc

    schema = _load(SCHEMA, "result-semantics schema")
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(declaration), key=lambda e: list(e.path))
    if not errors:
        return [(OK, "schema", f"validates against {SCHEMA.name}")]
    return [(BAD, "schema",
             f"{'.'.join(str(p) for p in e.absolute_path) or '(root)'}: {e.message}")
            for e in errors]


def validate_invariants(declaration: dict) -> list[tuple[str, str, str]]:
    """Every required invariant present, executable, and satisfied."""
    rows: list[tuple[str, str, str]] = []
    declared = {inv["id"]: inv for inv in declaration.get("invariants", [])}

    for required in REQUIRED_INVARIANTS:
        if required not in declared:
            rows.append((BAD, f"invariant {required}", (
                "not declared. It is required of any declaration this repository "
                "ships; removing it weakens the artifact silently.")))

    for inv_id, inv in declared.items():
        label = f"invariant {inv_id}"
        check_name = inv.get("check")
        fn = CHECKS.get(check_name)
        if fn is None:
            rows.append((BAD, label, (
                f"names check {check_name!r}, which is not implemented here. An "
                f"invariant with no executable check is prose.")))
            continue
        violations = fn(declaration)
        if violations:
            rows.extend((BAD, label, v) for v in violations)
        else:
            rows.append((OK, label, "holds against the declared outcomes"))

    return rows


def validate_no_drift(declaration: dict) -> list[tuple[str, str, str]]:
    """The declared outcomes must be the attestation schema's result enum.

    Two vocabularies for one set of states is how the third state was lost the
    first time: `run_summary()` had counted INCONCLUSIVE for a long time while the
    schema's enum was `pass | fail | error | skip`, so the state existed
    in-process and could not be serialized. Adding an outcome on either side now
    fails until both sides agree.
    """
    attestation = _load(ATTESTATION_SCHEMA, "attestation-report schema")
    try:
        enum = attestation["$defs"]["attestation_entry"]["properties"]["result"]["enum"]
        summary_props = attestation["properties"]["summary"]["properties"]
    except (KeyError, TypeError) as exc:
        raise CannotCheck(
            f"could not read the result enum or summary properties out of "
            f"{ATTESTATION_SCHEMA.name}: {exc}"
        ) from exc

    rows: list[tuple[str, str, str]] = []
    declared_names = [o["name"] for o in declaration["outcomes"]]

    missing = set(enum) - set(declared_names)
    extra = set(declared_names) - set(enum)
    if missing:
        rows.append((BAD, "drift outcome names", (
            f"the attestation schema can emit {sorted(missing)} but no meaning is "
            f"declared for it. A serializable state with no predeclared meaning is "
            f"the gap this artifact exists to close.")))
    if extra:
        rows.append((BAD, "drift outcome names", (
            f"meanings are declared for {sorted(extra)}, which the attestation "
            f"schema cannot emit. The declaration describes a harness that does "
            f"not exist.")))
    if not missing and not extra:
        rows.append((OK, "drift outcome names",
                     f"declared outcomes match the attestation result enum: "
                     f"{sorted(declared_names)}"))

    known_buckets = set(summary_props) | RUN_SUMMARY_ONLY_BUCKETS
    for outcome in declaration["outcomes"]:
        unknown = [b for b in outcome["aggregation"]["summary_buckets"]
                   if b not in known_buckets]
        if unknown:
            rows.append((BAD, f"drift buckets for {outcome['name']}", (
                f"declares bucket(s) {unknown!r} that the attestation report "
                f"summary does not define. Known: {sorted(known_buckets)}")))
    if not any(r[1].startswith("drift buckets") for r in rows):
        rows.append((OK, "drift buckets",
                     "every declared bucket exists in the report summary"))
    return rows


def run(declaration_path: Path) -> tuple[list[tuple[str, str, str]], str | None]:
    """All phases. Returns (rows, cannot_check_reason)."""
    try:
        declaration = _load(declaration_path, "result-semantics declaration")
        rows = validate_schema(declaration)
        # The invariant and drift checks read fields the schema guarantees, so
        # running them over a document that failed validation would report
        # KeyErrors as semantic violations. Stop at the first phase instead.
        if any(status == BAD for status, _, _ in rows):
            return rows, None
        rows += validate_invariants(declaration)
        rows += validate_no_drift(declaration)
        return rows, None
    except CannotCheck as exc:
        return [], str(exc)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--declaration", type=Path, default=DECLARATION,
                    help="path to the declaration (default: docs/result-semantics.json)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = ap.parse_args()

    if args.declaration == DECLARATION and not DECLARATION.is_file():
        rows, cannot_check = [], (
            f"checkout-only resource missing: docs/result-semantics.json (expected at "
            f"{DECLARATION}). It is not shipped in the wheel; run from a clone or pass "
            f"--declaration PATH.")
    else:
        rows, cannot_check = run(args.declaration)

    if cannot_check is not None:
        if args.json:
            print(json.dumps({"status": "could-not-check", "reason": cannot_check}, indent=2))
        else:
            print(f"  [SKIP] could not check: {cannot_check}")
            print("\nExiting 2. This run verified nothing; do not read it as a pass.")
        return EXIT_CANNOT_CHECK

    failed = [r for r in rows if r[0] == BAD]
    if args.json:
        print(json.dumps({
            "status": "invalid" if failed else "valid",
            "declaration": str(args.declaration),
            "results": [{"status": s, "check": c, "detail": d} for s, c, d in rows],
            "failed": len(failed),
        }, indent=2))
    else:
        for status, check, detail in rows:
            print(f"  [{status}] {check}: {detail}")
        print()
        print(f"{len(rows) - len(failed)} passed, {len(failed)} failed")
        if not failed:
            print("NOTE: this establishes that the semantics are declared and "
                  "internally consistent. It does not establish that any run "
                  "honored them.")

    return EXIT_INVALID if failed else EXIT_VALID


if __name__ == "__main__":
    sys.exit(main())
