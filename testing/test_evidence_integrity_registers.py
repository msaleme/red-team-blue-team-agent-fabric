"""Every evidence-integrity register must report a numerator AND a denominator.

The shared operating rule, agreed with the independent reviewer 2026-09-01:

> Every evidence-integrity register must report its derived numerator and
> surveyed denominator; every new detector must prove it can catch a seeded
> violation; every D-and-E result is classified by evidence type before it is
> treated as a candidate for change.

This file enforces the first clause. `test_static_detectors_can_fire.py`
enforces the second. The third is a classification discipline, written down in
`docs/EVIDENCE-INTEGRITY-OPERATING-RULES.md`.

## Why a bare count is not enough

A register reported as a number cannot distinguish two opposite situations:

    the debt shrank            good
    the surveyed universe shrank   bad, and looks identical

Both read as "7 -> 3". This repository has produced the second one: a queue
listed three instances of a construction, deriving the population from source
found six, and three of those sat in a file that had been repaired for that same
defect hours earlier. The queue was a sample drawn by an instrument sharing the
blind spot.

`PREFIX_ONLY` shows the same thing from the other direction. Its denominator has
moved from 21 to 28 as modules gained the structural field and so entered the
surveyed class. The numerator stayed 0 throughout. Only the pair is legible.

## What a register must expose

A `Register` whose numerator source and population source are separately
addressable, and which is CALLED to yield `(numerator, denominator, note)` --
the triple every consumer reads. The denominator is derived at call time, never
a literal. A hard-coded denominator is the defect this file exists to prevent,
and the fifth external review showed that rejecting a literal `1` does not
reject a literal `2`: the file now seeds a membership change and requires the
exported triple to move, which no constant can do.

Each register also carries an owner, the positive control that would retire it,
and a review date the suite enforces -- because a labelled exception with no
date is a completed control only in the sense that nobody will look again.
"""
from __future__ import annotations

import pathlib
import re
import sys
import unittest
from collections.abc import Callable
from dataclasses import dataclass
from unittest import mock

REPO = pathlib.Path(__file__).resolve().parents[1]
TESTING = REPO / "testing"
sys.path.insert(0, str(TESTING))
sys.path.insert(0, str(REPO))


# ---------------------------------------------------------------------------
# What a register is
# ---------------------------------------------------------------------------
#
# Two different facts, and the fifth external review (R5-02) is about keeping
# them apart:
#
#   the NUMERATOR is usually a DECLARED ratchet -- a hand-maintained list of
#   known debt that may only shrink. It is a floor, not a measurement.
#
#   the DENOMINATOR is DERIVED at call time from the tree or from a sweep. It
#   is a measurement, and it moves on its own.
#
# The third external review replaced every register with `(0, 1, "fabricated")`
# and the file failed, so positivity was enforced. The fifth review replaced
# nine of the twelve with `(0, 2, "fabricated")` and all 11 tests and 56
# subtests passed: `> 1` is defeated by writing 2, and the tests that did
# recompute anything called the helper functions directly, so they said nothing
# about the exported table. Effective against disappearance-to-zero, ineffective
# against arbitrary nonzero fabrication.
#
# So a register is no longer a bare callable. It carries the numerator source
# and the population source separately, and every check below goes through
# `REGISTERS[name]` -- the same table the reporting consumes -- rather than
# calling a helper beside it.

#: The numerator is a hand-maintained list that may only shrink.
NUMERATOR_DECLARED = "declared-ratchet"
#: The numerator is computed from a measurement minus what has been classified.
NUMERATOR_DERIVED = "derived-remainder"

#: The population can be listed, so it is compared by SET IDENTITY against an
#: independent enumeration built by a different instrument.
POPULATION_ENUMERABLE = "enumerable-set"
#: The population is whatever a sweep produced. Only a count survives the run,
#: so it is checked by seeding the sweep and watching the denominator move.
POPULATION_SWEEP = "sweep-derived-count"


def _size(value: object) -> int:
    """Members of a collection, or an already-computed count."""
    if isinstance(value, int):
        return value
    return len(value)                                   # type: ignore[arg-type]


#: Single maintainer, so every register has the same owner today. The field
#: exists so that stops being an assumption the moment a second one appears.
MAINTAINER = "@msaleme"


@dataclass(frozen=True)
class Register:
    """One evidence-integrity register: a declared numerator over a derived population.

    `__call__` returns the `(numerator, denominator, note)` triple every
    consumer already reads, so nothing downstream changes. What is new is that
    the two halves stay separately addressable, which is what lets a test seed a
    membership change and require the exported triple to move.

    `owner`, `positive_control` and `review_by` answer structural point I.8 of
    the fifth external review: "stable exception debt can become permanent".
    A labelled exception with no owner, no plan for the control that would
    retire it, and no date is a completed control only in the sense that nobody
    is going to look at it again. `review_by` is a deadline the suite enforces,
    so the debt cannot go quiet.
    """

    numerator: Callable[[], object]
    population: Callable[[], object]
    note: str
    numerator_kind: str
    population_kind: str
    #: Who answers for this register's remaining debt.
    owner: str
    #: The control that would let the numerator reach zero, and what it must
    #: positively establish -- not "keep reading the list".
    positive_control: str
    #: ISO date by which this register is re-read. Enforced below.
    review_by: str

    def __call__(self) -> tuple[int, int, str]:
        return (_size(self.numerator()), _size(self.population()), self.note)


# ---------------------------------------------------------------------------
# The modules each register reads
# ---------------------------------------------------------------------------
#
# One accessor per source module, used BOTH by the register and by the seeding
# tests. `testing.x` and a bare `x` are two different module objects when
# `testing/` is also on `sys.path`; patching one would leave the register
# reading the other, and the seeding test would report a movement that the
# exported table never made.

def _mod_transformation():
    import test_evidence_transformation_patterns as m
    return m


def _mod_duplicates():
    import test_no_duplicate_refusal_predicate as m
    return m


def _mod_refusal():
    import test_refusal_establishes_a_pass as m
    return m


def _mod_inconclusive():
    import test_inconclusive_is_structural as m
    return m


def _mod_detectors():
    import test_static_detectors_can_fire as m
    return m


def _mod_base_adoption():
    import test_harness_base_adoption as m
    return m


def _mod_permissive():
    import test_permissive_host_state as m
    return m


def _mod_empty_answer():
    import test_empty_answer_is_not_a_control as m
    return m


def _mod_simulated():
    from testing import test_simulated_passes_are_scoped as m
    return m


# ---------------------------------------------------------------------------
# Populations
# ---------------------------------------------------------------------------

def _protocol_module_files() -> frozenset[str]:
    """Every file in `protocol_tests/`. Returned as a SET of names, not a count,
    so it can be compared member-for-member with an independent enumeration."""
    return frozenset(p.name for p in (REPO / "protocol_tests").glob("*.py"))


def _harnesses_declaring_simulate() -> frozenset[str]:
    """Registered harnesses whose own argparse declares `--simulate`."""
    from protocol_tests.cli import HARNESSES, _module_declares_flag
    return frozenset(h for h in HARNESSES if _module_declares_flag(h, "--simulate"))


def _dead_host_suites_that_ran() -> list:
    import test_evidence_transformation_patterns  # noqa: F401  (puts scripts/ on sys.path)
    import dead_host_sweep
    return [r for r in dead_host_sweep.sweep() if r.get("status") == "ran"]


def _permissive_passes() -> int:
    return sum(_mod_permissive().PASSING_AGAINST_YES.values())


def _empty_answer_verdicts() -> int:
    return sum(r["total"] for r in _mod_empty_answer()._rows() if r["status"] == "ran")


def _permissive_read_remainder() -> int:
    """Permissive passes not yet read: measured, minus expected, minus classified.

    Read 2026-09-02 at verdict granularity: a module can hold both kinds, so a
    module-level count could not express it. Everything classified is read,
    whether it cleared or not; ABSENCE_AS_SUCCESS is debt of a different
    register, not unread debt of this one.
    """
    m = _mod_permissive()
    total = sum(m.PASSING_AGAINST_YES.values())
    expected = sum(m.LEGITIMATELY_PERMISSIVE.values())
    classified = len(m.POSITIVE_EVIDENCE_OR_LOCAL) + len(m.ABSENCE_AS_SUCCESS)
    return total - expected - classified


#: register name -> Register. The denominator must be derived at call time.
#: A literal is the defect; a constant that merely looks plausible is the same
#: defect wearing a larger number.
REGISTERS: dict[str, Register] = {
    "UNDER_REPORTS_A_QUOTING_REFUSAL": Register(
        numerator=lambda: _mod_transformation().UNDER_REPORTS_A_QUOTING_REFUSAL,
        population=_dead_host_suites_that_ran,
        note="suites losing a pass when a refusal quotes the request, of suites producing verdicts",
        numerator_kind=NUMERATOR_DECLARED,
        population_kind=POPULATION_SWEEP,
        owner=MAINTAINER,
        positive_control=(
            "a fixture whose refusal quotes the request verbatim, run against every "
            "suite that grades prose: a suite that keeps its pass on it has the defect, "
            "and one that loses it does not"),
        review_by="2026-12-01"),
    "KNOWN_DUPLICATES": Register(
        numerator=lambda: _mod_duplicates().KNOWN_DUPLICATES,
        population=_protocol_module_files,
        note="modules re-implementing the refusal predicate, of all protocol modules",
        numerator_kind=NUMERATOR_DECLARED,
        population_kind=POPULATION_ENUMERABLE,
        owner=MAINTAINER,
        positive_control=(
            "a module that re-implements the refusal predicate, added to a scratch "
            "tree, must be caught by the duplicate detector before this register can be "
            "called retired"),
        review_by="2026-12-01"),
    "UNREAD": Register(
        numerator=lambda: _mod_refusal().UNREAD,
        population=lambda: _mod_refusal()._prose_or_indicator_graded(),
        note="prose-graded modules not yet read, of the derived prose-graded class",
        numerator_kind=NUMERATOR_DECLARED,
        population_kind=POPULATION_SWEEP,
        owner=MAINTAINER,
        positive_control=(
            "each prose-graded module read against a bland-compliance fixture (Shape D) "
            "and a quoting-refusal fixture, and classified by what it did, not by "
            "whether it looks careful"),
        review_by="2026-11-01"),
    "PREFIX_ONLY": Register(
        numerator=lambda: _mod_inconclusive().PREFIX_ONLY,
        population=lambda: _mod_inconclusive()._modules_that_can_be_inconclusive(),
        note="modules carrying INCONCLUSIVE only as prose, of inconclusive-capable modules",
        numerator_kind=NUMERATOR_DECLARED,
        population_kind=POPULATION_SWEEP,
        owner=MAINTAINER,
        positive_control=(
            "a module carrying INCONCLUSIVE only in prose must fail the structural "
            "check when its result is serialised and re-read; the round trip is the "
            "control"),
        review_by="2026-12-01"),
    "UNCONTROLLED": Register(
        numerator=lambda: _mod_detectors().UNCONTROLLED,
        population=lambda: _mod_detectors().TestTheUncontrolledQueue._source_scanning_tests(),
        note="source-scanning tests with no seeded control pair, of source-scanning tests",
        numerator_kind=NUMERATOR_DECLARED,
        population_kind=POPULATION_SWEEP,
        owner=MAINTAINER,
        positive_control=(
            "a seeded violation per source-scanning test, or a recorded finding that "
            "the test asserts a required SHAPE and so has nothing to seed"),
        review_by="2026-11-01"),
    "GRANDFATHERED": Register(
        numerator=lambda: getattr(_mod_base_adoption(), "GRANDFATHERED", ()),
        population=_protocol_module_files,
        note="modules not yet on the shared base, of all protocol modules",
        numerator_kind=NUMERATOR_DECLARED,
        population_kind=POPULATION_ENUMERABLE,
        owner=MAINTAINER,
        positive_control=(
            "a harness that defines its own _record must fail adoption; the control is "
            "the seeded module, not the shrinking list"),
        review_by="2027-01-15"),
    "PERMISSIVE_READ_LIST": Register(
        numerator=_permissive_read_remainder,
        population=_permissive_passes,
        note="permissive passes not yet read, of all passes against an allow-all host",
        numerator_kind=NUMERATOR_DERIVED,
        population_kind=POPULATION_SWEEP,
        owner=MAINTAINER,
        positive_control=(
            "every remaining permissive pass read at verdict granularity against the "
            "allow-all host and placed in POSITIVE_EVIDENCE_OR_LOCAL or "
            "ABSENCE_AS_SUCCESS with its predicate"),
        review_by="2026-11-01"),
    "OVER_REFUSAL_EXPECTED": Register(
        # Inverted by design: over_refusal_harness measures wrongful refusal, so
        # an allow-all host is the one target it should score full marks against.
        numerator=lambda: sum(_mod_permissive().OVER_REFUSAL_EXPECTED.values()),
        population=_permissive_passes,
        note="over-refusal verdicts expected to pass permissively, of all permissive passes",
        numerator_kind=NUMERATOR_DECLARED,
        population_kind=POPULATION_SWEEP,
        owner=MAINTAINER,
        positive_control=(
            "inverted by design and not debt: the control is that over_refusal_harness "
            "FAILS against a host that refuses everything, which is the target shape it "
            "exists to score"),
        review_by="2027-01-15"),
    "ABSENCE_AS_SUCCESS": Register(
        # Read, and NOT cleared: permissive passes whose condition is a missing marker.
        numerator=lambda: _mod_permissive().ABSENCE_AS_SUCCESS,
        population=_permissive_passes,
        note="verdicts passing because a marker was absent, of all permissive passes",
        numerator_kind=NUMERATOR_DECLARED,
        population_kind=POPULATION_SWEEP,
        owner=MAINTAINER,
        positive_control=(
            "each verdict re-armed to require a positive marker, then re-run against "
            "the allow-all host: a verdict that still passes on a missing marker has "
            "not been repaired"),
        review_by="2026-11-01"),
    "EMPTY_ANSWER_PASSES": Register(
        # The fourth external review (R4-01) measured 47 of them against
        # v4.21.1. The denominator is every verdict the sweep produced, derived
        # from the same run that produces the numerator, so a fixture that
        # stopped answering shrinks both and cannot read as progress.
        numerator=lambda: _mod_empty_answer().EMPTY_ANSWER_PASSES,
        population=_empty_answer_verdicts,
        note="verdicts passing against a target that answered 200 with an empty "
             "body, of all verdicts produced against it; each declared a local "
             "self-test or a narrow scan",
        numerator_kind=NUMERATOR_DECLARED,
        population_kind=POPULATION_SWEEP,
        owner=MAINTAINER,
        positive_control=(
            "per row, a target that answers 200 with a body carrying the marker the row "
            "claims to check; a row that cannot distinguish that target from an empty "
            "body is not a local self-test, it is an absent control"),
        review_by="2026-11-01"),
    "GRANDFATHERED_UNLABELLED": Register(
        numerator=lambda: _mod_simulated().GRANDFATHERED_UNLABELLED,
        population=_harnesses_declaring_simulate,
        note="native --simulate modules whose PASS rows say nothing about being simulated; "
             "a row consumer publishes them as target passes",
        numerator_kind=NUMERATOR_DECLARED,
        population_kind=POPULATION_ENUMERABLE,
        owner=MAINTAINER,
        positive_control=(
            "a simulated run whose PASS rows carry the row-level scope marker, and a "
            "scope ratchet that rejects the same rows without it"),
        review_by="2026-12-01"),
    "GRANDFATHERED_UNREADABLE": Register(
        numerator=lambda: _mod_simulated().GRANDFATHERED_UNREADABLE,
        population=_harnesses_declaring_simulate,
        note="native --simulate modules whose simulated run yields no readable report, "
             "so the scope ratchet cannot see their rows at all",
        numerator_kind=NUMERATOR_DECLARED,
        population_kind=POPULATION_ENUMERABLE,
        owner=MAINTAINER,
        positive_control=(
            "a simulated run that writes a report the scope ratchet can read; until "
            "then the module's simulated rows are unmeasured, not clean"),
        review_by="2026-12-01"),
}


class TestEveryRegisterReportsBothNumbers(unittest.TestCase):
    def test_each_register_yields_a_numerator_and_a_denominator(self) -> None:
        for name, fn in REGISTERS.items():
            with self.subTest(register=name):
                num, den, note = fn()
                self.assertIsInstance(num, int)
                self.assertIsInstance(den, int)
                self.assertTrue(note, f"{name} has no description of what it counts")
                self.assertGreater(
                    den, 0,
                    f"{name} reports a zero denominator. A register over an empty "
                    f"surveyed set is not empty debt, it is an unrun measurement.")

    def test_no_register_exceeds_its_own_denominator(self) -> None:
        for name, fn in REGISTERS.items():
            with self.subTest(register=name):
                num, den, _ = fn()
                self.assertLessEqual(
                    num, den,
                    f"{name} counts {num} of a surveyed {den}. Either the "
                    f"derivation narrowed or the register is describing something "
                    f"other than what it claims.")

    def test_every_shrink_only_register_is_covered(self) -> None:
        """Derived: a file declaring a must-never-grow register must appear here.

        Kept derived rather than listed, because a register added tomorrow that
        nobody wired into this file would be exactly the untracked debt the rule
        exists to prevent.
        """
        import ast

        # Derived by AST, not regex. A first version matched `^[A-Z_]+ *=` and
        # collected REPO, TESTING, PROTOCOL_TESTS and CANONICAL -- path and string
        # constants that are not registers at all. A loose derivation produces a
        # register list that is itself wrong, which is the failure this file is
        # about, arriving in the file about it.
        declaring = set()
        for path in sorted(TESTING.glob("test_*.py")):
            text = path.read_text(encoding="utf-8", errors="replace")
            if not re.search(r"must never grow|MUST NEVER GROW", text):
                continue
            try:
                tree = ast.parse(text)
            except SyntaxError:                       # pragma: no cover
                continue
            for node in tree.body:                    # module level only
                if isinstance(node, ast.Assign):
                    targets, value = node.targets, node.value
                elif isinstance(node, ast.AnnAssign) and node.value is not None:
                    targets, value = [node.target], node.value
                else:
                    continue
                names = [t.id for t in targets
                         if isinstance(t, ast.Name) and t.id.isupper()]
                if not names:
                    continue
                # A register holds a COLLECTION of members: a set/dict literal,
                # or an explicitly empty one.
                is_collection = isinstance(value, (ast.Set, ast.Dict)) or (
                    isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                    and value.func.id in ("set", "dict", "frozenset"))
                if is_collection:
                    declaring.update(names)

        # Taxonomies and allowlists, not debt queues. They enumerate kinds or
        # permanent exceptions, so there is no surveyed population to be a
        # fraction of.
        taxonomies = {"PATTERNS", "PERMANENT", "DETECTORS", "CLASSIFIED_EXCEPTIONS",
                      "REGISTERS", "REFUSAL_VOCAB", "CALLER_EXTRA", "ALLOWED",
                      # A lookup of INSTRUMENTS -- one independent enumeration
                      # per enumerable population -- not a queue of debt. It is
                      # required to COVER the enumerable registers, and
                      # `test_every_enumerable_population_matches_an_independent_
                      # enumeration` derives that requirement from REGISTERS, so
                      # it cannot silently lose an entry either.
                      "INDEPENDENT_POPULATIONS",
                      "MODULE_TERMS", "HAS_THE_RULE", "DIFFERENT_REMEDY",
                      "LEGITIMATELY_PERMISSIVE", "PASSING_AGAINST_YES",
                      "RECOGNISES_A_REFUSAL", "RECOGNISES_NO_REFUSAL",
                      # Scope exclusions in test_report_states_its_provenance:
                      # files that are not report writers at all (a dispatcher,
                      # a usage docstring, the shared machinery). Same kind as
                      # NOT_A_HARNESS in test_inconclusive_summary -- naming
                      # what is outside the surveyed population, so there is no
                      # population for it to be a fraction of.
                      "NOT_A_REPORT_WRITER",
                      # test_empty_answer_is_not_a_control: NARROW_ROWS and
                      # LOCAL_ROWS are derived views of EMPTY_ANSWER_PASSES
                      # (which does report a denominator, above), and REPAIRED
                      # is the fixed list of IDs the review named. None is a
                      # debt queue of its own.
                      "NARROW_ROWS", "LOCAL_ROWS", "REPAIRED"}
        expected = declaring - taxonomies
        missing = expected - set(REGISTERS)
        self.assertEqual(
            missing, set(),
            f"these declare a shrink-only register and report no denominator: "
            f"{sorted(missing)}. Add a derivation to REGISTERS, or the register "
            f"cannot be told apart from a narrowed measurement.")


class TestThePermissiveReadListIsSplit(unittest.TestCase):
    """53 permissive passes is not 53 candidates, and reporting it as one number hides that.

    `LEGITIMATELY_PERMISSIVE` already exists and records that all 25
    `over_refusal_harness` passes are the DESIRED outcome: for that family a
    permissive target accepting the request is the healthy condition, not a
    finding. The independent reviewer asked for this to be reported as its own
    class so a future reader does not "repair" correct tests. It was already in
    the source; what was missing is that neither side reported the split.
    """

    def test_the_expected_permissive_passes_are_declared_and_subtracted(self) -> None:
        import test_permissive_host_state as m
        total = sum(m.PASSING_AGAINST_YES.values())
        expected = sum(m.LEGITIMATELY_PERMISSIVE.values())
        self.assertGreater(expected, 0, "no permissive pass is declared expected")
        self.assertLess(expected, total)
        for module in m.LEGITIMATELY_PERMISSIVE:
            with self.subTest(module=module):
                self.assertIn(
                    module, m.PASSING_AGAINST_YES,
                    f"{module} is declared legitimately permissive but is not in "
                    f"the measured map; the two have drifted apart")
                self.assertEqual(
                    m.LEGITIMATELY_PERMISSIVE[module], m.PASSING_AGAINST_YES[module],
                    f"{module} is declared entirely expected, so its expected count "
                    f"must equal its measured count")

    def test_the_read_list_is_the_remainder(self) -> None:
        # 28 -> 27 on 2026-09-01: CREW-005's leak check gained a third state, so
        # "the agent answered and never mentioned a passwd signature" stopped
        # counting as a pass against a target that grants everything.
        # 2026-09-02: denominator 52 -> 47 -> 43 -> 39 -> 37, numerator stays 0. The POPULATION
        # shrank, which is the outcome this guard exists to make visible: five
        # x402 verdicts stopped passing against an allow-all host because their
        # absence_as_success condition was repaired. A numerator alone would have
        # read as "no change".
        # 2026-09-07: denominator 37 -> 41, numerator stays 0. The POPULATION
        # grew because hitl_harness entered the permissive sweep for the first
        # time (R3-02) and HITL-005..008 pass against an allow-all host. Read
        # and repaired the same day: they now require a user-facing message
        # to scan, and the allow-all host writes one, so the four stay in the
        # population and sit in POSITIVE_EVIDENCE_OR_LOCAL. ABSENCE_AS_SUCCESS
        # went 4 -> 0.
        num, den, _ = REGISTERS["PERMISSIVE_READ_LIST"]()
        self.assertEqual(
            (num, den), (0, 41),
            f"the permissive read list changed: now {num} of {den}. That is fine, "
            f"and it must be restated here deliberately rather than drifting. "
            f"Report BOTH numbers -- a numerator alone hides whether the list "
            f"shrank or the population did.")

    def test_the_classification_covers_exactly_the_read_list(self) -> None:
        """Both sets must describe verdicts that actually pass permissively.

        Two failure directions. A verdict could be declared here and no longer
        pass against the allow-all host, which makes the classification a claim
        about a repository that has moved. Or a permissive pass could exist in
        neither set, which is unread debt reported as zero.
        """
        import sys as _sys
        _sys.path.insert(0, str(REPO / "scripts"))
        import test_permissive_host_state as m
        from test_permissive_host_state import permissive_sweep

        measured = {tid
                    for r in permissive_sweep() if r["status"] == "ran"
                    for tid in (r.get("passing_ids") or [])
                    if r["module"] not in m.LEGITIMATELY_PERMISSIVE}
        classified = set(m.POSITIVE_EVIDENCE_OR_LOCAL) | set(m.ABSENCE_AS_SUCCESS)

        self.assertEqual(
            classified - measured, set(),
            "declared as read but no longer passing permissively; the "
            "classification describes a repository that has moved")
        self.assertEqual(
            measured - classified, set(),
            "passes permissively and is in neither set: unread debt that the "
            "read-list register is reporting as zero")

    def test_no_verdict_is_in_both_classifications(self) -> None:
        import test_permissive_host_state as m
        both = set(m.POSITIVE_EVIDENCE_OR_LOCAL) & set(m.ABSENCE_AS_SUCCESS)
        self.assertEqual(both, set(), f"{sorted(both)} classified as both")

    def test_every_classification_records_its_predicate(self) -> None:
        """A bare ID is a name, not a reading."""
        import test_permissive_host_state as m
        for name, reg in (("POSITIVE_EVIDENCE_OR_LOCAL", m.POSITIVE_EVIDENCE_OR_LOCAL),
                          ("ABSENCE_AS_SUCCESS", m.ABSENCE_AS_SUCCESS)):
            for tid, why in reg.items():
                with self.subTest(register=name, verdict=tid):
                    self.assertGreater(
                        len(why), 20,
                        f"{tid} carries no predicate; the next reader cannot "
                        f"check the judgement without redoing it")

    def test_the_two_permissive_fixtures_are_not_diffed_as_one_metric(self) -> None:
        """An allow-all HTTP host and a bland-prose agent are different fixtures.

        On review feedback 2026-09-01. `PASSING_AGAINST_YES` is measured against a
        host that grants every REQUEST at the HTTP layer; Shape D is an agent that
        COMPLIES in plain prose. They answer different questions and currently
        happen to agree on the modules most recently read, which is exactly when a
        reader starts treating one number as the other.

        This does not require them to differ. It requires the registers to stay
        separately named and separately derived, so that if they ever diverge,
        nothing is quietly reporting one as evidence for the other.
        """
        import test_permissive_host_state as perm
        self.assertIsNot(
            perm.PASSING_AGAINST_YES, perm.LEGITIMATELY_PERMISSIVE,
            "the measured and expected permissive maps are the same object")
        num, den, note = REGISTERS["PERMISSIVE_READ_LIST"]()
        self.assertIn("allow-all host", note,
                      "the permissive register must name its fixture in its own "
                      "note, or a reader cannot tell which sweep produced it")
        self.assertNotIn(
            "shape d", note.lower(),
            "the permissive register is describing itself in Shape D terms")



# ---------------------------------------------------------------------------
# Independent enumerations
# ---------------------------------------------------------------------------
#
# Built by a DIFFERENT instrument than the register uses, so agreement is
# evidence rather than a tautology. The register globs the directory; this
# asks the import system what modules the package contains. The register
# regex-matches `add_argument("--simulate")` in module source; this parses the
# source and walks the call nodes.
#
# `test_static_detectors_can_fire.py` records the same lesson one level up: a
# register built by a different instrument than the one that checks it is how
# a stale list survives. The instruments must differ; the ANSWER must not.

def _independent_protocol_module_files() -> frozenset[str]:
    import pkgutil
    pkg = REPO / "protocol_tests"
    names = {f"{m.name}.py" for m in pkgutil.iter_modules([str(pkg)]) if not m.ispkg}
    if (pkg / "__init__.py").exists():
        names.add("__init__.py")
    return frozenset(names)


def _independent_harnesses_declaring_simulate() -> frozenset[str]:
    import ast
    import importlib.util
    from protocol_tests.cli import HARNESSES

    found = set()
    for name, info in HARNESSES.items():
        try:
            spec = importlib.util.find_spec(info["module"])
            origin = spec.origin if spec else None
            if not origin:
                continue
            tree = ast.parse(pathlib.Path(origin).read_text(encoding="utf-8"))
        except (ImportError, OSError, ValueError, SyntaxError):   # pragma: no cover
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            first = node.args[0]
            if called == "add_argument" and isinstance(first, ast.Constant) \
                    and first.value == "--simulate":
                found.add(name)
    return frozenset(found)


#: register name -> independent enumeration of its population.
#: Every register declared POPULATION_ENUMERABLE must have one, and the test
#: below derives that requirement from the table rather than from this dict, so
#: an enumerable register added without an independent enumeration fails.
INDEPENDENT_POPULATIONS: dict[str, Callable[[], frozenset[str]]] = {
    "KNOWN_DUPLICATES": _independent_protocol_module_files,
    "GRANDFATHERED": _independent_protocol_module_files,
    "GRANDFATHERED_UNLABELLED": _independent_harnesses_declaring_simulate,
    "GRANDFATHERED_UNREADABLE": _independent_harnesses_declaring_simulate,
}


# ---------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------
#
# Where each register's numerator membership actually lives, and which way the
# exported numerator moves when a member is added there. `sign` is -1 for a
# register whose numerator is a REMAINDER: classifying one more verdict makes
# the unread list shorter, not longer.

def _numerator_probe(name: str) -> tuple[object, str, int]:
    probes: dict[str, tuple[object, str, int]] = {
        "UNDER_REPORTS_A_QUOTING_REFUSAL":
            (_mod_transformation(), "UNDER_REPORTS_A_QUOTING_REFUSAL", 1),
        "KNOWN_DUPLICATES": (_mod_duplicates(), "KNOWN_DUPLICATES", 1),
        "UNREAD": (_mod_refusal(), "UNREAD", 1),
        "PREFIX_ONLY": (_mod_inconclusive(), "PREFIX_ONLY", 1),
        "UNCONTROLLED": (_mod_detectors(), "UNCONTROLLED", 1),
        "GRANDFATHERED": (_mod_base_adoption(), "GRANDFATHERED", 1),
        # A remainder: one more classified verdict is one less unread verdict.
        "PERMISSIVE_READ_LIST": (_mod_permissive(), "POSITIVE_EVIDENCE_OR_LOCAL", -1),
        "OVER_REFUSAL_EXPECTED": (_mod_permissive(), "OVER_REFUSAL_EXPECTED", 1),
        "ABSENCE_AS_SUCCESS": (_mod_permissive(), "ABSENCE_AS_SUCCESS", 1),
        "EMPTY_ANSWER_PASSES": (_mod_empty_answer(), "EMPTY_ANSWER_PASSES", 1),
        "GRANDFATHERED_UNLABELLED": (_mod_simulated(), "GRANDFATHERED_UNLABELLED", 1),
        "GRANDFATHERED_UNREADABLE": (_mod_simulated(), "GRANDFATHERED_UNREADABLE", 1),
    }
    return probes[name]


#: A member no real register can already hold, so seeding it is unambiguous.
SEEDED = ("seeded-by-the-register-test-1", "seeded-by-the-register-test-2")


def _with_members(collection: object, members: tuple[str, ...]) -> object:
    """A copy of *collection* holding *members* in addition to what it had."""
    if isinstance(collection, frozenset):
        return frozenset(collection | set(members))
    if isinstance(collection, (set, list, tuple)):
        return type(collection)(list(collection) + list(members))     # type: ignore[call-arg]
    if isinstance(collection, dict):
        # Value shape varies per register (a reason string, a tuple, a count).
        # Only its presence and, for the summed registers, its magnitude matter.
        return {**collection, **{m: 1 for m in members}}
    raise TypeError(f"register membership is a {type(collection).__name__}, "
                    f"which the seeding helper does not know how to copy")


def _grow_population(name: str):
    """(target, attribute, replacement, expected denominator delta) for *name*.

    The replacement makes the POPULATION one member larger, without touching the
    numerator source. Registers whose population is enumerable are not here:
    they are checked by set identity against an independent enumeration, which
    is the stronger statement.
    """
    if name == "UNDER_REPORTS_A_QUOTING_REFUSAL":
        import test_evidence_transformation_patterns  # noqa: F401
        import dead_host_sweep
        base = list(dead_host_sweep.sweep())
        return (dead_host_sweep, "sweep",
                lambda: base + [{"module": SEEDED[0], "status": "ran"}], 1)
    if name == "UNREAD":
        m = _mod_refusal()
        base = m._prose_or_indicator_graded()
        return (m, "_prose_or_indicator_graded",
                lambda: _with_members(base, SEEDED[:1]), 1)
    if name == "PREFIX_ONLY":
        m = _mod_inconclusive()
        base = m._modules_that_can_be_inconclusive()
        return (m, "_modules_that_can_be_inconclusive",
                lambda: _with_members(base, SEEDED[:1]), 1)
    if name == "UNCONTROLLED":
        m = _mod_detectors()
        base = m.TestTheUncontrolledQueue._source_scanning_tests()
        return (m.TestTheUncontrolledQueue, "_source_scanning_tests",
                staticmethod(lambda: _with_members(base, SEEDED[:1])), 1)
    if name in ("PERMISSIVE_READ_LIST", "OVER_REFUSAL_EXPECTED", "ABSENCE_AS_SUCCESS"):
        m = _mod_permissive()
        grown = {**m.PASSING_AGAINST_YES, SEEDED[0]: 1}
        return (m, "PASSING_AGAINST_YES", grown, 1)
    if name == "EMPTY_ANSWER_PASSES":
        m = _mod_empty_answer()
        base = list(m._rows())
        return (m, "_rows",
                lambda: base + [{"module": SEEDED[0], "status": "ran", "total": 7}], 7)
    raise KeyError(name)


class TestEveryRegisterIsRecomputedThroughTheExportedTable(unittest.TestCase):
    """R5-02: nine of twelve registers could be replaced with `(0, 2, "fabricated")`
    and this file stayed green.

    Two reasons, both repaired here. The movement test never moved anything --
    it asserted `den > 1`, which a fabricated 2 satisfies. And the tests that
    did recompute a population called the helper functions directly, beside the
    table, so replacing a table entry left them measuring the code that was no
    longer exported.

    Every check in this class reaches its register as `REGISTERS[name]`, and
    every check seeds a real change and requires the exported triple to move. A
    constant cannot move, whatever its value.
    """

    def test_each_register_says_whether_its_numerator_is_declared_or_derived(self) -> None:
        """A declared floor and a derived count are different facts."""
        for name, reg in REGISTERS.items():
            with self.subTest(register=name):
                self.assertIn(reg.numerator_kind,
                              (NUMERATOR_DECLARED, NUMERATOR_DERIVED),
                              f"{name} does not say what kind of number its numerator is")
                self.assertIn(reg.population_kind,
                              (POPULATION_ENUMERABLE, POPULATION_SWEEP),
                              f"{name} does not say what kind of population it is over")

    def test_every_enumerable_population_matches_an_independent_enumeration(self) -> None:
        """Set identity, not a matching count.

        Two enumerations of the same population by different instruments must
        agree member for member. A count can be fabricated; a membership has to
        name names, and the names have to be the real ones.
        """
        enumerable = {n for n, r in REGISTERS.items()
                      if r.population_kind == POPULATION_ENUMERABLE}
        self.assertEqual(
            enumerable - set(INDEPENDENT_POPULATIONS), set(),
            "declared as an enumerable population and given no independent "
            "enumeration to be compared against")
        for name in sorted(enumerable):
            with self.subTest(register=name):
                declared = frozenset(REGISTERS[name].population())
                independent = INDEPENDENT_POPULATIONS[name]()
                self.assertEqual(
                    declared, independent,
                    f"{name}'s population and an independent enumeration of it "
                    f"disagree: only in the register {sorted(declared - independent)}, "
                    f"only independently {sorted(independent - declared)}")
                _, den, _ = REGISTERS[name]()
                self.assertEqual(
                    den, len(independent),
                    f"{name} exports a denominator of {den} over a population of "
                    f"{len(independent)} named members")

    def test_every_numerator_moves_through_the_table_when_a_member_is_added(self) -> None:
        """Seed a member into the register's source and read the EXPORTED triple.

        This is the check the fabricated-constant mutation fails: a function
        returning `(0, 2, "fabricated")` returns 0 whether or not a member was
        added, because it is not reading the register at all.
        """
        for name in sorted(REGISTERS):
            with self.subTest(register=name):
                target, attr, sign = _numerator_probe(name)
                before, _, _ = REGISTERS[name]()
                seeded = _with_members(getattr(target, attr), SEEDED[:1])
                with mock.patch.object(target, attr, seeded):
                    after, _, _ = REGISTERS[name]()
                self.assertEqual(
                    after - before, sign,
                    f"{name}: a member was added to {attr} and the exported "
                    f"numerator went {before} -> {after}. A register that does "
                    f"not move with its membership is a constant.")

    def test_every_numerator_moves_through_the_table_when_a_member_is_removed(self) -> None:
        """The other direction, which is the one that hides a shrinking universe.

        Two members are seeded and one is then taken away, rather than removing
        a member the register already holds. Two reasons. Several registers are
        currently empty, so there is nothing real in them to remove. And two of
        them SUM values rather than counting keys -- removing
        `over_refusal_harness` from OVER_REFUSAL_EXPECTED moves the numerator by
        25, not by 1 -- so a seeded member of known weight is the only removal
        whose expected delta is the same statement for every register.
        """
        for name in sorted(REGISTERS):
            with self.subTest(register=name):
                target, attr, sign = _numerator_probe(name)
                base = getattr(target, attr)
                fuller = _with_members(base, SEEDED)
                emptier = _with_members(base, SEEDED[:1])
                with mock.patch.object(target, attr, fuller):
                    before, _, _ = REGISTERS[name]()
                with mock.patch.object(target, attr, emptier):
                    after, _, _ = REGISTERS[name]()
                self.assertEqual(
                    after - before, -sign,
                    f"{name}: a member was removed from {attr} and the exported "
                    f"numerator went {before} -> {after}")

    def test_every_sweep_derived_denominator_moves_when_its_population_grows(self) -> None:
        """The denominator half of the same argument.

        Enumerable populations are checked by set identity above. These are
        produced by running something, so the check is to make the run produce
        one more member and require the exported denominator to say so.
        """
        for name, reg in sorted(REGISTERS.items()):
            if reg.population_kind != POPULATION_SWEEP:
                continue
            with self.subTest(register=name):
                target, attr, replacement, delta = _grow_population(name)
                before = REGISTERS[name]()[1]
                with mock.patch.object(target, attr, replacement):
                    after = REGISTERS[name]()[1]
                self.assertEqual(
                    after - before, delta,
                    f"{name}: the population gained {delta} member(s) and the "
                    f"exported denominator went {before} -> {after}. A "
                    f"denominator that does not move with the sweep is a "
                    f"declared number wearing a derived name.")

    def test_every_register_has_an_owner_a_plan_and_a_review_date(self) -> None:
        """Structural point I.8: stable exception debt can become permanent.

        "Less than the old seed" permits growth below the seed and sets no
        repair deadline, and a label is not a control. Each register names who
        answers for it, the positive control that would retire it -- what a
        target must be observed to DO, not "read the list again" -- and a date.
        """
        for name, reg in sorted(REGISTERS.items()):
            with self.subTest(register=name):
                self.assertTrue(reg.owner, f"{name} has no owner")
                self.assertGreater(
                    len(reg.positive_control), 60,
                    f"{name}'s positive control is too short to be a plan; it has "
                    f"to say what a target must be observed to do")
                self.assertRegex(
                    reg.review_by, r"^\d{4}-\d{2}-\d{2}$",
                    f"{name}'s review date is not an ISO date")

    def test_no_register_is_past_its_review_date(self) -> None:
        """A deadline nobody enforces is a note.

        This fails on the day a register goes unreviewed. The repair is to read
        the register and move the date deliberately, with what changed -- not to
        push the date because the suite went red.
        """
        import datetime

        today = datetime.date.today()
        overdue = {name: reg.review_by for name, reg in REGISTERS.items()
                   if datetime.date.fromisoformat(reg.review_by) < today}
        self.assertEqual(
            overdue, {},
            f"these registers are past their review date: {sorted(overdue.items())}. "
            f"Re-read the register, record what moved, and set the next date. "
            f"Moving the date alone converts a deadline into a note.")

    def test_no_denominator_is_a_bare_one(self) -> None:
        """A floor, kept for its history, and no longer the load-bearing check.

        The third external review's fabrication was `(0, 1, ...)`; the fifth's
        was `(0, 2, ...)`, which this check cannot tell from a real population
        of two. The claims about movement are made by the seeded tests above.
        The name says what it does: it rejects one, and nothing more.
        """
        for name in sorted(REGISTERS):
            with self.subTest(register=name):
                _, den, _ = REGISTERS[name]()
                self.assertGreater(
                    den, 1, f"{name}: a denominator of 1 is a constant, not a population")


if __name__ == "__main__":
    unittest.main()
