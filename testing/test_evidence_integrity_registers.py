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

A callable returning `(numerator, denominator, note)` where the denominator is
DERIVED from source at call time, never a literal. A hard-coded denominator is
the defect this file exists to prevent.
"""
from __future__ import annotations

import pathlib
import re
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
TESTING = REPO / "testing"
sys.path.insert(0, str(TESTING))
sys.path.insert(0, str(REPO))


def _under_reports() -> tuple[int, int, str]:
    import test_evidence_transformation_patterns as m
    import dead_host_sweep
    suites = [r for r in dead_host_sweep.sweep() if r.get("status") == "ran"]
    return (len(m.UNDER_REPORTS_A_QUOTING_REFUSAL), len(suites),
            "suites losing a pass when a refusal quotes the request, of suites producing verdicts")


def _known_duplicates() -> tuple[int, int, str]:
    import test_no_duplicate_refusal_predicate as m
    modules = list((REPO / "protocol_tests").glob("*.py"))
    return (len(m.KNOWN_DUPLICATES), len(modules),
            "modules re-implementing the refusal predicate, of all protocol modules")


def _unread() -> tuple[int, int, str]:
    import test_refusal_establishes_a_pass as m
    return (len(m.UNREAD), len(m._prose_or_indicator_graded()),
            "prose-graded modules not yet read, of the derived prose-graded class")


def _prefix_only() -> tuple[int, int, str]:
    import test_inconclusive_is_structural as m
    return (len(m.PREFIX_ONLY), len(m._modules_that_can_be_inconclusive()),
            "modules carrying INCONCLUSIVE only as prose, of inconclusive-capable modules")


def _uncontrolled() -> tuple[int, int, str]:
    import test_static_detectors_can_fire as m
    scanning = m.TestTheUncontrolledQueue._source_scanning_tests()
    return (len(m.UNCONTROLLED), len(scanning),
            "source-scanning tests with no seeded control pair, of source-scanning tests")


def _grandfathered() -> tuple[int, int, str]:
    import test_harness_base_adoption as m
    reg = getattr(m, "GRANDFATHERED", None)
    modules = list((REPO / "protocol_tests").glob("*.py"))
    return (len(reg) if reg is not None else 0, len(modules),
            "modules not yet on the shared base, of all protocol modules")


def _permissive_read_list() -> tuple[int, int, str]:
    """Permissive passes still to be read, of all permissive passes.

    Was asserted as a bare literal (`total - expected == 27`), which reports a
    numerator with the denominator left in the reader's head. Same durable format
    as every other register now: numerator, derived denominator, and what it counts.
    """
    import test_permissive_host_state as m
    total = sum(m.PASSING_AGAINST_YES.values())
    expected = sum(m.LEGITIMATELY_PERMISSIVE.values())
    # Read 2026-09-02 at verdict granularity: a module can hold both kinds, so a
    # module-level count could not express it. Everything classified is read,
    # whether it cleared or not; ABSENCE_AS_SUCCESS is debt of a different
    # register, not unread debt of this one.
    classified = len(m.POSITIVE_EVIDENCE_OR_LOCAL) + len(m.ABSENCE_AS_SUCCESS)
    return (total - expected - classified, total,
            "permissive passes not yet read, of all passes against an allow-all host")


def _absence_as_success() -> tuple[int, int, str]:
    """Read, and NOT cleared: permissive passes whose condition is a missing marker."""
    import test_permissive_host_state as m
    return (len(m.ABSENCE_AS_SUCCESS), sum(m.PASSING_AGAINST_YES.values()),
            "verdicts passing because a marker was absent, of all permissive passes")


def _over_refusal_expected() -> tuple[int, int, str]:
    """OR verdicts that SHOULD pass permissively, of all permissive passes.

    Inverted by design: over_refusal_harness measures wrongful refusal, so an
    allow-all host is the one target it should score full marks against.
    """
    import test_permissive_host_state as m
    return (sum(m.OVER_REFUSAL_EXPECTED.values()),
            sum(m.PASSING_AGAINST_YES.values()),
            "over-refusal verdicts expected to pass permissively, of all permissive passes")


#: register name -> callable returning (numerator, denominator, note).
#: The denominator must be derived at call time. A literal is the defect.
REGISTERS = {
    "UNDER_REPORTS_A_QUOTING_REFUSAL": _under_reports,
    "KNOWN_DUPLICATES": _known_duplicates,
    "UNREAD": _unread,
    "PREFIX_ONLY": _prefix_only,
    "UNCONTROLLED": _uncontrolled,
    "GRANDFATHERED": _grandfathered,
    "PERMISSIVE_READ_LIST": _permissive_read_list,
    "OVER_REFUSAL_EXPECTED": _over_refusal_expected,
    "ABSENCE_AS_SUCCESS": _absence_as_success,
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
                      "MODULE_TERMS", "HAS_THE_RULE", "DIFFERENT_REMEDY",
                      "LEGITIMATELY_PERMISSIVE", "PASSING_AGAINST_YES",
                      "RECOGNISES_A_REFUSAL", "RECOGNISES_NO_REFUSAL"}
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
        num, den, _ = _permissive_read_list()
        self.assertEqual(
            (num, den), (0, 37),
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
        num, den, note = _permissive_read_list()
        self.assertIn("allow-all host", note,
                      "the permissive register must name its fixture in its own "
                      "note, or a reader cannot tell which sweep produced it")
        self.assertNotIn(
            "shape d", note.lower(),
            "the permissive register is describing itself in Shape D terms")


if __name__ == "__main__":
    unittest.main()
