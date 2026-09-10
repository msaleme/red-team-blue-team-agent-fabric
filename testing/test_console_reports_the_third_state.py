"""The console line must not print INCONCLUSIVE as a FAIL.

Twenty-nine modules computed their one-line console verdict from `result.passed`
alone while carrying `not_evaluated`, so every INCONCLUSIVE row printed as
`FAIL ❌`. The JSON report was correct throughout. Only the human-readable line
was wrong, and that is the surface an operator reads during a run.

This is the #348 collapse in the opposite direction. There, a target that never
serviced the request was recorded as a pass; the fix made "not measured" its own
state and `INCONCLUSIVE became a field` is a milestone in the changelog. Printing
that state as a FAIL undoes it at the last step: it reports evidence of a defect
where there is only absence of evidence. A reader who trusts the console sees a
finding that the record does not contain.

Two modules additionally used `N/A ➖` for the same field. That label is weaker
than the state: "not applicable" reads as a decision, while `not_evaluated`
means the measurement did not happen. One vocabulary, so a reader does not have
to learn which module they are looking at.

## How this was missed

The first sweep for it searched for the literal `PASS ✅` and found twenty of
them. Seventeen more write the same string as the escape `PASS \\u2705`, so the
real total was twenty-nine. A detector with a blind spot reported a smaller problem as the
whole problem -- the shape this repository keeps finding, here in the tool
looking for it.

## What this does not cover

`NO_VERDICT_FIELD` below names modules that print a status and have no
`not_evaluated` field at all. They cannot mislabel a state they do not carry,
and they also cannot report one. That is a separate gap and it is recorded
rather than left implicit; see CLAUDE.md item 10, where the number to move is
the unclassified remainder rather than the test count.
"""

from __future__ import annotations

import pathlib
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.http_helpers import console_status  # noqa: E402

PROTOCOL_TESTS = REPO_ROOT / "protocol_tests"

#: Both spellings. Searching only the first is how the count came back as 20.
PASS_FORMS = ("PASS ✅", "PASS \\u2705")

#: Modules that print a verdict but carry no `not_evaluated` field. They may
#: leave this list by gaining one. Nothing may join it: a new harness inherits
#: the field from the result dataclasses that already have it.
NO_VERDICT_FIELD = {
    "mcp_tool_poisoning_harness.py",
    "prompt_caching_harness.py",
    "receipt_claim_harness.py",
    "skill_security_harness.py",
}


def _status_statement(lines: list[str], i: int) -> str:
    """The whole assignment at line i, including continuations."""
    stmt, j = lines[i], i
    while stmt.count("(") > stmt.count(")") and j + 1 < len(lines):
        j += 1
        stmt += "\n" + lines[j]
    if i and "not_evaluated" not in stmt:
        stmt = lines[i - 1] + "\n" + stmt          # `status = (` on its own line
    return stmt


class _Result:
    def __init__(self, passed: bool, not_evaluated: bool = False):
        self.passed = passed
        self.not_evaluated = not_evaluated


class ConsoleStatusTests(unittest.TestCase):

    def test_console_status_reports_three_distinct_states(self):
        """A helper that cannot say INCONCLUSIVE is the defect, not the fix."""
        self.assertIn("PASS", console_status(_Result(True)))
        self.assertIn("FAIL", console_status(_Result(False)))
        self.assertIn("INCONCLUSIVE", console_status(_Result(False, True)))
        self.assertEqual(
            len({console_status(_Result(True)),
                 console_status(_Result(False)),
                 console_status(_Result(False, True))}), 3,
            "two of the three states render identically")

    def test_not_evaluated_outranks_passed(self):
        """`passed` is meaningless once the run did not evaluate anything.

        `_record` sets `passed = False` alongside `not_evaluated = True`, but a
        helper that checked `passed` first would still be wrong for any caller
        that does not, and the point is that the state is not derived from the
        verdict.
        """
        self.assertIn("INCONCLUSIVE", console_status(_Result(True, True)))

    def test_no_module_prints_a_verdict_without_the_third_state(self):
        """The regression. Twenty-nine harnesses did this before 2026-09-10."""
        offenders = []
        for module in sorted(PROTOCOL_TESTS.glob("*.py")):
            if module.name == "http_helpers.py":
                continue
            lines = module.read_text(encoding="utf-8").splitlines()
            source = "\n".join(lines)
            if "not_evaluated" not in source:
                continue
            for i, line in enumerate(lines):
                if not any(form in line for form in PASS_FORMS):
                    continue
                if "not_evaluated" not in _status_statement(lines, i):
                    offenders.append(f"{module.name}:{i + 1}")
                break
        self.assertEqual(
            offenders, [],
            "these print a console verdict from `passed` alone while carrying "
            "`not_evaluated`, so an INCONCLUSIVE row renders as FAIL. Use "
            "protocol_tests.http_helpers.console_status: " + ", ".join(offenders))

    def test_the_no_verdict_field_list_may_shrink_and_never_grow(self):
        """The recorded remainder, kept honest.

        A module that prints a status and has no `not_evaluated` field cannot
        mislabel the state, and cannot report it either. Naming them is the
        point: an unlisted gap is indistinguishable from no gap.
        """
        actual = set()
        for module in sorted(PROTOCOL_TESTS.glob("*.py")):
            if module.name == "http_helpers.py":
                continue
            source = module.read_text(encoding="utf-8")
            if "not_evaluated" in source:
                continue
            if any(form in source for form in PASS_FORMS):
                actual.add(module.name)
        self.assertEqual(
            actual - NO_VERDICT_FIELD, set(),
            "a module gained a printed verdict without a `not_evaluated` field: "
            f"{sorted(actual - NO_VERDICT_FIELD)}. Give its result dataclass the "
            "field rather than adding it here.")
        stale = NO_VERDICT_FIELD - actual
        self.assertEqual(
            stale, set(),
            f"these now carry the field and should leave NO_VERDICT_FIELD: {sorted(stale)}")


if __name__ == "__main__":
    unittest.main()
