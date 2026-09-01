"""Every static integrity detector must prove it can catch a seeded violation.

The independent reviewer's rule, 2026-09-01, and the reason for it is this
repository's own history rather than principle:

> Every new static integrity detector must have a nearby seeded positive-control
> violation that it detects, plus at least one negative control it does not flag.
> That is the static-analysis equivalent of the Harness's PASS/FAIL
> counterfactual rule.

The suppression guard in `test_no_duplicate_refusal_predicate` took three
attempts. Version one read raw lines and fired on PROSE DESCRIBING the defect,
including the examples in the helper's own docstring -- a check that fails on an
accurate description of what it forbids is a check that gets muted. Version two
tokenised and dropped STRING tokens, removing the string literal the pattern
needed, and **passed against a deliberately seeded violation**. Only seeding one
revealed it.

A green static scan is therefore not evidence. It is evidence only once the
detector has been shown to discriminate.

## What this file does

Each registered detector is run twice over a TEMPORARY directory: once against a
module containing a seeded violation, which it must flag, and once against a
module containing the closest legitimate form, which it must not. The real
`protocol_tests/` tree is never written to.

`UNCONTROLLED` lists the source-scanning tests that do not yet have such a pair.
It may shrink and must never grow.
"""
from __future__ import annotations

import pathlib
import re
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
TESTING = REPO / "testing"
sys.path.insert(0, str(TESTING))
sys.path.insert(0, str(REPO))


def _seed(source: str) -> pathlib.Path:
    """A throwaway package directory holding one module. Never the real tree."""
    tmp = pathlib.Path(tempfile.mkdtemp())
    (tmp / "seeded_harness.py").write_text(source, encoding="utf-8")
    return tmp


# --------------------------------------------------------------------------
# Detector 1 — raw refusal suppression
# --------------------------------------------------------------------------

_SUPPRESSION_VIOLATION = '''"""A module that cancels a harm finding with a substring."""


def check(resp, resp_str):
    leaked = any(k in resp_str for k in ["secret", "token"]) and "denied" not in resp_str
    return leaked
'''

_SUPPRESSION_CONTROL = '''"""The correct form, plus prose describing the wrong one.

A previous version of the guard fired on this docstring, which says
`and "denied" not in resp_str` while forbidding it. It must not.
"""
from protocol_tests.http_helpers import declined


def check(resp, resp_str):
    # Also `and "refuse" not in resp_str` in a comment, which must not fire.
    leaked = any(k in resp_str for k in ["secret", "token"]) and not declined(resp)
    return leaked
'''


def _run_suppression_detector(directory: pathlib.Path) -> list[str]:
    import test_no_duplicate_refusal_predicate as mod
    offenders = []
    for path in sorted(directory.glob("*.py")):
        prose = mod.TestNoRawRefusalSuppression._prose_lines(path)
        for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1):
            if lineno in prose or line.strip().startswith("#"):
                continue
            m = mod._RAW_SUPPRESSION.search(line)
            if m and any(v in m.group(1).lower() for v in mod._SUPPRESSION_VOCAB):
                offenders.append(f"{path.name}:{lineno}")
    return offenders


# --------------------------------------------------------------------------
# Detector 2 — duplicated refusal predicate (membership over refusal literals)
# --------------------------------------------------------------------------

_MEMBERSHIP_VIOLATION = '''"""A module re-implementing the refusal predicate inline."""


def refused(resp_str):
    return any(w in resp_str for w in ["denied", "rejected", "forbidden", "not allowed"])
'''

_MEMBERSHIP_CONTROL = '''"""The correct form: one shared predicate, module terms passed in."""
from protocol_tests.http_helpers import looks_like_refusal

MODULE_TERMS = ["cannot delegate", "will not confirm"]


def refused(resp_str):
    return looks_like_refusal(resp_str, extra=MODULE_TERMS)
'''


def _run_membership_detector(directory: pathlib.Path) -> list[str]:
    import test_no_duplicate_refusal_predicate as mod
    offenders = []
    for path in sorted(directory.glob("*.py")):
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if line.strip().startswith("#"):
                continue
            if mod._MEMBERSHIP.search(line):
                literals = mod._literals_from(lines, i)
                hits = sum(any(v in lit for v in mod.REFUSAL_VOCAB) for lit in literals)
                if hits >= 2:
                    offenders.append(f"{path.name}:{i + 1}")
    return offenders


# --------------------------------------------------------------------------
# Detector 3 — a result class that can be INCONCLUSIVE without carrying the field
# --------------------------------------------------------------------------

_PREFIX_VIOLATION = '''"""A result class that can report INCONCLUSIVE with no structural field."""
from dataclasses import dataclass

from protocol_tests.http_helpers import INCONCLUSIVE_PREFIX


@dataclass
class SeededTestResult:
    test_id: str
    passed: bool
    details: str


def record():
    return SeededTestResult("X-001", False, INCONCLUSIVE_PREFIX + "never exercised")
'''

_PREFIX_CONTROL = '''"""The correct form: the state has a field."""
from dataclasses import dataclass

from protocol_tests.http_helpers import INCONCLUSIVE_PREFIX, is_inconclusive


@dataclass
class SeededTestResult:
    test_id: str
    passed: bool
    details: str
    not_evaluated: bool = False

    def __post_init__(self):
        if is_inconclusive(self.details):
            self.not_evaluated = True


def record():
    return SeededTestResult("X-001", False, INCONCLUSIVE_PREFIX + "never exercised")
'''


def _run_prefix_detector(directory: pathlib.Path) -> list[str]:
    import test_inconclusive_is_structural as mod
    import ast
    offenders = []
    for path in sorted(directory.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "@dataclass" not in text:
            continue
        if ("INCONCLUSIVE_PREFIX" not in text
                and not any(f in text for f in mod.INCONCLUSIVE_FIELDS)):
            continue
        tree = ast.parse(text)
        carries = any(
            isinstance(node, ast.ClassDef)
            and any(isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name)
                    and s.target.id in mod.INCONCLUSIVE_FIELDS for s in node.body)
            for node in ast.walk(tree))
        if not carries:
            offenders.append(path.name)
    return offenders


# --------------------------------------------------------------------------
# Detector 4 - fabricated default endpoint
#
# The 2026-08-04 incident: three references to infrastructure this project has
# never owned shipped as DEFAULTS, so every `agent-security publish` run without
# an override posted a signed attestation, including a user-supplied contact
# email, to a third party. The guard has stood green ever since, which is
# precisely the state in which nobody knows whether it can still fire.
# --------------------------------------------------------------------------

# Assembled rather than written literally, for the same reason the guard's own
# FORBIDDEN tuple is: a test file stating the host in one piece is a usable
# reference to it.
_BAD_HOST = "agentsecurity" + ".dev"

_ENDPOINT_VIOLATION = (
    '"""A module that hardcodes a default publish target."""\n'
    "\n"
    "DEFAULT_REGISTRY = \"https://registry." + _BAD_HOST + "/v1/attestation\"\n"
    "\n"
    "\n"
    "def publish(payload, url=DEFAULT_REGISTRY):\n"
    "    return url\n"
)

_ENDPOINT_CONTROL = (
    '"""The correct form: no default, and no usable reference anywhere."""\n'
    "\n"
    "# Historical note, and the reason this line is a COMMENT. The guard exempts\n"
    "# a Python comment or a Markdown blockquote, and nothing else -- a DOCSTRING\n"
    "# naming registry." + _BAD_HOST + " still trips it, which was\n"
    "# confirmed while writing this control. That is deliberate and is left\n"
    "# strict: a docstring is user-facing documentation, and the 2026-08-04\n"
    "# incident included a contact address in docs. Prose about the incident in\n"
    "# package source belongs in a comment.\n"
    "#\n"
    "# The default used to point at registry." + _BAD_HOST + ".\n"
    "\n"
    "\n"
    "def publish(payload, url):\n"
    "    if not url:\n"
    "        raise ValueError(\"publish requires an explicit --url\")\n"
    "    return url\n"
)


def _run_endpoint_detector(directory: pathlib.Path) -> list[str]:
    import test_no_default_endpoints as mod
    case = mod.TestForbiddenHostsAreGone("test_no_forbidden_host_in_package_source")
    return case._scan(sorted(directory.glob("*.py")))


#: detector name -> (runner, seeded violation, legitimate control, guarded file)
#:
#: The fourth element is load-bearing. The queue's ratchet used to compare
#: against a hand-written set of "already controlled" filenames, so adding a
#: pair here left that literal stale and the ratchet rejected the improvement.
#: A register checked by a different instrument than the one that fills it is
#: the defect this file exists to catch, one level up -- for the second time.
DETECTORS = {
    "raw refusal suppression": (
        _run_suppression_detector, _SUPPRESSION_VIOLATION, _SUPPRESSION_CONTROL,
        "test_no_duplicate_refusal_predicate.py"),
    "duplicated refusal predicate": (
        _run_membership_detector, _MEMBERSHIP_VIOLATION, _MEMBERSHIP_CONTROL,
        "test_no_duplicate_refusal_predicate.py"),
    "inconclusive without a structural field": (
        _run_prefix_detector, _PREFIX_VIOLATION, _PREFIX_CONTROL,
        "test_inconclusive_is_structural.py"),
    "fabricated default endpoint": (
        _run_endpoint_detector, _ENDPOINT_VIOLATION, _ENDPOINT_CONTROL,
        "test_no_default_endpoints.py"),
}

#: Derived, never written down: the files that have a seeded control pair.
CONTROLLED = {entry[3] for entry in DETECTORS.values()}

#: Source-scanning tests with no seeded positive/negative control pair yet.
#: **May shrink. Must never grow.** A new static detector lands here or, better,
#: in DETECTORS above with its own pair.
#:
#: Not every entry needs one. Several of these assert a SHAPE that must be
#: present rather than forbidding a construction, and a seeded violation is
#: meaningless for that direction. The queue exists so the judgement is recorded
#: per file rather than assumed for all of them.
#:
#: The list was first written from a looser grep than the derivation below uses,
#: and the stale-entry assertion rejected eight files that read specific paths
#: rather than globbing source. Recorded because it is the same defect this file
#: exists to catch, one level up: a register built by a different instrument than
#: the one that checks it.
UNCONTROLLED = {
    # Globs source to COMPUTE DENOMINATORS, not to detect a forbidden
    # construction. A seeded violation is meaningless in that direction: there
    # is nothing for it to fail to find. Added here the moment it was written,
    # because this queue flagged it on its first run -- which is the queue
    # working, and a reminder that "scans source" and "is a detector" are not
    # the same property.
    "test_evidence_integrity_registers.py",

    # The remaining five, read 2026-09-01. Every one of them globs source to
    # DERIVE A POPULATION and then asserts something BEHAVIOURAL about the
    # members -- it runs them, or inspects results they produced. None forbids a
    # construction in source, so there is nothing for a seeded violation to
    # fail to find. The discriminator is what the glob feeds, not that a glob
    # exists.
    #
    # If any of these ever grows a "this pattern must not appear in source"
    # assertion, it stops being a population derivation and needs a pair.

    # Globs for `def _record` to enumerate modules, then RUNS each against the
    # unserviced conditions and reads the verdicts.
    "test_harness_base_adoption.py",
    # Globs to enumerate harnesses, then asserts on summary dicts those
    # harnesses PRODUCE (inconclusive counted separately from failed).
    "test_inconclusive_summary.py",
    # Globs to enumerate bare CLIs, then EXECUTES each with --json and parses
    # stdout. The verdict is a property of the process, not of the text.
    "test_json_stdout_purity.py",
    # Globs for `def _record` to derive the prose-graded class as a
    # DENOMINATOR for its ratchet.
    "test_refusal_establishes_a_pass.py",
    # Globs for `_record` + `response_received` to enumerate harnesses, then
    # FEEDS each the five unserviced conditions.
    "test_serviced_guard.py",
}


class TestEveryRegisteredDetectorDiscriminates(unittest.TestCase):
    def test_each_detector_flags_its_seeded_violation(self) -> None:
        for name, (run, violation, _, _file) in DETECTORS.items():
            with self.subTest(detector=name):
                offenders = run(_seed(violation))
                self.assertTrue(
                    offenders,
                    f"{name!r} did not flag a seeded violation. A static detector "
                    f"that cannot fire is not evidence, however green it reports.")

    def test_each_detector_clears_its_negative_control(self) -> None:
        """The other half. A detector that flags everything is equally useless."""
        for name, (run, _, control, _file) in DETECTORS.items():
            with self.subTest(detector=name):
                offenders = run(_seed(control))
                self.assertEqual(
                    offenders, [],
                    f"{name!r} flagged the legitimate form. Two of the three "
                    f"controls here contain PROSE describing the violation, "
                    f"which an earlier version of one guard fired on.")

    def test_the_real_tree_was_not_written_to(self) -> None:
        """Seeding must never touch protocol_tests/."""
        seeded = list((REPO / "protocol_tests").glob("seeded_*.py"))
        self.assertEqual(seeded, [], f"seeded files leaked into the tree: {seeded}")


class TestTheUncontrolledQueue(unittest.TestCase):
    """Which source-scanning tests still lack a seeded control pair."""

    @staticmethod
    def _source_scanning_tests() -> set[str]:
        """Derived: a test that reads protocol_tests source to make its assertion."""
        found = set()
        for path in sorted(TESTING.glob("test_*.py")):
            if path.name == pathlib.Path(__file__).name:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if re.search(r'glob\(["\']\*\.py["\']\)|rglob\(["\']\*\.py["\']\)', text):
                found.add(path.name)
        return found

    def test_the_uncontrolled_list_may_shrink_and_must_never_grow(self) -> None:
        scanning = self._source_scanning_tests()
        grew = scanning - UNCONTROLLED - CONTROLLED
        self.assertEqual(
            grew, set(),
            f"these scan source and have no seeded control pair, and are not on "
            f"the list: {sorted(grew)}. Add a pair to DETECTORS, or add the file "
            f"here with the reason a seeded violation would be meaningless for it.")

    def test_every_controlled_file_is_real_and_scans_source(self) -> None:
        """The fourth element of a DETECTORS entry must name a real scanner.

        Without this, a detector could claim to control a file that does not
        exist or does not scan source, and the ratchet above would silently
        subtract a name that means nothing.
        """
        scanning = self._source_scanning_tests()
        for name, entry in DETECTORS.items():
            with self.subTest(detector=name):
                guarded = entry[3]
                self.assertTrue(
                    (TESTING / guarded).exists(),
                    f"{name!r} names {guarded}, which does not exist")
                self.assertIn(
                    guarded, scanning,
                    f"{name!r} claims to control {guarded}, but that file does "
                    f"not scan source, so the pair controls nothing")

    def test_no_file_is_both_controlled_and_queued(self) -> None:
        both = CONTROLLED & UNCONTROLLED
        self.assertEqual(
            both, set(),
            f"{sorted(both)} are declared both controlled and uncontrolled. The "
            f"queue and the registry disagree about the same file.")

    def test_the_uncontrolled_list_is_not_stale(self) -> None:
        scanning = self._source_scanning_tests()
        stale = UNCONTROLLED - scanning
        self.assertEqual(
            stale, set(),
            f"{sorted(stale)} no longer scan source; remove them, or the queue "
            f"stops describing the repository.")


if __name__ == "__main__":
    unittest.main()
