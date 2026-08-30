"""A correct repair must reach every copy of the rule it repairs.

The reviewer's correction to the taxonomy, 2026-08-30:

    "I agree that duplicated predicate belongs in the model, but I would call it
     an implementation-risk modifier, not a peer evidence-transformation
     pattern. Evidence-transformation pattern -> how a conclusion can become
     unsound. Duplicated predicate -> why a correct repair fails to propagate."

That is the right distinction, and the two need different controls: a semantic
pattern needs counterfactual fixtures, a duplication modifier needs static
detection plus one canonical helper and an explicit exception registry.

## Why this file exists

Negation handling was ONE edit in `http_helpers._term_present` and it should
have been sufficient. It was not, because four sites had drifted into keeping
their own copy of the matching rule and so received neither it nor the
word-boundary fix made hours earlier:

    multi_agent_harness         any(r in resp_str for r in REFUSAL_INDICATORS)
    x402_harness      X4-025    an inline list containing "forbidden"
    identity_harness  AUTHZ-001 an inline list containing "forbidden"

This repository has paid for this shape once already: it accumulated 44 parallel
`_record` implementations, and one verdict defect had to be repaired four times
because each fix reached only the files someone happened to open.

The reviewer's instruction was explicit about not settling for a name check:

    "Do not merely grep for the current list. Guard the predicate shape as well:
     direct any(... in response ...) loops over refusal-like markers should be
     review candidates."
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_TESTS = REPO_ROOT / "protocol_tests"
CANONICAL = "http_helpers.py"

#: Vocabulary that means "this list is about refusals". A loop testing these
#: against a response body is re-implementing `looks_like_refusal`.
REFUSAL_VOCAB = (
    "denied", "rejected", "forbidden", "unauthorized", "blocked",
    "not permitted", "not allowed", "cannot", "refuse", "declined",
)

#: A membership test over a response body, in the shapes this repository writes.
_MEMBERSHIP = re.compile(
    r"\b(?:any|all)\s*\(\s*[\w.\[\]]+\s+in\s+(?P<hay>\w+)\s+for\b"
    r"|for\s+\w+\s+in\s+(?P<lst>[A-Z_]*(?:REFUSAL|REJECTION)[A-Z_]*)\s*:",
)

#: Sites that legitimately hold their own matching rule, with the reason.
#: A module may only LEAVE this set. Adding to it needs a reason a reader can
#: check, not a note that it was inconvenient.
PERMANENT = {
    "over_refusal_harness.py": (
        "carries OVER_REFUSAL_INDICATORS deliberately, and must NOT use the "
        "shared list: its requests are legitimate, so bare nouns like 'denied' "
        "and 'forbidden' appear innocently in correct technical answers. "
        "Measured 2026-08-30: the shared predicate gives 3 false positives in 8 "
        "sample legitimate answers. Narrower on purpose."),
    "http_helpers.py": "is the canonical implementation.",
}

#: Known duplicates, measured 2026-08-30. Each re-implements refusal matching
#: and will therefore NOT receive a fix made at the shared seam -- which is the
#: claim, not that any of them is wrong today. Word boundaries and negation
#: handling both shipped at the seam that day and reached none of these.
#:
#: This is a queue, not an allowlist. It MAY SHRINK AND MUST NEVER GROW, the
#: same idiom this repository uses for UNREVIEWED, RECOGNISES_NO_REFUSAL and
#: UNREAD. Fixing all eight in one pass is the bulk edit the independent review
#: of the permissive sweep warned against twice: "refusal wording, marker
#: coverage, direct observed state and intentionally permissive tests require
#: different remedies."
#:
#: Read in this order. The first is the sharpest: multi_agent_harness had ONE of
#: its two refusal predicates routed through the shared helper on 2026-08-30 and
#: this one was missed in the same commit, which is the duplication risk
#: demonstrating itself inside the repair for it.
KNOWN_DUPLICATES = {
    "multi_agent_harness.py": "a SECOND refusal predicate at :1125, missed when "
                              "the first was routed through the shared helper",
    "gtg1002_simulation.py": 'raw `and "refuse" not in resp_str` suppression at :527',
    "advanced_attacks.py": 'raw `and "refuse" not in resp_str` suppression at :330',
    "autogen_harness.py": 'raw `and "denied" not in resp_str` suppression at :603',
    "ap2_harness.py": "payment-protocol rejection tuple at :315",
    "card_token_harness.py": "payment-protocol rejection tuple at :262",
    "ucp_acp_harness.py": "payment-protocol rejection tuple at :303",
    "x402_fireblocks_harness.py": "payment-protocol rejection tuple at :366",
}

#: Everything the guard will not report on.
ALLOWED = {**PERMANENT, **KNOWN_DUPLICATES}


def _literals_from(lines: list[str], start: int, span: int = 6) -> list[str]:
    """The quoted strings belonging to one membership expression.

    A list can wrap, so read forward until the brackets balance rather than
    assuming one line.
    """
    buf, depth = "", 0
    for line in lines[start:start + span]:
        buf += line
        depth += line.count("(") + line.count("[") - line.count(")") - line.count("]")
        if depth <= 0 and buf.strip():
            break
    return [m.group(1).lower() for m in re.finditer(r"[\"']([^\"']{2,40})[\"']", buf)]


def _sources() -> list[Path]:
    return sorted(p for p in PROTOCOL_TESTS.glob("*.py") if p.name != "__init__.py")


class TestOneCanonicalRefusalPredicate(unittest.TestCase):
    def test_no_module_reimplements_the_membership_test(self) -> None:
        """The predicate SHAPE, not just the current list's name."""
        offenders = []
        for path in _sources():
            if path.name in ALLOWED:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for line_no, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if not _MEMBERSHIP.search(line):
                    continue
                # Only a loop whose OWN literal list is about refusals.
                #
                # A window scan over surrounding lines was tried first and
                # over-triggered badly: `followed_playbook`, `replayed`,
                # `generated_exploit`, `granted_admin` and `accepted` are
                # positive-harm detectors that merely sit near refusal
                # vocabulary. Flagging those would push five correct local
                # predicates into an allowlist, which is how an allowlist stops
                # meaning anything. Read the literals the loop actually tests.
                literals = _literals_from(text.splitlines(), line_no - 1)
                if sum(any(v in lit for v in REFUSAL_VOCAB) for lit in literals) < 2:
                    continue
                offenders.append(f"{path.name}:{line_no}  {stripped[:74]}")
        self.assertEqual(
            offenders, [],
            "these re-implement the refusal membership test instead of calling "
            "http_helpers.looks_like_refusal:\n  " + "\n  ".join(offenders) +
            "\n\nA local copy does not receive a fix made at the shared seam. "
            "Word boundaries and negation handling both shipped that way on "
            "2026-08-30 and reached none of the copies. Call the shared helper "
            "with `extra=` for domain terms, or register the file in ALLOWED "
            "with a reason.")

    def test_the_duplicate_queue_does_not_grow(self) -> None:
        """A queue that can grow is a list of excuses."""
        self.assertLessEqual(
            len(KNOWN_DUPLICATES), 8,
            "KNOWN_DUPLICATES grew. A module may only LEAVE it, by calling "
            "http_helpers.looks_like_refusal with `extra=` for its domain terms.")

    def test_every_known_duplicate_still_has_one(self) -> None:
        """Remove an entry once it is fixed, or the queue stops describing the code."""
        for name in KNOWN_DUPLICATES:
            with self.subTest(name=name):
                text = (PROTOCOL_TESTS / name).read_text(encoding="utf-8", errors="replace")
                lines = text.splitlines()
                found = any(
                    _MEMBERSHIP.search(l)
                    and sum(any(v in lit for v in REFUSAL_VOCAB)
                            for lit in _literals_from(lines, i)) >= 2
                    for i, l in enumerate(lines) if not l.strip().startswith("#"))
                self.assertTrue(
                    found,
                    f"{name} no longer re-implements the predicate. Good news, and "
                    f"the queue must record it: remove it from KNOWN_DUPLICATES.")

    def test_the_allowlist_is_not_stale(self) -> None:
        for name in ALLOWED:
            with self.subTest(name=name):
                self.assertTrue(
                    (PROTOCOL_TESTS / name).exists(),
                    f"{name} is allowlisted but no longer exists; remove it.")

    def test_the_canonical_helper_is_where_it_claims_to_be(self) -> None:
        text = (PROTOCOL_TESTS / CANONICAL).read_text(encoding="utf-8")
        for fn in ("def looks_like_refusal", "def _term_present", "def _negated_at"):
            with self.subTest(fn=fn):
                self.assertIn(
                    fn, text,
                    f"{fn} has moved out of {CANONICAL}. This guard points every "
                    f"module at that file; if the implementation moves, update "
                    f"the guard rather than letting it check nothing.")


if __name__ == "__main__":
    unittest.main()
