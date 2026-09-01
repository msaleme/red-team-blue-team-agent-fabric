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
    "agent_prose_outcome.py": (
        "agent-prose-outcome-v1: a SECOND canonical predicate, deliberately. "
        "The reviewer's point, 2026-08-30: the durable architecture is one "
        "canonical helper PER EVIDENCE DOMAIN, not one helper. Consolidating "
        "agent prose, protocol rejection, transport execution and capability "
        "applicability behind a single predicate would be false consolidation, "
        "because a protocol 402 and an agent saying 'I cannot' are different "
        "kinds of evidence. This file owns the agent-prose domain; the guard "
        "rejects UNREGISTERED inline copies, not registered families."),
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
#: The four payment modules left this queue 2026-08-31. Their `_live_rejected`
#: functions were structurally identical -- verified mechanically, with the term
#: tuple normalised away the four bodies differed only in two comments -- and
#: they now route through `http_helpers.payment_outcome`, keeping their own
#: vocabulary via `extra=`.
#:
#: The consolidation deliberately took the RESPONSE and not the URL. The first
#: attempt pulled the request in too, and that would have silently swapped the
#: transport: these four import `http_post_json` from `protocol_tests._utils`,
#: which is a DIFFERENT function from the one in `http_helpers` -- different
#: default timeout, different SSE handling, different error-dict shape. The
#: duplication this file guards is the matching rule, not the HTTP call.
KNOWN_DUPLICATES: dict[str, str] = {}

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

#: Refusal-ish words whose ABSENCE was used to suppress a harm finding.
_SUPPRESSION_VOCAB = (
    "denied", "rejected", "forbidden", "unauthorized", "blocked", "refuse",
    "cannot", "declin", "not permitted", "not allowed", "invalid", "reject",
)

#: `and "<word>" not in <haystack>` -- a harm finding cancelled by a substring.
_RAW_SUPPRESSION = re.compile(r'and\s+"([^"]+)"\s+not\s+in\s+\w+')


class TestNoRawRefusalSuppression(unittest.TestCase):
    """A harm finding must not be cancelled by a bare substring test.

    Six of these existed across three modules, all the same shape:

        cooperated    = _recon_info(resp) and "refuse" not in resp_str
        replayed      = any(...) and "denied" not in resp_str
        hmac_bypassed = any(...) and "rejected" not in resp_str

    Each is the shape-E hole in miniature. The word appears anywhere in the
    reply -- including inside its own negation, and including in a reply that
    goes on to deliver -- and the finding vanishes.

    Only three were on KNOWN_DUPLICATES, because the membership-shape detector
    above sees a LIST of refusal words and these are single ones. The other
    three were found by deriving the list from source rather than working the
    queue, and one of the modules had already been repaired that day for the
    same defect somewhere else in the same file.

    `http_helpers.declined(resp)` is the answer: it asks whether the agent's
    words decline the requested action, rather than whether a word is present.
    """

    @staticmethod
    def _prose_lines(path) -> set[int]:
        """Line numbers belonging to a docstring or a comment.

        Two wrong versions preceded this one, and both are worth recording.

        The first read raw lines and flagged four hits, every one of them PROSE
        ABOUT the defect -- a comment quoting the suppression it had just
        removed, and the three examples in `http_helpers.declined`'s own
        docstring. A check that fires on an accurate description of the thing it
        forbids is a check that gets muted.

        The second tokenised and dropped STRING tokens, which removed the string
        literal the pattern needs to see. It passed against a deliberately
        seeded suppression -- a guard that cannot fail, which is the defect this
        repository names most often. Verified by seeding, not by reading.

        So: exclude docstrings and comments by position, and read the real line
        text everywhere else.
        """
        import ast
        import io
        import tokenize

        source = path.read_text(encoding="utf-8", errors="replace")
        prose: set[int] = set()
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return set(range(1, source.count("\n") + 2))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Module, ast.ClassDef,
                                     ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = getattr(node, "body", None)
            if not body:
                continue
            first = body[0]
            if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)):
                prose.update(range(first.lineno, (first.end_lineno or first.lineno) + 1))
        try:
            for tok in tokenize.generate_tokens(io.StringIO(source).readline):
                if tok.type == tokenize.COMMENT:
                    prose.add(tok.start[0])
        except (tokenize.TokenError, IndentationError):
            pass
        return prose

    def test_no_module_cancels_a_finding_with_a_substring(self) -> None:
        offenders = []
        for path in sorted(PROTOCOL_TESTS.glob("*.py")):
            prose = self._prose_lines(path)
            for lineno, line in enumerate(
                    path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if lineno in prose or line.strip().startswith("#"):
                    continue
                m = _RAW_SUPPRESSION.search(line)
                if m and any(v in m.group(1).lower() for v in _SUPPRESSION_VOCAB):
                    offenders.append(f"{path.name}:{lineno}  {line.strip()[:70]}")
        self.assertEqual(
            offenders, [],
            "a harm finding is cancelled by a bare substring test:\n  "
            + "\n  ".join(offenders)
            + "\n\nUse `http_helpers.declined(resp)`. A word is not a refusal; a "
              "sentence that declines the requested action is.")

    def test_the_guard_can_fire(self) -> None:
        """A checker that cannot fail is not a checker.

        Tokenising away strings is exactly the kind of narrowing that can make a
        guard vacuous, so this asserts the pattern still matches real code.
        """
        self.assertTrue(
            _RAW_SUPPRESSION.search('x = any(...) and "denied" not in resp_str'),
            "the suppression pattern no longer matches the construction it forbids")
        self.assertFalse(
            _RAW_SUPPRESSION.search('x = any(...) and declined(resp)'),
            "the pattern matches the correct form, which would forbid the remedy")

