"""A claim of independent review must carry a disclosure or a citation.

## Why

`docs/EVIDENCE-INTEGRITY-OPERATING-RULES.md` opened with "Three rules, agreed
with the independent reviewer", naming no reviewer, no organisation, no
relationship, and no retained artifact. `docs/AUDIT-R33-INDEPENDENT-REVIEW.md`
was titled "Independent Review" and named its reviewer four lines down as
"Claude Opus 4.6 (automated)": a language model run by the author.

Meanwhile README says the harness as a whole has had no independent review. The
repository was asserting and denying the same thing in different files.

Raised 2026-09-11 as F5 by a second reader grading evidence classes, who also
supplied the rule this file encodes:

> Do not call a separate agent "independent" merely because it produced a
> different reading.

## What this can and cannot decide

It **cannot** establish independence. Reviewer identity, absence of common
control, and economic interest are relational facts about the world, and no test
reading this repository can reach them. That half is recorded as UNGUARDABLE in
`test_review_findings_are_ratcheted.py`.

What it **can** do is refuse the bare assertion. Wherever a document claims
independent review, a reader must find one of three things nearby: a denial (the
overwhelmingly common case here, and the honest one), a named party or retained
artifact, or an explicit disclosure that the reviewer was not independent. A
sentence that claims independence and supplies none of those is the defect.
"""

from __future__ import annotations

import pathlib
import re
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

#: An assertion that independent review happened.
_ASSERTS = re.compile(
    r"\b(?:the|an|our|a)\s+independent\s+(?:review|reviewer|assessor|audit|assessment)\b"
    r"|\bindependently\s+(?:reviewed|assessed|audited|verified)\b",
    re.I)

#: Nearby text that makes the assertion legitimate. Any one is enough.
_DISCHARGES = (
    # a denial, which is what most of this repository correctly does
    re.compile(r"\b(?:not|no|never|without|lacks?|absent|nobody|none)\b[^.]{0,120}?"
               r"independent|independent[^.]{0,120}?\b(?:not|no|never)\b", re.I),
    re.compile(r"does not (?:have|constitute|establish|amount to|confer)", re.I),
    re.compile(r"\bNOT independent\b", re.I),
    # a definition rather than a claim about this project
    re.compile(r"\b(?:means|defined as|distinguish|requires a qualified|"
               r"a qualified (?:party|outside))\b", re.I),
    # a citation: a retained artifact, issue, PR, or named party
    re.compile(r"#\d{2,}|https?://|\bissue\b|\bPR\b|\bretained\b|\bsee\b\s+[`\w/.-]+\.(?:md|json)", re.I),
    # an explicit disclosure that the reviewer was not independent
    re.compile(r"run by the (?:author|repository author)|under common control|"
               r"second reader|author-run|E1/I0", re.I),
)

_SKIP_DIRS = {"paper-dgb", "drafts", "proposals", "research"}


def _documents():
    for path in sorted((REPO_ROOT / "docs").rglob("*.md")):
        if _SKIP_DIRS & set(path.relative_to(REPO_ROOT).parts):
            continue
        yield path, path.read_text(encoding="utf-8", errors="replace")
    readme = REPO_ROOT / "README.md"
    if readme.is_file():
        yield readme, readme.read_text(encoding="utf-8", errors="replace")


def _paragraphs(text: str):
    for para in re.split(r"\n\s*\n", text):
        yield para


class IndependenceClaimsAreDisclosed(unittest.TestCase):

    def test_no_document_asserts_independent_review_without_support(self):
        for path, text in _documents():
            rel = path.relative_to(REPO_ROOT)
            for para in _paragraphs(text):
                if not _ASSERTS.search(para):
                    continue
                if any(d.search(para) for d in _DISCHARGES):
                    continue
                with self.subTest(doc=str(rel)):
                    snippet = " ".join(para.split())[:150]
                    self.fail(
                        f"{rel} asserts independent review with nothing beside it: "
                        f"\"{snippet}\". Name the party or the retained artifact, "
                        f"disclose that the reviewer was not independent, or say "
                        f"plainly that the project does not have it. A separate "
                        f"agent producing a different reading is not independence.")

    def test_the_title_of_a_review_document_does_not_outrun_its_reviewer(self):
        """AUDIT-R33 was titled 'Independent Review' and reviewed by a model.

        A file whose own `Reviewer:` line names a language model must not carry an
        unqualified independence claim in its heading.
        """
        model = re.compile(r"^\*\*Reviewer:\*\*\s*(.+)$", re.M)
        looks_automated = re.compile(r"claude|gpt|gemini|llama|automated|agent|model", re.I)
        for path, text in _documents():
            m = model.search(text)
            if not m or not looks_automated.search(m.group(1)):
                continue
            head = text[:text.index("\n\n")] if "\n\n" in text else text[:400]
            rel = path.relative_to(REPO_ROOT)
            with self.subTest(doc=str(rel)):
                if not re.search(r"\bindependent\b", head, re.I):
                    continue
                self.assertTrue(
                    any(d.search(text[:1200]) for d in _DISCHARGES),
                    f"{rel} has an automated reviewer ({m.group(1).strip()!r}) and the word "
                    f"'independent' in its heading, with no disclaimer near the top.")

    def test_the_scanner_sees_the_claims_it_should(self):
        """Anti-vacuity: a regex matching nothing passes both rules above."""
        docs = list(_documents())
        self.assertGreater(len(docs), 15)
        hits = [p for p, t in docs if _ASSERTS.search(t)]
        self.assertGreater(
            len(hits), 2,
            "almost no document mentions independent review, so the assertion "
            "pattern stopped matching rather than the claims disappearing")

    def test_a_bare_assertion_is_actually_rejected(self):
        """The positive control: prove the rule fires on the original sentence."""
        bare = "Three rules, agreed with the independent reviewer on 2026-09-01."
        self.assertTrue(_ASSERTS.search(bare))
        self.assertFalse(
            any(d.search(bare) for d in _DISCHARGES),
            "the withdrawn sentence would pass this guard, so the guard is not "
            "checking what it claims to check")


if __name__ == "__main__":
    unittest.main()
