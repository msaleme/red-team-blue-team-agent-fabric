"""MEM-013..016 must PASS against a store that enforces revocation and FAIL against one that does not.

Spec: arXiv:2609.08258, "Revoked but Still Authoritative: An Empirical Study of
Revocation Enforcement in Agent-Memory Systems" (2026-09-08). Across five
agent-memory systems, nine policy scenarios and nine models it reports that "no
system enforces revocation by default: the revoked fact is returned wherever the
revocation label is visible to the retrieval layer." Three things must line up
for the incident: the label is visible to retrieval, the revoked fact outranks
its replacement, and the agent then acts on it.

The harness already tested revocation at four layers -- AUTH-002 (credential),
DCA-007 (delegation epoch, cascading to the leaf), PRV-015 (attestation replay),
DSET-008 (settlement remediation). Memory had none, and memory is the layer the
paper measured.

## Why this file exists rather than a sweep row

`dead_host_sweep.py` and `permissive_host_sweep.py` both report 0 passing for
these four, which is correct and proves nothing on its own. A test that can never
pass is indistinguishable from one that works, from those two poles -- #357 had
six identity tests that could not fail for any input, and the mirror of that is a
verdict that cannot be right. Only a compliant target separates them.

CONTRIBUTION_REVIEW_CHECKLIST requires both directions. Four store modes are
asserted here, so every cell of the truth table is pinned:

    enforcing        revocation withheld at retrieval, replacement displaces,
                     withdrawal survives a session edge          -> all four PASS
    label_only       the paper's mechanism: the record is labelled revoked and
                     still returned                              -> 013/014/015 FAIL
    session_lapse    enforced in-session, forgotten at the edge  -> only 016 FAILS
    retains_nothing  stores nothing at all                       -> all four INCONCLUSIVE
    audit_visible    enforced, but revoked records stay visible to an
                     audit-shaped question                       -> all four PASS

`retains_nothing` is the one that would otherwise be missed. A store that retains
nothing returns no revoked record either, so without a positive control every
test here would score a vacuous PASS against it -- the X4-057 shape, where
nothing was accepted, nothing settled, nothing overdrawn, and "the control held".
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.memory_harness import MemoryTests  # noqa: E402

#: Matches every marker shape MEM-013..016 mint: policy_token_, limit_token_,
#: grant_token_, session_policy_. Deliberately not a list of those four literals
#: -- a control keyed to the exact strings under test drifts the moment one is
#: renamed, and then silently stops exercising anything.
_MARKER_RE = re.compile(r"\b[a-z][a-z_]*_[0-9a-f]{12}\b")


class _RevocationStore:
    """A memory backend whose revocation semantics are selectable.

    Message shapes are discriminated by verb, not by whether a marker is
    present: MEM-015's pre-revocation read quotes the granting policy back
    ("Under policy X, are you authorised to ..."), so "contains a marker"
    would misread a read as a write.
    """

    def __init__(self, mode: str):
        self.mode = mode
        self.live: list[str] = []       # insertion-ordered, newest last
        self.revoked: set[str] = set()

    #: Phrases that make a query a question about the RECORD rather than about
    #: what applies now. Named as a positive list of audit shapes rather than a
    #: list of task shapes on purpose: enumerating the task phrasings would mean
    #: extending this fixture every time a test is reworded, which is fixture
    #: tuning, and the fixture would stop being able to falsify anything.
    _AUDIT_SHAPES = ("stored", "history", "carried over", "have you kept",
                     "ever been", "previously")

    def _is_audit_query(self, query: str) -> bool:
        q = query.lower()
        return any(shape in q for shape in self._AUDIT_SHAPES)

    def _retrievable(self, query: str = "") -> list[str]:
        if self.mode == "retains_nothing":
            return []
        if self.mode == "audit_visible":
            # Correct soft revocation: withdrawn records stop applying but stay
            # visible to an audit or history question. A test that asks what is
            # STORED sees them and wrongly calls that a failure to enforce; a
            # test that asks what applies now, or what the agent may do, does not.
            if self._is_audit_query(query):
                return list(self.live)
            return [m for m in self.live if m not in self.revoked]
        if self.mode == "label_only":
            # The label exists; retrieval cannot see past it. The revoked record
            # is returned, and returned FIRST -- "outranks its replacement".
            return sorted(self.live, key=lambda m: m not in self.revoked)
        return [m for m in self.live if m not in self.revoked]

    def send(self, text: str) -> dict:
        markers = _MARKER_RE.findall(text)
        lowered = text.lower()

        if "revoked" in lowered:
            if markers:
                self.revoked.add(markers[0])
                for replacement in markers[1:]:
                    if replacement not in self.live:
                        self.live.append(replacement)
            body = "acknowledged"
        elif "remember" in lowered or "store this policy" in lowered:
            for m in markers:
                if m not in self.live:
                    self.live.append(m)
            body = "stored"
        else:
            if "new session" in lowered and self.mode == "session_lapse":
                # The withdrawal did not cross the edge; the grant did.
                self.revoked.clear()
            hits = self._retrievable(text)
            body = " ".join(hits) if hits else "no policies on record"

        # Shaped as a serviced response so the #348 guard in _record does not
        # rewrite these to INCONCLUSIVE. See testing/test_serviced_guard.py.
        return {"_status": 200,
                "response": {"jsonrpc": "2.0", "id": 1,
                             "result": {"parts": [{"text": body}]}}}


def _run(test_name: str, mode: str):
    suite = MemoryTests("http://stub.invalid")
    store = _RevocationStore(mode)
    suite._send = store.send  # type: ignore[method-assign]
    getattr(suite, test_name)()
    assert len(suite.results) == 1, f"expected one result, got {len(suite.results)}"
    return suite.results[0]


CASES = [
    ("test_mem_013_revoked_record_returned_at_retrieval", "MEM-013"),
    ("test_mem_014_revoked_record_outranks_replacement", "MEM-014"),
    ("test_mem_015_agent_acts_on_revoked_policy", "MEM-015"),
    ("test_mem_016_revocation_survives_session_boundary", "MEM-016"),
]


class RevocationEnforcementTests(unittest.TestCase):

    def test_all_pass_against_an_enforcing_store(self):
        """The control holding must produce a PASS, or the test is unusable.

        This is the direction neither host sweep can establish. Both report 0
        passing for these four, and a verdict that can only ever fail is the
        mirror of a verdict that can only ever pass.
        """
        for method, test_id in CASES:
            with self.subTest(test_id=test_id):
                r = _run(method, "enforcing")
                self.assertEqual(r.test_id, test_id)
                self.assertFalse(
                    r.not_evaluated,
                    f"{test_id} was INCONCLUSIVE against an enforcing store: {r.details}")
                self.assertTrue(
                    r.passed,
                    f"{test_id} did not pass against a store that enforces "
                    f"revocation: {r.details}")

    def test_retrieval_stage_fails_against_a_label_only_store(self):
        """The paper's mechanism must be detected. This is the direction that matters.

        MEM-016 is excluded: with the in-session revocation already broken there
        is no effective withdrawal for a session edge to lapse, and it reports
        INCONCLUSIVE rather than double-counting MEM-013's finding.
        """
        for method, test_id in CASES[:3]:
            with self.subTest(test_id=test_id):
                r = _run(method, "label_only")
                self.assertFalse(
                    r.passed,
                    f"{test_id} reported PASS against a store that returns a "
                    f"revoked record at retrieval -- it cannot detect what it "
                    f"was written for")
                self.assertFalse(
                    r.not_evaluated,
                    f"{test_id} went INCONCLUSIVE against a store that did "
                    f"answer and did retain: {r.details}")

    def test_mem_016_is_the_only_one_that_fails_on_a_session_lapse(self):
        """A revocation honoured in-session and forgotten at the edge.

        Isolates MEM-016: the other three complete before the boundary and must
        still pass, or MEM-016 is not measuring the boundary specifically.
        """
        for method, test_id in CASES[:3]:
            with self.subTest(test_id=test_id):
                self.assertTrue(
                    _run(method, "session_lapse").passed,
                    f"{test_id} failed on a store that enforces in-session; it "
                    f"is picking up the session-boundary behaviour MEM-016 owns")
        r = _run(CASES[3][0], "session_lapse")
        self.assertFalse(
            r.passed, "MEM-016 passed a store whose revocation lapses at the edge")
        self.assertFalse(
            r.not_evaluated,
            f"MEM-016 went INCONCLUSIVE where the withdrawal did hold in-session: {r.details}")

    def test_audit_visibility_is_not_a_revocation_failure(self):
        """Soft revocation: withdrawn but still visible to an audit question.

        Added 2026-09-10 after external review. MEM-013 and MEM-016 originally
        asked for "every operating policy you have stored", which is an
        audit-shaped question. A store that correctly stops honouring a revoked
        policy while retaining it for history answers that question with the
        revoked marker, and both tests would have called correct behaviour a
        failure to enforce.

        This mode returns revoked records to any query that does not name the
        in-force set. All four must pass against it, which holds only while
        every query they issue asks what is in force rather than what is
        stored. If one drifts back, this fails.
        """
        for method, test_id in CASES:
            with self.subTest(test_id=test_id):
                r = _run(method, "audit_visible")
                self.assertFalse(
                    r.not_evaluated,
                    f"{test_id} was INCONCLUSIVE against a store that enforces "
                    f"revocation and retains history: {r.details}")
                self.assertTrue(
                    r.passed,
                    f"{test_id} called audit visibility a revocation failure. Its "
                    f"retrieval query is asking what is STORED, not what is in "
                    f"force: {r.details}")

    def test_a_store_that_retains_nothing_is_inconclusive_not_a_pass(self):
        """The vacuous pass, guarded explicitly.

        Absence of a revoked record only means enforcement if the record was
        there to remove. Without this, every test here scores PASS against a
        target with no memory at all.
        """
        for method, test_id in CASES:
            with self.subTest(test_id=test_id):
                r = _run(method, "retains_nothing")
                self.assertTrue(
                    r.not_evaluated,
                    f"{test_id} returned a verdict against a store that retains "
                    f"nothing; it must be INCONCLUSIVE: {r.details}")
                self.assertFalse(r.passed, f"{test_id} passed vacuously")

    def test_failure_detail_names_the_revoked_marker(self):
        """A FAIL has to say which policy survived, or it is not actionable."""
        for method, test_id in CASES[:3]:
            with self.subTest(test_id=test_id):
                r = _run(method, "label_only")
                self.assertRegex(
                    r.details, r"[a-z][a-z_]*_[0-9a-f]{12}",
                    f"{test_id} failure detail names no marker: {r.details}")


if __name__ == "__main__":
    unittest.main()
