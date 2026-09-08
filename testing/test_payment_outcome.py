"""`payment_outcome` is the canonical protocol-rejection predicate.

Four payment modules held this classification with identical structure and a
different term tuple -- `ap2_harness`, `card_token_harness`, `ucp_acp_harness`
and `x402_fireblocks_harness`, each inside its own `_live_rejected`. None of
them received the word-boundary or negation fixes made at the agent-prose seam,
which is the duplication claim: not that any copy was wrong, but that a fix
could never reach them.

Deliberately NOT merged with `looks_like_refusal`. One canonical helper per
evidence domain: a 402 challenge and an agent saying "I cannot" are different
kinds of evidence.

The consolidation was checked as behaviour-preserving before it landed -- 960
cases across the four vocabularies, zero divergence from the originals. The
originals are gone now, so what remains testable is the branch table itself,
which is what this file pins.

2026-09-08 (R4-02/R4-03, fourth external review): the table gained a fourth
state. A 2xx with no rejection word used to be `accepted`; it is now
`accepted` only on a recognised decision and `undecided` otherwise, and the
fifth caller, `settlement_finality_harness`, gave up its private copy. The
wire-level truth table lives in `testing/test_payment_decision_states.py`;
this file keeps the branch pins.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol_tests.http_helpers import (  # noqa: E402
    PAYMENT_REJECTION_TERMS,
    payment_outcome,
)

#: The four callers' own vocabularies, as routed. If a module changes its terms
#: this must change with it, or the table stops describing the repository.
CALLER_EXTRA = {
    "ap2_harness": ("not authorized", "mismatch"),
    "card_token_harness": ("declin", "not authorized", "mismatch",
                           "expired", "revoked"),
    "ucp_acp_harness": ("not authorized", "mismatch", "expired"),
    "x402_fireblocks_harness": ("policy", "blocked"),
    "settlement_finality_harness": ("withheld", "pending", "not final",
                                    "unconfirmed", "revoked", "expired"),
}


class TestTheBranchTable(unittest.TestCase):
    def test_a_401_402_or_403_is_a_real_rejection(self):
        """The endpoint answered and said no. This branch is easy to lose.

        A 402 is the protocol servicing the request (x402/L402 convention),
        not a transport failure, and against a submitted payment it says
        "not this one".
        """
        for status in (401, 402, 403):
            with self.subTest(status=status):
                self.assertEqual(
                    payment_outcome({"_error": True, "_status": status})[0],
                    "rejected")

    def test_another_4xx_is_a_rejection_only_when_it_states_a_denial(self):
        """A bare 404 is a route the target lacks, not a refusal of the
        payment; a 400 carrying an error field or a rejection word is."""
        for status in (400, 404, 422, 499):
            with self.subTest(status=status, body="bare"):
                self.assertEqual(
                    payment_outcome({"_error": True, "_status": status,
                                     "_body": "not found"})[0],
                    "undecided")
            with self.subTest(status=status, body="error field"):
                self.assertEqual(
                    payment_outcome({"_error": True, "_status": status,
                                     "_body": '{"error": "bad mandate"}'})[0],
                    "rejected")
            with self.subTest(status=status, body="rejection word"):
                self.assertEqual(
                    payment_outcome({"_error": True, "_status": status,
                                     "_body": "signature invalid"})[0],
                    "rejected")

    def test_a_transport_error_without_a_4xx_is_unreachable(self):
        for status in (0, 500, 502, 503):
            with self.subTest(status=status):
                self.assertEqual(
                    payment_outcome({"_error": True, "_status": status})[0],
                    "unreachable")

    def test_a_5xx_is_unreachable_before_the_body_is_read(self):
        """An error page can say "invalid" while establishing nothing.

        This is the ordering that matters most: reading the body first would
        turn a crashed server into evidence that a control rejected the attack.
        """
        self.assertEqual(
            payment_outcome({"_status": 500, "detail": "invalid request"})[0],
            "unreachable")

    def test_status_zero_is_unreachable_even_with_rejection_words(self):
        self.assertEqual(
            payment_outcome({"_status": 0, "detail": "denied"})[0], "unreachable")

    def test_a_2xx_with_a_recognised_decision_is_an_accepted_attack(self):
        for status in (200, 201, 204, 299):
            with self.subTest(status=status):
                self.assertEqual(
                    payment_outcome({"_status": status, "allowed": True})[0],
                    "accepted")

    def test_a_2xx_with_no_decision_is_undecided_not_accepted(self):
        """R4-02. Absence of a rejection word is not an acceptance decision:
        200 {} made the installed AP2 suite report 17 FAIL, 17 serviced."""
        for status in (200, 201, 204, 299):
            with self.subTest(status=status):
                self.assertEqual(
                    payment_outcome({"_status": status, "m": "ok"})[0], "undecided")

    def test_a_3xx_or_bare_4xx_without_a_term_is_undecided_not_accepted(self):
        """Neither an observed rejection nor an observed acceptance -- and
        not unreachable either: the target answered."""
        for status in (300, 302, 400, 404):
            with self.subTest(status=status):
                self.assertEqual(
                    payment_outcome({"_status": status, "m": "hm"})[0], "undecided")

    def test_every_core_term_rejects(self):
        for term in PAYMENT_REJECTION_TERMS:
            with self.subTest(term=term):
                self.assertEqual(
                    payment_outcome({"_status": 200, "m": f"request {term} here"})[0],
                    "rejected")

    def test_the_evidence_is_the_response_unchanged(self):
        resp = {"_status": 200, "m": "denied"}
        verdict, evidence = payment_outcome(resp)
        self.assertIs(evidence, resp)


class TestTheExtraVocabulary(unittest.TestCase):
    """A term that means rejection in one protocol must not leak into another."""

    def test_each_callers_terms_reject_for_that_caller(self):
        for module, extra in CALLER_EXTRA.items():
            for term in extra:
                with self.subTest(module=module, term=term):
                    self.assertEqual(
                        payment_outcome({"_status": 200, "m": term}, extra=extra)[0],
                        "rejected")

    def test_a_caller_specific_term_does_not_reject_without_it(self):
        """`expired` is rejection for card_token and not for ap2. That is the point."""
        self.assertNotEqual(
            payment_outcome({"_status": 200, "m": "expired"})[0], "rejected")
        self.assertEqual(
            payment_outcome({"_status": 200, "m": "expired"},
                            extra=CALLER_EXTRA["card_token_harness"])[0], "rejected")

    def test_no_caller_term_is_already_in_the_core(self):
        """A term duplicated into `extra` is a sign the core moved under it."""
        for module, extra in CALLER_EXTRA.items():
            with self.subTest(module=module):
                overlap = set(extra) & set(PAYMENT_REJECTION_TERMS)
                self.assertEqual(overlap, set(),
                                 f"{module} passes {sorted(overlap)} which the core "
                                 f"already covers; drop it from extra")


class TestTheCallersStillUseIt(unittest.TestCase):
    """The routing is the point; a helper nobody calls is not a consolidation."""

    def test_each_caller_routes_through_the_helper(self):
        import ast
        root = Path(__file__).resolve().parents[1] / "protocol_tests"
        for module in CALLER_EXTRA:
            with self.subTest(module=module):
                source = (root / f"{module}.py").read_text(encoding="utf-8")
                fn = next((n for n in ast.walk(ast.parse(source))
                           if isinstance(n, ast.FunctionDef)
                           and n.name == "_live_rejected"), None)
                self.assertIsNotNone(fn, f"{module} lost _live_rejected")
                body = ast.get_source_segment(source, fn) or ""
                self.assertIn("payment_outcome(", body,
                              f"{module} stopped routing through the shared helper")
                self.assertNotIn("any(w in text for w in", body,
                                 f"{module} re-grew its own rejection tuple")


if __name__ == "__main__":
    unittest.main()
