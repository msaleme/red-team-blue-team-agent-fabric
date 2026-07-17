#!/usr/bin/env python3
"""Receipt claim-level verification (RCP-001..RCP-008).

The property under test: a format-valid receipt whose *envelope signature
verifies* must still be rejected when its claims are not semantically supported
by the correct trust domain. Each negative asserts BOTH that the envelope is
valid AND that the claim-level verdict is reject; the control asserts accept.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol_tests.receipt_claim_harness import (
    ClaimLevelVerifier, build_valid_receipt, NEGATIVES,
)

NOW = 1_750_000_000


class TestReceiptClaimVerification(unittest.TestCase):
    def test_valid_receipt_is_accepted(self):
        v = ClaimLevelVerifier(NOW)
        r = build_valid_receipt(NOW)
        self.assertTrue(v.verify_envelope(r))
        self.assertEqual(v.verify(r).verdict, "accept")

    def test_each_claim_invalid_receipt_is_rejected_despite_valid_envelope(self):
        # The core claim: valid signature, invalid claim, rejected on semantics.
        v = ClaimLevelVerifier(NOW)
        for test_id, name, builder in NEGATIVES:
            with self.subTest(vector=test_id):
                r = builder(NOW)
                self.assertTrue(v.verify_envelope(r),
                                f"{test_id}: envelope must verify (that is the point)")
                out = v.verify(r)
                self.assertEqual(out.verdict, "reject",
                                 f"{test_id} ({name}) must be rejected: got {out.reason}")

    def test_rejection_reasons_are_distinct(self):
        # Each vector fails for its own semantic reason, not a single catch-all.
        v = ClaimLevelVerifier(NOW)
        reasons = {tid: v.verify(builder(NOW)).reason for tid, _, builder in NEGATIVES}
        self.assertEqual(len(set(reasons.values())), len(NEGATIVES),
                         f"expected distinct reasons, got: {reasons}")

    def test_harness_run_all_all_pass(self):
        from protocol_tests.receipt_claim_harness import ReceiptClaimTests
        results = ReceiptClaimTests(simulate=True).run_all()
        self.assertEqual(len(results), 8)
        self.assertTrue(all(r.passed for r in results))


if __name__ == "__main__":
    unittest.main()
