#!/usr/bin/env python3
"""Replay every RCL conformance vector through the claim-level verifier and assert
each reaches its recorded `expected_result`. This is what makes the vectors a
conformance suite rather than static data: a receipt implementation can run its
own verifier over the same fixtures and compare.

    python conformance/receipt-claim/verify_fixtures.py     # exits non-zero on mismatch
"""
import glob, json, os, sys
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)
from protocol_tests.receipt_claim_harness import ClaimLevelVerifier, ReceiptClaimTests

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def run():
    now = ReceiptClaimTests().now
    v = ClaimLevelVerifier(now)
    failures = []
    files = sorted(glob.glob(os.path.join(FIX, "RCL-*.json")))
    for path in files:
        fx = json.load(open(path))
        # every vector is envelope-valid by construction; the claim verdict is the test
        if not v.verify_envelope(fx["receipt"]):
            failures.append((fx["test_id"], "envelope signature did not verify"))
            continue
        got = v.verify(fx["receipt"]).verdict
        if got != fx["expected_result"]:
            failures.append((fx["test_id"], f"expected {fx['expected_result']}, got {got}"))
    print(f"receipt-claim conformance: {len(files) - len(failures)}/{len(files)} vectors match")
    for tid, why in failures:
        print(f"  MISMATCH {tid}: {why}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run())
