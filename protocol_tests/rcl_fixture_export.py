#!/usr/bin/env python3
"""Export the RCL receipt-claim vectors as portable oracle fixtures.

Why this exists
---------------
``receipt_claim_harness.py`` reports *outcomes*: it builds each receipt in
code, verifies it, and prints a pass/fail line whose verdict lives as prose
inside a ``details`` string. That is adequate as an evidence report and
unusable as a fixture: an outside implementation cannot consume it without
reimplementing the builders.

This module emits the same eleven vectors as data, so a third party can run
their own verifier against them and compare.

Derived, not asserted
---------------------
Every expected value in the output is produced by **executing**
``ClaimLevelVerifier`` over the built receipt. Nothing here hand-writes an
expected verdict or claim family. A hand-assigned expectation would be a
label, not a result, and this project has already published one audit about
what happens when those two are confused (see ``benchmarks/CHANGELOG.md``).

The ``claim_family`` field is taken from the verifier's own rejection reason
prefix, which is where the verifier already records which property failed.

Determinism
-----------
Signing keys are derived from fixed seeds and the evaluation time is pinned
(``EVALUATION_TIME``), so the emitted JSON is byte-stable across runs and
machines. ``tests/test_rcl_fixture_export.py`` enforces that.

Only public keys are exported. The seeds stay in the harness; these fixtures
are for verification, not for minting new receipts.
"""

from __future__ import annotations

import json
from pathlib import Path

from protocol_tests import receipt_claim_harness as H

SCHEMA_VERSION = "1.0"

# Pinned so the output is reproducible. Matches ReceiptClaimTests.now.
EVALUATION_TIME = 1_750_000_000

# The four families the decomposition defines. `integrity_provenance` is
# declared and enforced by the verifier but is NOT exercised by any current
# vector -- see `coverage_gaps` in the emitted file. Stated rather than
# quietly omitted.
CLAIM_FAMILIES = [
    "integrity_provenance",
    "occurrence",
    "authorization",
    "check_execution",
]

# The verifier prefixes each rejection reason with the property that failed.
_REASON_PREFIX_TO_FAMILY = {
    "integrity": "integrity_provenance",
    "occurrence": "occurrence",
    "authorization": "authorization",
    "check": "check_execution",
}


def _family_from_reason(reason: str) -> str | None:
    """Map a verifier reason onto a claim family. None for an accept."""
    prefix = reason.split(":", 1)[0].strip()
    return _REASON_PREFIX_TO_FAMILY.get(prefix)


def _case(verifier, test_id: str, name: str, receipt: dict) -> dict:
    outcome = verifier.verify(receipt)
    envelope_valid = verifier.verify_envelope(receipt)
    family = _family_from_reason(outcome.reason) if outcome.verdict == "reject" else None
    return {
        "id": test_id,
        "name": name,
        # Every vector's envelope signature verifies. That is the whole point:
        # signature validity does not establish the substantive claims.
        "envelope_valid": envelope_valid,
        "receipt": receipt,
        "expected": {
            "verdict": outcome.verdict,
            "claim_family": family,
            "reason": outcome.reason,
        },
    }


def build_fixture_set(now: int = EVALUATION_TIME) -> dict:
    """Build the full fixture set by executing the verifier over each vector."""
    v = H.ClaimLevelVerifier(now)
    fixtures: list[dict] = []

    for test_id, name, builder in H.NEGATIVES:
        fixtures.append(_case(v, test_id, name, builder(now)))

    fixtures.append(
        _case(v, "RCL-008", "Fully-supported receipt accepted (control)",
              H.build_valid_receipt(now))
    )
    fixtures.append(
        _case(v, "RCL-009", "Wired MCP-019 check (clean) accepted",
              H.build_tool_context_receipt(now, H._CLEAN_TOOLS))
    )
    fixtures.append(
        _case(v, "RCL-010", "Wired MCP-019 check (composite found) rejected",
              H.build_tool_context_receipt(now, H._SHARELOCK_TOOLS))
    )
    fixtures.append(
        _case(v, "RCL-011", "Wired MCP-019 check bound to wrong tool set rejected",
              H.build_tool_context_receipt(now, H._CLEAN_TOOLS,
                                           action_tools=H._SHARELOCK_TOOLS))
    )

    accepts = [f for f in fixtures if f["expected"]["verdict"] == "accept"]
    rejects = [f for f in fixtures if f["expected"]["verdict"] == "reject"]
    exercised = {f["expected"]["claim_family"] for f in rejects}
    gaps = [fam for fam in CLAIM_FAMILIES if fam not in exercised]

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_by": "protocol_tests/rcl_fixture_export.py",
        "source_module": "protocol_tests/receipt_claim_harness.py",
        "evaluation_time": now,
        "freshness_window_seconds": H.FRESHNESS_WINDOW,
        "signature_algorithm": "Ed25519 (RFC 8032) over JCS-canonicalised JSON",
        "public_keys": {k: v.hex() for k, v in H.PUBKEYS.items()},
        "claim_families": CLAIM_FAMILIES,
        "counts": {
            "total": len(fixtures),
            "accept": len(accepts),
            "reject": len(rejects),
        },
        "coverage_gaps": {
            "families_with_no_negative_vector": gaps,
            "note": (
                "The decomposition defines four claim families. Families listed "
                "here are enforced by the verifier but have no negative vector "
                "in this set, so these fixtures do not exercise them."
            ),
        },
        "scope": (
            "These vectors establish whether a receipt supports its asserted "
            "claims. They do not establish that any particular implementation "
            "produces defective receipts."
        ),
        "usage": (
            "For each fixture, run your verifier over `receipt` and compare "
            "against `expected.verdict`. Retain the accept cases: a verifier "
            "that rejects every fixture has not demonstrated correct claim "
            "validation."
        ),
        "fixtures": fixtures,
    }


DEFAULT_OUTPUT = Path("fixtures/rcl/rcl-oracle-fixtures.v1.json")


def serialise(data: dict) -> str:
    return json.dumps(data, indent=2, sort_keys=False) + "\n"


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-o", "--output", type=Path, default=DEFAULT_OUTPUT)
    ap.add_argument("--stdout", action="store_true", help="print instead of writing")
    args = ap.parse_args()

    data = build_fixture_set()
    text = serialise(data)

    if args.stdout:
        print(text, end="")
        return

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8")
    c = data["counts"]
    print(f"wrote {args.output} - {c['total']} fixtures "
          f"({c['accept']} accept, {c['reject']} reject)")
    gaps = data["coverage_gaps"]["families_with_no_negative_vector"]
    if gaps:
        print(f"coverage gap: no negative vector for {', '.join(gaps)}")


if __name__ == "__main__":
    main()
