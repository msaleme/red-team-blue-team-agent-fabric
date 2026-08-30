#!/usr/bin/env python3
"""Export the RCL-001..RCL-011 receipt-claim vectors as reusable oracle fixtures.

Why this module exists
----------------------
``receipt_claim_harness.py`` runs the vectors and reports pass/fail, but two
things make its output hard for an external evaluation harness to consume:

1. The **receipt inputs are constructed in code**, not exported as data. A
   consumer would have to import and reverse-engineer the harness to get them.
2. The **verdict is prose** inside ``RCLResult.details`` (for example
   ``"envelope_valid=True; claim verdict=reject (occurrence: missing evidence)"``),
   so a consumer has to string-parse to learn what the expected answer is.

This module emits a stable, versioned fixture set that carries, per vector:

* the receipt input, as data;
* the expected verdict (``accept`` / ``reject``);
* the failing claim family as a structured field rather than prose.

What a fixture set is *not*
---------------------------
These fixtures establish whether a receipt supports the claims it asserts. They
do **not** establish that any particular implementation emits defective
receipts. A consumer using them as oracle cases should preserve that
distinction in its result language.

Determinism
-----------
Freshness is evaluated relative to a clock (see ``FRESHNESS_WINDOW``), and
RCL-003 is a *stale transcript* case, so the fixtures are only meaningful
alongside the evaluation time they were generated against. ``EVALUATION_TIME``
is therefore pinned and exported in the fixture set as ``evaluation_time``. A
consumer must verify with that value injected as "now", not with wall-clock
time, or the freshness-dependent cases will not reproduce.

Usage
-----
    python -m protocol_tests.rcl_fixtures            # write the fixture set
    python -m protocol_tests.rcl_fixtures --stdout   # print instead of writing
    python -m protocol_tests.rcl_fixtures --check    # verify, write nothing
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from protocol_tests.receipt_claim_harness import (
    _CLEAN_TOOLS,
    _SHARELOCK_TOOLS,
    FRESHNESS_WINDOW,
    NEGATIVES,
    ClaimLevelVerifier,
    build_tool_context_receipt,
    build_valid_receipt,
)

FIXTURE_SET = "rcl-oracle-fixtures"
VERSION = "1.0.0"
SOURCE_MODULE = "protocol_tests/receipt_claim_harness.py"

# Pinned so the set is byte-stable across runs. Any fixed value works; what
# matters is that the consumer verifies against this same value.
EVALUATION_TIME = 1_780_000_000

# The four separately assessable claim families. Keys are the prefixes the
# verifier emits in ``Outcome.reason``; values are the stable field names.
CLAIM_FAMILIES = {
    "integrity": "integrity_provenance",
    "authorization": "authorization",
    "occurrence": "occurrence",
    "check": "check_execution",
}


def _cases(now: int):
    """(id, name, receipt, expected_verdict, is_positive_control)."""
    out = []
    for case_id, name, builder in NEGATIVES:
        out.append((case_id, name, builder(now), "reject", False))
    out.append((
        "RCL-008", "Fully-supported receipt accepted (control)",
        build_valid_receipt(now), "accept", True,
    ))
    out.append((
        "RCL-009", "Wired MCP-019 check (clean) accepted",
        build_tool_context_receipt(now, _CLEAN_TOOLS), "accept", True,
    ))
    out.append((
        "RCL-010", "Wired MCP-019 check (composite found) rejected",
        build_tool_context_receipt(now, _SHARELOCK_TOOLS), "reject", False,
    ))
    out.append((
        "RCL-011", "Wired MCP-019 check bound to wrong tool set rejected",
        build_tool_context_receipt(now, _CLEAN_TOOLS, action_tools=_SHARELOCK_TOOLS),
        "reject", False,
    ))
    return out


def _family(reason: str) -> str | None:
    """Map a verifier reason string onto a stable claim-family field name."""
    prefix = reason.split(":", 1)[0].strip()
    if prefix not in CLAIM_FAMILIES:
        raise ValueError(
            f"verifier reason {reason!r} has prefix {prefix!r}, which is not one of "
            f"{sorted(CLAIM_FAMILIES)}. The fixture exporter and the verifier have "
            "drifted; fix the mapping rather than widening it silently."
        )
    return CLAIM_FAMILIES[prefix]


def build(now: int = EVALUATION_TIME) -> dict:
    verifier = ClaimLevelVerifier(now)
    cases = []

    for case_id, name, receipt, expected, is_control in _cases(now):
        envelope_valid = verifier.verify_envelope(receipt)
        outcome = verifier.verify(receipt)

        # Self-check. Every vector must pass envelope validation — that is the
        # whole point of the suite: these are correctly signed receipts whose
        # substantive claims may still be unsupported. And the observed verdict
        # must match the expectation being exported, or the fixture set would
        # publish an expectation the harness itself does not produce.
        if not envelope_valid:
            raise AssertionError(f"{case_id}: envelope did not verify")
        if outcome.verdict != expected:
            raise AssertionError(
                f"{case_id}: harness returned {outcome.verdict!r} but the fixture "
                f"set declares {expected!r} ({outcome.reason})"
            )

        cases.append({
            "id": case_id,
            "name": name,
            "expected_verdict": outcome.verdict,
            "failing_claim_family": _family(outcome.reason) if outcome.verdict == "reject" else None,
            "reason": outcome.reason,
            "envelope_valid": True,
            "positive_control": is_control,
            "owasp_asi": "ASI09",
            "receipt": receipt,
        })

    accepts = [c for c in cases if c["expected_verdict"] == "accept"]
    rejects = [c for c in cases if c["expected_verdict"] == "reject"]

    return {
        "fixture_set": FIXTURE_SET,
        "version": VERSION,
        "source_module": SOURCE_MODULE,
        "evaluation_time": now,
        "freshness_window_seconds": FRESHNESS_WINDOW,
        "claim_families": sorted(set(CLAIM_FAMILIES.values())),
        "counts": {
            "total": len(cases),
            "accept": len(accepts),
            "reject": len(rejects),
            "positive_controls": len([c for c in cases if c["positive_control"]]),
        },
        "notes": {
            "evaluation_time": (
                "Verify with this value injected as the current time, not wall-clock "
                "time. Freshness is relative, so under wall-clock verification the "
                "attestations in RCL-008 and RCL-009 age out and both are rejected. "
                "Those are exactly the two positive controls, so a consumer that "
                "ignores this field rejects all eleven cases and is indistinguishable "
                "from a verifier that does no claim-level checking at all."
            ),
            "envelope": (
                "Every fixture passes envelope and signature validation, including "
                "the reject cases. A verifier that rejects on signature alone has "
                "not exercised claim-level verification."
            ),
            "positive_controls": (
                "RCL-008 and RCL-009 must be ACCEPTED. A verifier that rejects all "
                "eleven has not demonstrated correct claim validation."
            ),
            "scope": (
                "These fixtures establish whether a receipt supports its asserted "
                "claims. They do not establish that any implementation produces "
                "defective receipts."
            ),
        },
        "cases": cases,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--stdout", action="store_true", help="print instead of writing")
    ap.add_argument("--check", action="store_true",
                    help="build and self-verify only; write nothing")
    ap.add_argument("--out", default="reports/round_26/rcl-oracle-fixtures-v1.json")
    args = ap.parse_args()

    data = build()

    if args.check:
        c = data["counts"]
        print(f"OK: {c['total']} fixtures ({c['accept']} accept, {c['reject']} reject, "
              f"{c['positive_controls']} positive controls) at "
              f"evaluation_time={data['evaluation_time']}")
        return

    blob = json.dumps(data, indent=2, sort_keys=False) + "\n"
    if args.stdout:
        print(blob, end="")
        return

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(blob)
    c = data["counts"]
    print(f"wrote {out} — {c['total']} fixtures "
          f"({c['accept']} accept, {c['reject']} reject)")


if __name__ == "__main__":
    main()
