#!/usr/bin/env python3
"""Independent reproduction of the CognOS LUMEN v0.1 scope-binding negative vector.

Source of the challenge (commit-pinned by its author):
  acprofessionale/CognOS-Constitutional-Engineering-Framework
  @ c7c4f7dc88ddc94800d493d6eb1001eaff3c3df0
  docs/protocols/LUMEN_INTEROP_CHALLENGE_SCOPE_BINDING_v0.1.md
  examples/interop/lumen-v0.1.scope-binding-mismatch.json

The vector asserts: content integrity is valid, the policy decision is `ask`,
the approval status is `approved`, execution is `completed`, and the approval's
scope digest is NOT the canonical commitment to the executed tool + arguments.
Expected verdict: FAIL on approval scope mismatch.

This script does two separate things, and keeps them separate on purpose:

  1. RECOMPUTE the vector's two load-bearing digests from the raw fixture with
     local code, so the claim is checked rather than taken. This does not use
     the CognOS verifier.

  2. TRANSLITERATE the vector onto the harness's own receipt-claim model
     (protocol_tests/receipt_claim_harness.py) and run the harness's
     ClaimLevelVerifier against it, unmodified. That is the actual question the
     issue asks: does an implementation built independently, against a
     different record shape, return the same verdict for the same reason.

The fixture is NOT vendored into this repository. As of 2026-09-20 the CognOS
repository publishes no LICENSE, so there is no explicit permission to
redistribute the fixture. This script READS it from the author's own pinned
commit instead, which keeps his copy as the reference artifact, and verifies
the bytes against a recorded digest so that each run is known to use the bytes
this script was written against. The digest check establishes byte identity
with the pinned artifact; it does not by itself establish a reproduction --
stage 3 below is what does that.

Run:
    python3 interop/lumen_scope_binding_repro.py           # fetches the pinned fixture
    python3 interop/lumen_scope_binding_repro.py --fixture PATH   # offline, local copy
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from protocol_tests.receipt_claim_harness import (  # noqa: E402
    KEYS,
    ClaimLevelVerifier,
    _attest,
    _digest,
    _reseal,
)

ZERO_DIGEST = "0" * 64

# The fixture, pinned to the commit its author cited on issue #576.
FIXTURE_COMMIT = "c7c4f7dc88ddc94800d493d6eb1001eaff3c3df0"
FIXTURE_PATH = "examples/interop/lumen-v0.1.scope-binding-mismatch.json"
FIXTURE_URL = (
    "https://raw.githubusercontent.com/acprofessionale/"
    "CognOS-Constitutional-Engineering-Framework/"
    f"{FIXTURE_COMMIT}/{FIXTURE_PATH}"
)
# SHA-256 over the exact bytes served at that commit, recorded 2026-09-20.
# A mismatch means the artifact read is not the one this script was written
# against, so the run aborts rather than warning.
FIXTURE_SHA256 = "cc3a2c6535926e0d9d7e68010fc5eee472df275370f771f99952c81905765056"


def load_fixture(local_path: Path | None) -> bytes:
    """Return the fixture bytes, pinned by digest either way."""
    if local_path is not None:
        raw = local_path.read_bytes()
        source = str(local_path)
    else:
        try:
            with urllib.request.urlopen(FIXTURE_URL, timeout=30) as response:
                raw = response.read()
        except urllib.error.URLError as exc:
            raise SystemExit(
                f"could not read the pinned fixture: {exc}\n"
                f"  url      : {FIXTURE_URL}\n"
                f"  sha256   : {FIXTURE_SHA256}\n"
                "Fetch it by hand and re-run with --fixture PATH."
            ) from exc
        source = FIXTURE_URL

    actual = hashlib.sha256(raw).hexdigest()
    if actual != FIXTURE_SHA256:
        raise SystemExit(
            "fixture digest mismatch -- refusing to report a reproduction\n"
            f"  source   : {source}\n"
            f"  expected : {FIXTURE_SHA256}\n"
            f"  actual   : {actual}"
        )
    print(f"  fixture source            : {source}")
    print(f"  fixture sha256            : {actual} (pinned, verified)")
    return raw


# --- 1. check the vector's own claims, with local code ----------------------

def lumen_content_digest(passport: dict) -> str:
    """LUMEN v0.1 canonical content digest.

    Note the construction: `integrity.content_sha256` is SUBSTITUTED with a
    zero digest rather than the `integrity` block being removed. That keeps
    `integrity.algorithm` inside the commitment, so the hash covers the
    algorithm that produced it. Removing the block instead yields a different
    digest -- worth stating because it is the kind of detail an independent
    implementation gets wrong first.
    """
    payload = copy.deepcopy(passport)
    payload.setdefault("integrity", {})["content_sha256"] = ZERO_DIGEST
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def lumen_scope_digest(execution: dict) -> str:
    """The canonical approval-scope commitment: SHA-256 over {arguments_sha256, tool}."""
    payload = {
        "arguments_sha256": execution["arguments_sha256"],
        "tool": execution["tool"],
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


# --- 2. transliterate onto the harness receipt model ------------------------

def lumen_to_harness_receipt(passport: dict, now: int) -> dict:
    """Map a LUMEN Decision Passport onto the harness's receipt shape.

    The mapping is deliberately faithful to what the passport ACTUALLY commits
    to, not to what a well-formed receipt would commit to:

      execution.tool + execution.arguments_sha256  ->  action
      governance.approval.scope_digest             ->  authorization claim
      execution.status == "completed"              ->  occurrence claim

    The harness decomposes authorization into TWO predicates where LUMEN has
    one. LUMEN's single `scope_digest` covers (tool, arguments) jointly; the
    harness checks `action_digest` (the whole action) and `params_digest` (the
    arguments) separately. The transliteration therefore drives BOTH from the
    passport's one scope digest, which is what makes the mismatch visible on
    each predicate independently.
    """
    execution = passport["execution"]
    approval = passport["governance"]["approval"]

    # The action that was actually executed, as the passport records it.
    action = {
        "tool": execution["tool"],
        "params": {"arguments_sha256": execution["arguments_sha256"]},
    }
    action_digest = _digest(action)

    # The authorization claim carries the APPROVED scope, not the executed one.
    # In a well-formed passport these coincide; in this vector they do not.
    approved_scope = approval["scope_digest"]

    receipt = {
        "action": action,
        "action_digest": action_digest,
        "tool_set_digest": _digest([{"name": execution["tool"]}]),
        "claims": {
            # Bound to the APPROVED scope digest, which is what the passport
            # actually attests. The harness will compare it to the executed one.
            "authorization": _attest(
                KEYS["authz"],
                {"action_digest": approved_scope, "params_digest": approved_scope},
            ),
            "occurrence": _attest(
                KEYS["exec"],
                {
                    "action_digest": action_digest,
                    "outcome_digest": _digest({"status": execution["status"]}),
                },
            ),
            "check": _attest(
                KEYS["checker"],
                {
                    "checker_id": "lumen-interop",
                    "version": "0.1",
                    "policy_digest": _digest(
                        {"policy_refs": passport["governance"]["policy_refs"]}
                    ),
                    "input_digest": _digest([{"name": execution["tool"]}]),
                    "output": "pass",
                    "issued_at": now,
                },
            ),
        },
    }
    return _reseal(receipt)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--fixture",
        type=Path,
        default=None,
        help="read the fixture from a local path instead of the pinned URL",
    )
    args = parser.parse_args(argv)

    print("== 0. the artifact under reproduction ==")
    passport = json.loads(load_fixture(args.fixture))

    print("\n== 1. the vector's own claims, recomputed locally ==")
    declared = passport["integrity"]["content_sha256"]
    recomputed = lumen_content_digest(passport)
    print(f"  content digest declared   : {declared}")
    print(f"  content digest recomputed : {recomputed}")
    integrity_ok = declared == recomputed
    print(f"  -> content integrity      : {'VALID' if integrity_ok else 'INVALID'}")

    canonical_scope = lumen_scope_digest(passport["execution"])
    approved_scope = passport["governance"]["approval"]["scope_digest"]
    print(f"\n  canonical scope digest    : {canonical_scope}")
    print(f"  approval.scope_digest     : {approved_scope}")
    scope_bound = canonical_scope == approved_scope
    print(f"  -> approval scope         : {'BOUND' if scope_bound else 'NOT BOUND'}")

    gov = passport["governance"]
    print(
        f"\n  decision={gov['decision']!r} "
        f"approval.status={gov['approval']['status']!r} "
        f"execution.status={passport['execution']['status']!r}"
    )

    print("\n== 2. the harness's own verifier, run on the transliterated receipt ==")
    now = 1_758_000_000
    receipt = lumen_to_harness_receipt(passport, now)
    verifier = ClaimLevelVerifier(now)
    print(f"  envelope signature        : {'verifies' if verifier.verify_envelope(receipt) else 'INVALID'}")
    outcome = verifier.verify(receipt)
    print(f"  verdict                   : {outcome.verdict.upper()}")
    print(f"  reason                    : {outcome.reason}")

    print("\n== 3. positive control: bind the approval to the executed scope ==")
    # A verifier that rejects everything has not reproduced anything. Repair the
    # ONE defect the vector encodes and the same verifier must accept.
    repaired = copy.deepcopy(passport)
    repaired["governance"]["approval"]["scope_digest"] = canonical_scope
    control_receipt = lumen_to_harness_receipt(repaired, now)
    # The transliteration keys authorization off scope_digest, so a bound
    # approval must now equal the executed action's digests.
    control_receipt["claims"]["authorization"] = _attest(
        KEYS["authz"],
        {
            "action_digest": control_receipt["action_digest"],
            "params_digest": _digest(control_receipt["action"]["params"]),
        },
    )
    control_receipt = _reseal(control_receipt)
    control = verifier.verify(control_receipt)
    print(f"  verdict                   : {control.verdict.upper()}")
    print(f"  reason                    : {control.reason or '(accepted)'}")

    print("\n== summary ==")
    reproduced = (
        integrity_ok
        and not scope_bound
        and outcome.verdict == "reject"
        and control.verdict == "accept"
    )
    print(
        "  REPRODUCED: content-integrity-valid, scope-mismatched receipt is\n"
        "  rejected by an independently-built verifier, and the same verifier\n"
        "  accepts it once the scope binding is repaired."
        if reproduced
        else "  NOT REPRODUCED -- see the lines above."
    )
    return 0 if reproduced else 1


if __name__ == "__main__":
    raise SystemExit(main())
