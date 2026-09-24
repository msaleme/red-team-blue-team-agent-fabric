#!/usr/bin/env python3
"""ABV v0.1 reference checker — dependency-free.

This is a REFERENCE, not an authority. Its purpose is to demonstrate that the
vector set is satisfiable: a checker can exist that rejects every negative for
the right predicate AND accepts every control. An implementation that disagrees
with this one is not thereby wrong; it is a result worth reporting.

Usage:
    python3 check.py            # run the whole corpus, report pass/fail
    python3 check.py <file>     # check one record, print the verdict
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sys
from datetime import datetime
from pathlib import Path

KEYS = {"approver.example": b"abv/approver", "executor.example": b"abv/executor"}
BLOBS = {
    "blob://plan-v1": b'{"target":"prod","replicas":3}',
    "blob://plan-v2": b'{"target":"prod","replicas":300}',
}


def jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(obj) -> str:
    return hashlib.sha256(jcs(obj)).hexdigest()


def resolve(args: dict) -> dict:
    """Replace every {"$ref": uri} with the digest of the DEREFERENCED bytes.

    This is P3 in one function. A checker that skips it -- comparing the
    reference string instead -- accepts NEG-P3-01 and NEG-P3-02.
    """
    out = {}
    for k, v in args.items():
        if isinstance(v, dict) and "$ref" in v:
            uri = v["$ref"]
            if uri not in BLOBS:
                raise KeyError(uri)
            out[k] = hashlib.sha256(BLOBS[uri]).hexdigest()
        else:
            out[k] = v
    return out


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


class Reject(Exception):
    def __init__(self, predicate: str, reason: str):
        super().__init__(reason)
        self.predicate = predicate
        self.reason = reason


def verify(rec: dict) -> tuple[str, str | None, str]:
    approval = rec["approval"]
    scope = approval["scope"]
    executions = rec["execution"]
    if isinstance(executions, dict):
        executions = [executions]

    # P5 -- separate attester. Checked first: an unattested approval makes every
    # later comparison a comparison against something nobody stands behind.
    # NOTE: this establishes separateness + authentication over the scope. It does
    # NOT establish that the attester was ENTITLED to approve this action.
    attestations = [a for a in rec.get("attestations", []) if a.get("claim") == "approval"]
    if not attestations:
        raise Reject("P5", "no approval attestation")
    executors = {e.get("by") for e in executions}
    for a in attestations:
        auth = a.get("authority")
        if auth in executors:
            raise Reject("P5", f"approval attested by the executing party ({auth})")
        if auth not in KEYS:
            raise Reject("P5", f"unknown attesting authority {auth}")
        expected = hmac.new(KEYS[auth], jcs(scope), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, a.get("mac", "")):
            raise Reject("P5", "approval attestation does not verify over the scope")

    # P6 -- single use. An approval authorises at most one execution, whatever nonce
    # each execution claims. v0.1.1 only compared nonces for duplicates, so one approval
    # executed twice under distinct nonce values was accepted (NEG-P6-02).
    if len(executions) > 1:
        raise Reject("P6", f"one approval, {len(executions)} executions")

    for ex in executions:
        # P1 -- action.
        if ex.get("action") != scope.get("action"):
            raise Reject("P1", f"approved action {scope.get('action')!r}, executed {ex.get('action')!r}")

        # P3 / P2 -- dereference, then arguments.
        try:
            executed_args = resolve(ex.get("arguments", {}))
        except KeyError as e:
            raise Reject("P3", f"unresolvable reference {e}")
        executed_digest = digest(executed_args)

        if executed_digest != scope.get("arguments_digest"):
            # Distinguish P3 from P2: if the approval's digest matches the
            # UNRESOLVED form, the approval committed a reference string and
            # the referenced bytes were never bound.
            if digest(ex.get("arguments", {})) == scope.get("arguments_digest"):
                raise Reject("P3", "approval committed the reference, not the dereferenced bytes")
            # If the reference changed but everything else is equal, that is
            # also P3: the commitment was over bytes the execution did not use.
            refs_changed = any(
                isinstance(v, dict) and "$ref" in v for v in ex.get("arguments", {}).values()
            )
            if refs_changed:
                raise Reject("P3", "referenced bytes at execution are not the approved bytes")
            raise Reject("P2", "executed arguments are not the approved arguments")

        # P4 -- freshness.
        if "not_after" in approval and ts(ex["at"]) > ts(approval["not_after"]):
            raise Reject("P4", f"executed at {ex['at']} after approval expired {approval['not_after']}")

    return ("accept", None, "all six predicates hold")


def check_one(path: Path) -> tuple[bool, str]:
    rec = json.loads(path.read_text())
    want = rec.get("expect", {})
    try:
        verdict, pred, reason = verify(rec)
    except Reject as r:
        verdict, pred, reason = "reject", r.predicate, r.reason

    if want.get("verdict") != verdict:
        return False, f"expected {want.get('verdict')}, got {verdict} ({reason})"
    if verdict == "reject" and want.get("predicate") != pred:
        return False, f"rejected for {pred}, expected {want.get('predicate')} ({reason})"
    detail = reason if verdict == "accept" else f"{pred}: {reason}"
    return True, detail


def main() -> int:
    if len(sys.argv) > 1:
        ok, detail = check_one(Path(sys.argv[1]))
        print(("PASS " if ok else "FAIL ") + detail)
        return 0 if ok else 1

    vectors = sorted((Path(__file__).parent / "vectors").glob("*.json"))
    failures = 0
    ctrl_accepted = 0
    for v in vectors:
        ok, detail = check_one(v)
        print(f"  {'PASS' if ok else 'FAIL'}  {v.stem:<12} {detail}")
        failures += not ok
        if ok and v.stem.startswith("CTRL"):
            ctrl_accepted += 1

    total = len(vectors)
    print(f"\n{total - failures}/{total} vectors behaved as specified")

    # The acceptance control on the corpus itself.
    if ctrl_accepted == 0:
        print("NO RESULT: no positive control was accepted. A checker that rejects "
              "everything satisfies every negative vector; this run proves nothing.")
        return 2
    print(f"acceptance controls: {ctrl_accepted} accepted "
          f"(a run with 0 is not a result, regardless of the negatives)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
