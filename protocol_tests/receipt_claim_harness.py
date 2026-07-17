#!/usr/bin/env python3
"""Receipt Claim-Level Verification Harness (RCL-001..RCL-008).

The point this suite makes executable: a **format-valid, correctly signed
receipt** can still be **claim-invalid**, and a claim-level verifier must reject
it on semantic grounds even though envelope-signature verification succeeds.

An action receipt is decomposed into four separately assessable properties;
signing supports only the first:

    integrity/provenance | occurrence | authorization | check execution+integrity

Evidence for the other three must be attested by *distinct trust domains*, not by
the receipt emitter (which the threat model permits to lie):

    emitter        — signs the receipt envelope
    checker auth   — attests a check ran (id/version/policy/input digest, output)
    authorization  — attests the exact action+params were authorized
    execution auth — attests the action occurred / settled

The verifier requires each claimed property to be attested by the correct
authority, fresh, and bound to this action. Each negative vector below builds a
receipt whose *envelope signature verifies* but whose claims are missing, stale,
substituted, replayed, or bound to the wrong thing; the verifier must reject it.

Cryptography is modeled with HMAC-SHA256 (stdlib only, per the repo's
zero-extra-dependency guarantee for ``protocol_tests``); the accept/reject
*decisions* under test do not depend on the primitive.

Usage:
    python -m protocol_tests.receipt_claim_harness --simulate
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import time
from dataclasses import dataclass

from protocol_tests._utils import Severity

FRESHNESS_WINDOW = 300  # seconds a checker transcript stays fresh


# --- stdlib crypto model ----------------------------------------------------

def _jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(obj) -> str:
    return hashlib.sha256(_jcs(obj)).hexdigest()


def _mac(key: bytes, body: dict) -> str:
    return hmac.new(key, _jcs(body), hashlib.sha256).hexdigest()


def _attest(key: bytes, block: dict) -> dict:
    """Sign a claim block with an authority key (sig computed over block-minus-sig)."""
    body = {k: v for k, v in block.items() if k != "sig"}
    block["sig"] = _mac(key, body)
    return block


def _attest_ok(key: bytes, block: dict) -> bool:
    body = {k: v for k, v in block.items() if k != "sig"}
    return hmac.compare_digest(block.get("sig", ""), _mac(key, body))


# --- authorities / keys -----------------------------------------------------

KEYS = {
    "emitter": b"emitter-key",
    "checker": b"checker-authority-key",
    "authz": b"authorization-authority-key",
    "exec": b"execution-settlement-authority-key",
}


# --- receipt construction ---------------------------------------------------

def _reseal(receipt: dict) -> dict:
    """Recompute the emitter's envelope signature over the (possibly tampered)
    body. Models an emitter that validly signs whatever it emits."""
    body = {k: v for k, v in receipt.items() if k != "envelope_sig"}
    receipt["envelope_sig"] = _mac(KEYS["emitter"], body)
    return receipt


def build_valid_receipt(now: int) -> dict:
    action = {"tool": "transfer", "params": {"to": "acct-A", "amount": 100}}
    tool_set = [{"name": "transfer", "description": "moves funds"},
                {"name": "lookup", "description": "reads balance"}]
    action_digest = _digest(action)
    tool_set_digest = _digest(tool_set)
    r = {
        "action": action,
        "action_digest": action_digest,
        "tool_set_digest": tool_set_digest,
        "claims": {
            "authorization": _attest(KEYS["authz"], {
                "action_digest": action_digest,
                "params_digest": _digest(action["params"]),
            }),
            "occurrence": _attest(KEYS["exec"], {
                "action_digest": action_digest,
                "outcome_digest": _digest({"status": "settled"}),
            }),
            "check": _attest(KEYS["checker"], {
                "checker_id": "tool-scan", "version": "1.0",
                "policy_digest": _digest({"policy": "no-injection"}),
                "input_digest": tool_set_digest,
                "output": "pass",
                "issued_at": now,
            }),
        },
    }
    return _reseal(r)


# --- claim-level verifier ---------------------------------------------------

@dataclass
class Outcome:
    verdict: str      # accept | reject
    reason: str


class ClaimLevelVerifier:
    """Rejects a receipt whose claims are not semantically supported by the
    correct authority, even when the envelope signature verifies."""

    def __init__(self, now: int, window: int = FRESHNESS_WINDOW):
        self.now = now
        self.window = window

    def verify_envelope(self, receipt: dict) -> bool:
        body = {k: v for k, v in receipt.items() if k != "envelope_sig"}
        return hmac.compare_digest(receipt.get("envelope_sig", ""),
                                   _mac(KEYS["emitter"], body))

    def verify(self, receipt: dict) -> Outcome:
        # 0. integrity: action digest must match the action.
        if receipt.get("action_digest") != _digest(receipt.get("action", {})):
            return Outcome("reject", "integrity: action_digest != hash(action)")
        # (envelope is assumed valid in this suite; check anyway)
        if not self.verify_envelope(receipt):
            return Outcome("reject", "integrity: envelope signature invalid")

        claims = receipt.get("claims", {})
        ad = receipt["action_digest"]

        # 1. authorization — must be attested by the authorization authority,
        #    bound to this action AND its exact parameters.
        az = claims.get("authorization")
        if not az:
            return Outcome("reject", "authorization: missing evidence")
        if not _attest_ok(KEYS["authz"], az):
            return Outcome("reject", "authorization: not attested by authorization authority")
        if az.get("action_digest") != ad:
            return Outcome("reject", "authorization: bound to a different action")
        if az.get("params_digest") != _digest(receipt["action"].get("params", {})):
            return Outcome("reject", "authorization: params do not match the action")

        # 2. occurrence — must be attested by the execution/settlement authority,
        #    bound to this action.
        oc = claims.get("occurrence")
        if not oc:
            return Outcome("reject", "occurrence: missing evidence")
        if not _attest_ok(KEYS["exec"], oc):
            return Outcome("reject", "occurrence: not attested by execution authority")
        if oc.get("action_digest") != ad:
            return Outcome("reject", "occurrence: acknowledgment bound to another action")

        # 3. check execution/integrity — must be an independent checker-authority
        #    attestation (not an emitter self-assertion), fresh, bound to this
        #    action's tool set, with a passing output.
        ck = claims.get("check")
        if not ck:
            return Outcome("reject", "check: missing evidence")
        if not _attest_ok(KEYS["checker"], ck):
            if _attest_ok(KEYS["emitter"], ck):
                return Outcome("reject", "check: attested by the emitter, not the checker authority")
            return Outcome("reject", "check: checker attestation does not verify (substituted or forged)")
        if self.now - int(ck.get("issued_at", 0)) > self.window:
            return Outcome("reject", "check: stale transcript (outside freshness window)")
        if ck.get("input_digest") != receipt.get("tool_set_digest"):
            return Outcome("reject", "check: result bound to the wrong tool-set digest")
        if ck.get("output") != "pass":
            return Outcome("reject", "check: recorded output is not a pass")

        return Outcome("accept", "all four properties independently supported")


# --- negative receipt vectors (each: envelope-valid, claim-invalid) ---------

def rcl_001_omitted_evidence(now):
    r = build_valid_receipt(now)
    del r["claims"]["occurrence"]          # drop a mandatory property
    return _reseal(r)


def rcl_002_substituted_evidence(now):
    r = build_valid_receipt(now)
    # Original checker attested output="fail"; emitter substitutes "pass" and
    # re-signs the ENVELOPE. The checker attestation no longer verifies.
    r["claims"]["check"] = _attest(KEYS["checker"], {
        "checker_id": "tool-scan", "version": "1.0",
        "policy_digest": _digest({"policy": "no-injection"}),
        "input_digest": r["tool_set_digest"], "output": "fail",
        "issued_at": now,
    })
    r["claims"]["check"]["output"] = "pass"   # tamper AFTER attestation
    return _reseal(r)


def rcl_003_stale_transcript(now):
    r = build_valid_receipt(now)
    ck = {k: v for k, v in r["claims"]["check"].items() if k != "sig"}
    ck["issued_at"] = now - (FRESHNESS_WINDOW + 60)
    r["claims"]["check"] = _attest(KEYS["checker"], ck)   # validly signed, but stale
    return _reseal(r)


def rcl_004_wrong_toolset_digest(now):
    r = build_valid_receipt(now)
    ck = {k: v for k, v in r["claims"]["check"].items() if k != "sig"}
    ck["input_digest"] = _digest([{"name": "other"}])     # a different tool set
    r["claims"]["check"] = _attest(KEYS["checker"], ck)    # valid attestation, wrong binding
    return _reseal(r)


def rcl_005_wrong_params(now):
    r = build_valid_receipt(now)
    az = {k: v for k, v in r["claims"]["authorization"].items() if k != "sig"}
    az["params_digest"] = _digest({"to": "acct-EVIL", "amount": 100})
    r["claims"]["authorization"] = _attest(KEYS["authz"], az)  # valid auth, different params
    return _reseal(r)


def rcl_006_wrong_action_ack(now):
    r = build_valid_receipt(now)
    oc = {k: v for k, v in r["claims"]["occurrence"].items() if k != "sig"}
    oc["action_digest"] = _digest({"tool": "other", "params": {}})
    r["claims"]["occurrence"] = _attest(KEYS["exec"], oc)  # valid exec ack for another action
    return _reseal(r)


def rcl_007_emitter_self_assertion(now):
    r = build_valid_receipt(now)
    ck = {k: v for k, v in r["claims"]["check"].items() if k != "sig"}
    r["claims"]["check"] = _attest(KEYS["emitter"], ck)   # emitter signs the check itself
    return _reseal(r)


NEGATIVES = [
    ("RCL-001", "Omitted mandatory evidence", rcl_001_omitted_evidence),
    ("RCL-002", "Substituted evidence, re-signed envelope", rcl_002_substituted_evidence),
    ("RCL-003", "Stale checker transcript", rcl_003_stale_transcript),
    ("RCL-004", "Check bound to the wrong tool-set digest", rcl_004_wrong_toolset_digest),
    ("RCL-005", "Authorization bound to different parameters", rcl_005_wrong_params),
    ("RCL-006", "Execution ack bound to another action", rcl_006_wrong_action_ack),
    ("RCL-007", "Emitter self-assertion, no independent attestation", rcl_007_emitter_self_assertion),
]


@dataclass
class RCLResult:
    test_id: str
    name: str
    category: str
    owasp_asi: str
    severity: str
    passed: bool
    details: str


class ReceiptClaimTests:
    """Each test builds a receipt whose envelope signature verifies but whose
    claims are not semantically supported; a PASS means the claim-level verifier
    correctly rejected it (RCL-001..007) or accepted a fully-supported receipt
    (RCL-008)."""

    def __init__(self, simulate: bool = False):
        self.simulate = simulate
        self.results: list[RCLResult] = []
        self.now = 1_750_000_000

    def _record(self, r: RCLResult):
        self.results.append(r)
        print(f"  {'PASS ✅' if r.passed else 'FAIL ❌'}  {r.test_id}: {r.name}")

    def _run_negative(self, test_id, name, builder):
        v = ClaimLevelVerifier(self.now)
        receipt = builder(self.now)
        envelope_valid = v.verify_envelope(receipt)
        outcome = v.verify(receipt)
        # Correct behavior: the envelope verifies AND the claim-level verdict is reject.
        passed = envelope_valid and outcome.verdict == "reject"
        self._record(RCLResult(
            test_id=test_id, name=name, category="receipt_claim",
            owasp_asi="ASI09", severity=Severity.HIGH.value, passed=passed,
            details=(f"envelope_valid={envelope_valid}; claim verdict="
                     f"{outcome.verdict} ({outcome.reason})")))

    def test_rcl_001(self):
        self._run_negative(test_id="RCL-001", name="Omitted mandatory evidence",
                           builder=rcl_001_omitted_evidence)

    def test_rcl_002(self):
        self._run_negative(test_id="RCL-002", name="Substituted evidence, re-signed envelope",
                           builder=rcl_002_substituted_evidence)

    def test_rcl_003(self):
        self._run_negative(test_id="RCL-003", name="Stale checker transcript",
                           builder=rcl_003_stale_transcript)

    def test_rcl_004(self):
        self._run_negative(test_id="RCL-004", name="Check bound to the wrong tool-set digest",
                           builder=rcl_004_wrong_toolset_digest)

    def test_rcl_005(self):
        self._run_negative(test_id="RCL-005", name="Authorization bound to different parameters",
                           builder=rcl_005_wrong_params)

    def test_rcl_006(self):
        self._run_negative(test_id="RCL-006", name="Execution ack bound to another action",
                           builder=rcl_006_wrong_action_ack)

    def test_rcl_007(self):
        self._run_negative(test_id="RCL-007", name="Emitter self-assertion, no independent attestation",
                           builder=rcl_007_emitter_self_assertion)

    def test_rcl_008(self):
        """RCL-008: positive control — a fully-supported receipt is accepted."""
        v = ClaimLevelVerifier(self.now)
        receipt = build_valid_receipt(self.now)
        envelope_valid = v.verify_envelope(receipt)
        outcome = v.verify(receipt)
        passed = envelope_valid and outcome.verdict == "accept"
        self._record(RCLResult(
            test_id="RCL-008", name="Fully-supported receipt accepted (control)",
            category="receipt_claim", owasp_asi="ASI09",
            severity=Severity.HIGH.value, passed=passed,
            details=f"envelope_valid={envelope_valid}; claim verdict={outcome.verdict}"))

    def run_all(self) -> list[RCLResult]:
        print("\n[RECEIPT CLAIM-LEVEL VERIFICATION]")
        for m in ("test_rcl_001", "test_rcl_002", "test_rcl_003", "test_rcl_004",
                  "test_rcl_005", "test_rcl_006", "test_rcl_007", "test_rcl_008"):
            getattr(self, m)()
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        print(f"\nRESULTS: {passed}/{total} passed")
        return self.results


def main():
    ap = argparse.ArgumentParser(description="Receipt claim-level verification harness")
    ap.add_argument("--simulate", action="store_true", help="offline reference run")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    tests = ReceiptClaimTests(simulate=args.simulate)
    results = tests.run_all()
    if args.json:
        from dataclasses import asdict
        print(json.dumps([asdict(r) for r in results], indent=2))


if __name__ == "__main__":
    main()
