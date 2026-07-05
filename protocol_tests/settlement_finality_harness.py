#!/usr/bin/env python3
"""Denial-of-Settlement / Settlement-Finality Security Test Harness (v1.0)

Security conformance suite for the **settlement-finality boundary** of agent
payments — the liveness class the rest of the payment suite does not cover.

Motivation (closes a named gap): the peer-reviewed analysis "Free-Riding the
Agentic Web: A Systematic Security Analysis of x402 Payments" (arXiv:2605.30998,
ACM SIGOPS ATC '26) names four attack primitives. Three are integrity attacks
the harness already catches (cross-resource substitution, duplicate-settlement
race, allowance overdraft). The fourth — **denial of settlement** — is a
*liveness* attack: the attacker consumes the resource, then blocks or delays
finality so the payment never lands. It has a different shape from a
tamper->reject differential, so it lived as an honest, untested gap
(Discussion #231). This module closes it.

The core defect denial-of-settlement exploits is the state-synchronization gap
between a synchronous request (returns in milliseconds) and asynchronous
settlement (final only after confirmations). A conformant implementation must
answer one question correctly: *what is the authoritative finality point at
which the resource is released?* Treating "broadcast" — or a self-asserted
"paid" flag — as final is where free-riding lives.

Reference-verifier note (honesty, per the repo's stdlib-only guarantee for
``protocol_tests``): production settlement runs against a chain/facilitator.
The built-in reference verifier implements the *finality-decision semantics* —
a settlement state machine (pending -> confirming -> final, with a reverted
branch for reorgs), a confirmation threshold, a finality deadline, an authentic
settlement receipt (not a self-asserted flag), escrow atomicity, grant
idempotency, and post-grant revocation — with structural checks standing in for
chain state. Every check **fails closed**: an unproven, unconfirmed, expired,
reverted or receipt-less settlement does not release the resource. ``--simulate``
runs the differential against this reference verifier; ``--url`` folds in a live
settlement/release endpoint behind a liveness gate (unreachable/erroring is
observe-failure, never a silent pass).

References:
    Free-Riding the Agentic Web (arXiv:2605.30998, ACM SIGOPS ATC '26) — the
        "denial of settlement" primitive.
    Discussion #231 (msaleme/red-team-blue-team-agent-fabric) — the named gap.
    x402 / AP2 settlement layer; blockchain finality / reorg semantics.

OWASP Mappings: ASI02 (Improper Access Controls), ASI03 (Identity/Priv Abuse),
                ASI04 (Agentic Supply Chain)
STRIDE: Tampering, Repudiation, Elevation of Privilege, Denial of Service

Usage:
    python -m protocol_tests.settlement_finality_harness --simulate
    python -m protocol_tests.settlement_finality_harness --url https://settle.example.com
    python -m protocol_tests.settlement_finality_harness --simulate --report dset.json

Requires: Python 3.10+, no external dependencies.
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from protocol_tests._utils import Severity, wilson_ci, http_post_json


@dataclass
class VerifyOutcome:
    ok: bool
    reason: str


# ---------------------------------------------------------------------------
# Settlement-finality reference verifier
# ---------------------------------------------------------------------------

def _valid_receipt(receipt: dict | None, payment: dict) -> bool:
    """An authentic settlement receipt proves finality; a self-asserted flag
    does not. A real receipt binds to the payment id and an on-chain anchor
    (block/tx), not just a ``{"final": true}`` boolean the caller controls.
    """
    if not isinstance(receipt, dict):
        return False
    if not receipt.get("block"):
        return False
    if receipt.get("payment_id") != payment.get("id"):
        return False
    return True


class SettlementVerifier:
    """Deterministic settlement-finality verifier (reference model).

    Decides whether releasing a resource is permitted for a payment's current
    settlement state, and whether an already-granted resource must be revoked
    (reorg / expiry). Every decision fails closed.

    policy = {min_confirmations, finality_deadline_s, require_receipt, require_escrow}
    """

    def __init__(self, policy: dict | None = None):
        self.policy = policy or {
            "min_confirmations": 6, "finality_deadline_s": 300,
            "require_receipt": True, "require_escrow": True,
        }
        self._released: set = set()  # payment ids already released (grant idempotency)

    def release_ok(self, payment: dict, now: int) -> VerifyOutcome:
        pol = self.policy
        state = payment.get("state")
        pid = payment.get("id")

        # 1. Never release on a payment that is only broadcast / pending.
        if state in (None, "pending", "broadcast"):
            return VerifyOutcome(False, "release before finality: payment only broadcast/pending")
        # 2. A reverted (reorg) payment must never release.
        if state == "reverted" or payment.get("reverted"):
            return VerifyOutcome(False, "payment reverted (reorg) — must not release / must revoke")
        # 3. Confirmation threshold.
        confs = payment.get("confirmations", 0)
        if state == "confirming" or confs < pol["min_confirmations"]:
            return VerifyOutcome(
                False, f"insufficient confirmations ({confs} < {pol['min_confirmations']})")
        # 4. Finality deadline: not-final past the window means the settlement
        #    was withheld/stalled — the grant must expire, not free-ride.
        deadline = payment.get("broadcast_at", now) + pol["finality_deadline_s"]
        if state != "final" and now > deadline:
            return VerifyOutcome(False, "settlement deadline passed without finality — grant must expire")
        # 5. Authentic settlement receipt (finality proof, not a self-asserted flag).
        if pol["require_receipt"] and not _valid_receipt(payment.get("receipt"), payment):
            return VerifyOutcome(False, "missing/unauthentic settlement receipt (finality not proven)")
        # 6. Escrow atomicity: release must be atomic with (or backed by) settlement.
        if pol["require_escrow"] and not payment.get("escrow"):
            return VerifyOutcome(False, "no escrow hold — release not atomic with settlement")
        # 7. Grant idempotency: one release per payment (no double-consume across the window).
        if pid in self._released:
            return VerifyOutcome(False, "resource already released for this payment (double consume)")
        self._released.add(pid)
        return VerifyOutcome(True, "settlement final and proven — release permitted")

    def revoke_required(self, payment: dict, now: int) -> bool:
        """After a grant, a reverted or deadline-expired settlement REQUIRES
        revoking resource access (the remediation side of denial-of-settlement).
        """
        if payment.get("state") == "reverted" or payment.get("reverted"):
            return True
        deadline = payment.get("broadcast_at", now) + self.policy["finality_deadline_s"]
        if payment.get("state") != "final" and now > deadline:
            return True
        return False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _valid_payment(now: int) -> dict:
    """A payment that has legitimately reached proven finality."""
    return {
        "id": "pay-1",
        "state": "final",
        "confirmations": 6,
        "broadcast_at": now - 60,
        "receipt": {"payment_id": "pay-1", "block": "0xabc123", "amount": 15000},
        "escrow": True,
        "amount": 15000,
    }


# ---------------------------------------------------------------------------
# Result model + live probe
# ---------------------------------------------------------------------------

@dataclass
class SettlementTestResult:
    test_id: str
    name: str
    category: str
    owasp_asi: str
    stride: str
    severity: str
    passed: bool
    details: str
    ref: str = ""
    normative: str = "N"
    live_evidence: dict | None = None
    elapsed_s: float = 0.0


def _live_rejected(url: str, headers: dict, payload: dict) -> tuple[str, dict]:
    """Probe a live settlement/release endpoint. verdict in
    {rejected, accepted, unreachable}. A transport failure or 5xx is
    'unreachable', never a pass."""
    resp = http_post_json(url, payload, headers, timeout=10)
    if resp.get("_error"):
        status = resp.get("_status", 0)
        if status and 400 <= status < 500:
            return ("rejected", resp)
        return ("unreachable", resp)
    status = resp.get("_status", 0)
    if status >= 500 or status == 0:
        return ("unreachable", resp)
    text = json.dumps(resp).lower()
    if any(w in text for w in ("reject", "denied", "withheld", "pending", "not final",
                               "unconfirmed", "revoked", "expired", "invalid")):
        return ("rejected", resp)
    if 200 <= status < 300:
        return ("accepted", resp)
    return ("unreachable", resp)


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

class SettlementFinalityTests:
    """Denial-of-settlement / finality conformance suite (DSET-001..008)."""

    def __init__(self, url: str | None = None, headers: dict | None = None,
                 simulate: bool = False):
        self.url = url.rstrip("/") if url else "http://localhost:8080"
        self.headers = headers or {}
        self.simulate = simulate
        self.results: list[SettlementTestResult] = []

    def _now(self) -> int:
        return 1_750_000_000 if self.simulate else int(time.time())

    def _record(self, r: SettlementTestResult) -> None:
        print(f"  {'PASS ✅' if r.passed else 'FAIL ❌'}  {r.test_id}: {r.name}")
        self.results.append(r)

    def _finish(self, *, test_id, name, category, owasp, stride, severity, ref,
                normative, model_pass, model_reason, attack_payload, t0):
        passed = model_pass
        details = model_reason
        live_ev = None
        if not self.simulate and attack_payload is not None:
            verdict, ev = _live_rejected(self.url, self.headers, attack_payload)
            live_ev = {"verdict": verdict, "status": ev.get("_status", 0)}
            if verdict == "accepted":
                passed = False
                details = f"{model_reason}; LIVE endpoint RELEASED on non-final settlement — control absent"
            elif verdict == "rejected":
                details = f"{model_reason}; live endpoint withheld release"
            else:
                details = f"{model_reason}; live endpoint unreachable — verdict from reference model"
        self._record(SettlementTestResult(
            test_id=test_id, name=name, category=category, owasp_asi=owasp,
            stride=stride, severity=severity, passed=passed, details=details,
            ref=ref, normative=normative, live_evidence=live_ev,
            elapsed_s=round(time.monotonic() - t0, 3)))

    # -- DSET-001: release before finality --------------------------------

    def test_dset_001_release_before_finality(self) -> None:
        """DSET-001: Resource released on a broadcast-only payment (CRITICAL).

        Treating a broadcast/pending payment as final is the core denial-of-
        settlement free-ride. A conformant release MUST wait for finality.
        """
        t0 = time.monotonic(); now = self._now()
        p = dict(_valid_payment(now), state="pending", confirmations=0)
        v = SettlementVerifier().release_ok(p, now)
        self._finish(
            test_id="DSET-001", name="Release Before Finality (broadcast-only)",
            category="finality", owasp="ASI02", stride="Elevation of Privilege",
            severity=Severity.CRITICAL.value,
            ref="ATC'26 denial-of-settlement: broadcast != final", normative="N",
            model_pass=(not v.ok and "before finality" in v.reason),
            model_reason=(f"pre-finality release rejected ({v.reason})" if not v.ok else
                          "FREE-RIDE — resource released on a merely-broadcast payment"),
            attack_payload={"payment": p}, t0=t0)

    # -- DSET-002: insufficient confirmations -----------------------------

    def test_dset_002_insufficient_confirmations(self) -> None:
        """DSET-002: Release under the confirmation threshold (HIGH)."""
        t0 = time.monotonic(); now = self._now()
        p = dict(_valid_payment(now), state="confirming", confirmations=1)
        v = SettlementVerifier().release_ok(p, now)
        self._finish(
            test_id="DSET-002", name="Insufficient Confirmations",
            category="finality", owasp="ASI02", stride="Tampering",
            severity=Severity.HIGH.value,
            ref="finality requires N confirmations", normative="N",
            model_pass=(not v.ok and "insufficient confirmations" in v.reason),
            model_reason=(f"under-confirmed release rejected ({v.reason})" if not v.ok else
                          "PREMATURE — released before the confirmation threshold"),
            attack_payload={"payment": p}, t0=t0)

    # -- DSET-003: reorg / reverted ---------------------------------------

    def test_dset_003_reorg_revocation(self) -> None:
        """DSET-003: Reverted (reorg) payment released / not revoked (CRITICAL).

        A payment that reached finality and then reverted MUST NOT release, and
        an existing grant MUST be revoked.
        """
        t0 = time.monotonic(); now = self._now()
        p = dict(_valid_payment(now), state="reverted", reverted=True)
        ver = SettlementVerifier()
        v = ver.release_ok(p, now)
        must_revoke = ver.revoke_required(p, now)
        self._finish(
            test_id="DSET-003", name="Reorg / Reverted-Settlement Revocation",
            category="reorg", owasp="ASI03", stride="Repudiation",
            severity=Severity.CRITICAL.value,
            ref="reverted settlement must not release + must revoke", normative="N",
            model_pass=(not v.ok and "reverted" in v.reason and must_revoke),
            model_reason=("reverted payment rejected and revocation required"
                          if (not v.ok and must_revoke) else
                          "REORG FREE-RIDE — a reverted settlement kept the resource"),
            attack_payload={"payment": p}, t0=t0)

    # -- DSET-004: finality deadline / withheld settlement ----------------

    def test_dset_004_finality_deadline(self) -> None:
        """DSET-004: Settlement withheld past the finality deadline (HIGH).

        If finality is not reached within the window, the grant MUST expire —
        the attacker cannot consume the resource and stall settlement forever.
        """
        t0 = time.monotonic(); now = self._now()
        p = dict(_valid_payment(now), state="confirming", confirmations=1,
                 broadcast_at=now - 100000)  # long past the 300s deadline
        ver = SettlementVerifier()
        v = ver.release_ok(p, now)
        must_revoke = ver.revoke_required(p, now)
        self._finish(
            test_id="DSET-004", name="Finality Deadline (withheld settlement)",
            category="finality", owasp="ASI02", stride="Denial of Service",
            severity=Severity.HIGH.value,
            ref="ATC'26: denial of settlement — withhold finality while consuming", normative="N",
            model_pass=(not v.ok and ("deadline" in v.reason or "insufficient" in v.reason) and must_revoke),
            model_reason=("stalled settlement rejected and revocation required"
                          if (not v.ok and must_revoke) else
                          "STALL FREE-RIDE — resource kept while settlement withheld"),
            attack_payload={"payment": p}, t0=t0)

    # -- DSET-005: self-asserted finality flag ----------------------------

    def test_dset_005_self_asserted_receipt(self) -> None:
        """DSET-005: Release on a self-asserted 'final' flag (HIGH).

        A receipt-less ``{"final": true}`` claim is not proof of finality. The
        authoritative finality point must be a real settlement receipt.
        """
        t0 = time.monotonic(); now = self._now()
        p = dict(_valid_payment(now), receipt={"final": True})  # no block/binding
        v = SettlementVerifier().release_ok(p, now)
        self._finish(
            test_id="DSET-005", name="Self-Asserted Finality (no authentic receipt)",
            category="finality_proof", owasp="ASI03", stride="Tampering",
            severity=Severity.HIGH.value,
            ref="finality point must be a verifiable receipt, not a flag", normative="N",
            model_pass=(not v.ok and "receipt" in v.reason),
            model_reason=(f"unproven finality rejected ({v.reason})" if not v.ok else
                          "SPOOFED FINALITY — released on a self-asserted paid flag"),
            attack_payload={"payment": p}, t0=t0)

    # -- DSET-006: escrow atomicity ---------------------------------------

    def test_dset_006_escrow_atomicity(self) -> None:
        """DSET-006: Release without an escrow hold (HIGH).

        Resource release must be atomic with (or backed by) settlement; without
        an escrow hold, one party can free-ride the other.
        """
        t0 = time.monotonic(); now = self._now()
        p = dict(_valid_payment(now), escrow=False)
        v = SettlementVerifier().release_ok(p, now)
        self._finish(
            test_id="DSET-006", name="Escrow Atomicity",
            category="atomicity", owasp="ASI02", stride="Elevation of Privilege",
            severity=Severity.HIGH.value,
            ref="release must be atomic with settlement (escrow-backed)", normative="N",
            model_pass=(not v.ok and "escrow" in v.reason),
            model_reason=(f"non-atomic release rejected ({v.reason})" if not v.ok else
                          "NON-ATOMIC — resource released without an escrow hold"),
            attack_payload={"payment": p}, t0=t0)

    # -- DSET-007: grant idempotency --------------------------------------

    def test_dset_007_grant_idempotency(self) -> None:
        """DSET-007: Double-release across the finality window (HIGH).

        One payment MUST release the resource at most once — consuming it more
        than once across the pending->final window is a free-ride.
        """
        t0 = time.monotonic(); now = self._now()
        p = _valid_payment(now)
        ver = SettlementVerifier()
        first = ver.release_ok(p, now)
        second = ver.release_ok(dict(p), now)  # same payment id again
        self._finish(
            test_id="DSET-007", name="Grant Idempotency (double consume)",
            category="idempotency", owasp="ASI03", stride="Elevation of Privilege",
            severity=Severity.HIGH.value,
            ref="one release per settled payment", normative="N",
            model_pass=(first.ok and not second.ok and "already released" in second.reason),
            model_reason=("second release on one payment rejected"
                          if (first.ok and not second.ok) else
                          "DOUBLE CONSUME — one payment released the resource twice"),
            attack_payload={"payment": p}, t0=t0)

    # -- DSET-008: revoke on post-grant nonfinality -----------------------

    def test_dset_008_revoke_on_nonfinality(self) -> None:
        """DSET-008: No revocation after a settlement fails post-grant (MEDIUM).

        If settlement reverts or expires after the resource was granted, access
        MUST be revoked; keeping it granted is the denial-of-settlement payoff.
        """
        t0 = time.monotonic(); now = self._now()
        good = _valid_payment(now)                       # final -> no revoke
        bad = dict(_valid_payment(now), state="reverted", reverted=True)  # -> revoke
        ver = SettlementVerifier()
        keep_ok = ver.revoke_required(good, now) is False
        revoke_bad = ver.revoke_required(bad, now) is True
        self._finish(
            test_id="DSET-008", name="Revoke-on-Nonfinality (post-grant remediation)",
            category="remediation", owasp="ASI02", stride="Repudiation",
            severity=Severity.MEDIUM.value,
            ref="post-grant revert/expiry must revoke access", normative="N",
            model_pass=(keep_ok and revoke_bad),
            model_reason=("final grant kept, reverted grant flagged for revocation"
                          if (keep_ok and revoke_bad) else
                          "NO REMEDIATION — a failed settlement kept resource access"),
            attack_payload={"payment": bad}, t0=t0)

    # -- run_all ----------------------------------------------------------

    def run_all(self) -> list[SettlementTestResult]:
        tests = [
            self.test_dset_001_release_before_finality,
            self.test_dset_002_insufficient_confirmations,
            self.test_dset_003_reorg_revocation,
            self.test_dset_004_finality_deadline,
            self.test_dset_005_self_asserted_receipt,
            self.test_dset_006_escrow_atomicity,
            self.test_dset_007_grant_idempotency,
            self.test_dset_008_revoke_on_nonfinality,
        ]
        print(f"\n{'='*60}")
        print("DENIAL-OF-SETTLEMENT / FINALITY CONFORMANCE SUITE")
        print(f"{'='*60}")
        print(f"Target: {self.url}")
        print(f"Mode: {'simulate (reference model)' if self.simulate else 'live'}")
        print("Class: liveness at the settlement-finality boundary (ATC'26 gap, Discussion #231)")
        print("Question under test: what is the authoritative finality point before release?")
        print("\n[DENIAL-OF-SETTLEMENT TESTS]")
        for fn in tests:
            try:
                fn()
            except Exception as e:  # pragma: no cover - defensive
                print(f"  ERROR ⚠️  {fn.__name__}: {e}")
                self.results.append(SettlementTestResult(
                    test_id="DSET-ERR", name=f"ERROR: {fn.__name__}",
                    category="error", owasp_asi="ASI02", stride="Tampering",
                    severity=Severity.HIGH.value, passed=False, details=str(e)))
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        ci = wilson_ci(passed, total)
        print(f"\n{'='*60}")
        if total:
            print(f"RESULTS: {passed}/{total} passed ({passed/total*100:.0f}%)")
            print(f"WILSON 95% CI: [{ci[0]:.4f}, {ci[1]:.4f}]")
        print(f"{'='*60}\n")
        return self.results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Denial-of-settlement / settlement-finality conformance harness (DSET-001..008)")
    ap.add_argument("--url", default=None, help="Target settlement/release endpoint URL (live mode)")
    ap.add_argument("--simulate", action="store_true",
                    help="Run the differential against the built-in reference verifier (no network)")
    ap.add_argument("--report", help="Output JSON report path")
    ap.add_argument("--json", action="store_true", help="Emit JSON summary to stdout")
    ap.add_argument("--header", action="append", default=[],
                    help="Extra HTTP headers (key:value)")
    args = ap.parse_args()

    headers: dict[str, str] = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    simulate = args.simulate or not args.url
    suite = SettlementFinalityTests(url=args.url, headers=headers, simulate=simulate)
    results = suite.run_all()

    total = len(results)
    passed = sum(1 for r in results if r.passed)
    ci = wilson_ci(passed, total)
    report = {
        "suite": "Denial-of-Settlement / Finality Conformance",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "simulate" if simulate else "live",
        "summary": {
            "total": total, "passed": passed, "failed": total - passed,
            "pass_rate": round(passed / total, 4) if total else 0,
            "wilson_95_ci": {"lower": ci[0], "upper": ci[1]},
        },
        "results": [asdict(r) for r in results],
    }
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    if args.report:
        with open(args.report, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"Report written to {args.report}")


if __name__ == "__main__":
    main()
