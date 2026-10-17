"""A stateful live row must replay its sequence, not only its last request (#653).

## The defect

Six rows test a control that exists only relative to earlier state: a velocity
cap needs earlier spend, a replay needs a first use, a double-spend needs a
first payment, a takeover needs a registered profile, a duplicate order needs a
first order. The reference model built that state in-process; the live leg sent
only the final request. A correct target saw a fresh credential, accepted it,
and the row reported "LIVE ... ACCEPTED the attack -- control absent". Every
released version through v4.27.0 graded a correct target FAIL on these rows,
unless earlier rows in the same run happened to leave the right state, which is
order-dependent. Every row also shared one credential id (``ntk-1``,
``open-1``, ``agent-prof-1``, ``sess-1``), so earlier rows' state could spoil a
later row's setup.

Rows: CTK-004, CTK-005 (`card_token_harness`); AP2-011, AP2-013
(`ap2_harness`); UCP-006, ACP-004 (`ucp_acp_harness`). The issue listed three;
a sweep of every `_finish` caller that reuses one verifier instance found the
other three. FB-014 and FB-017 have the same model shape but send no live probe
(``attack_payload=None``), so they are INCONCLUSIVE live and are not affected.

## Truth table (written before the fix)

| Target shape | Setup steps | Final step | Row |
|---|---|---|---|
| STATEFUL_CORRECT: enforces the control | accepted | rejected | PASS |
| PERMISSIVE: accepts everything | accepted | accepted | FAIL |
| REFUSES_ALL: rejects everything | step 1 rejected | not sent | INCONCLUSIVE |

The accepted setup steps are the positive control: a target that refuses
everything never gets past step 1, so its refusal of the final step is never
scored. Each row uses its own credential id, so the full suite run against
STATEFUL_CORRECT must still PASS all six (order independence).

## What this does not establish

That any real authorizer or verifier keys its state the way these stubs do. A
target that rejects every Nth request regardless of content would PASS CTK-004;
the row has no within-cap third-charge control. That limit is unchanged.
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.ap2_harness import AP2MandateTests  # noqa: E402
from protocol_tests.card_token_harness import CardTokenTests  # noqa: E402
from protocol_tests.ucp_acp_harness import UCPACPJourneyTests  # noqa: E402

ROWS = {
    "CTK-004": (CardTokenTests, "test_ctk_004_velocity_cap"),
    "CTK-005": (CardTokenTests, "test_ctk_005_cryptogram_replay"),
    "AP2-011": (AP2MandateTests, "test_ap2_011_payment_replay"),
    "AP2-013": (AP2MandateTests, "test_ap2_013_double_spend"),
    "UCP-006": (UCPACPJourneyTests, "test_ucp_006_profile_rebind"),
    "ACP-004": (UCPACPJourneyTests, "test_acp_004_order_idempotency"),
}

ACCEPT = (200, {"approved": True})
REJECT = (403, {"error": "denied"})


class StatefulCorrect:
    """Enforces exactly the stateful controls the six rows test, nothing else."""

    def __init__(self):
        self.spent, self.counter = {}, {}
        self.jti, self.open_used = set(), set()
        self.profiles, self.orders = {}, set()

    def decide(self, body: dict):
        if "token" in body:
            tok, txn = body["token"], body["transaction"]
            tid, amt, ctr = tok["token_id"], txn["amount"], txn["counter"]
            if ctr <= self.counter.get(tid, 0):
                return REJECT
            if self.spent.get(tid, 0) + amt > tok["velocity_cap"]:
                return REJECT
            self.counter[tid] = ctr
            self.spent[tid] = self.spent.get(tid, 0) + amt
            return ACCEPT
        if "payment_mandate" in body:
            pm = body["payment_mandate"]
            if pm["jti"] in self.jti or pm["open_mandate_id"] in self.open_used:
                return REJECT
            self.jti.add(pm["jti"])
            self.open_used.add(pm["open_mandate_id"])
            return ACCEPT
        if "profile" in body:
            p = body["profile"]
            owner = self.profiles.setdefault(p["profile_id"], p["owner_kid"])
            return ACCEPT if owner == p["owner_kid"] else REJECT
        if "completion" in body:
            c = body["completion"]
            key = (c["session_id"], c["idem_key"])
            if key in self.orders:
                return REJECT
            self.orders.add(key)
            return ACCEPT
        return ACCEPT


class Permissive:
    def decide(self, body):
        return ACCEPT


class RefusesAll:
    def decide(self, body):
        return REJECT


class _Server:
    def __init__(self, policy):
        self.policy = policy
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("content-length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                status, out = outer.policy.decide(body)
                data = json.dumps(out).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _run_row(policy, row_id):
    cls, meth = ROWS[row_id]
    srv = _Server(policy)
    try:
        suite = cls(url=srv.url, simulate=False)
        getattr(suite, meth)()
        (r,) = [x for x in suite.results if x.test_id == row_id]
        return r
    finally:
        srv.close()


class StatefulRowTruthTable(unittest.TestCase):

    def test_stateful_correct_target_passes(self):
        for row in ROWS:
            with self.subTest(row=row):
                r = _run_row(StatefulCorrect(), row)
                self.assertFalse(r.not_evaluated, r.details)
                self.assertTrue(r.passed, r.details)
                self.assertTrue(all(s["verdict"] == "accepted"
                                    for s in r.live_evidence["setup"]))
                self.assertEqual(r.live_evidence["verdict"], "rejected")

    def test_permissive_target_fails(self):
        for row in ROWS:
            with self.subTest(row=row):
                r = _run_row(Permissive(), row)
                self.assertFalse(r.not_evaluated, r.details)
                self.assertFalse(r.passed)
                self.assertIn("ACCEPTED the attack", r.details)

    def test_refuse_all_target_is_inconclusive(self):
        for row in ROWS:
            with self.subTest(row=row):
                r = _run_row(RefusesAll(), row)
                self.assertTrue(r.not_evaluated, r.details)
                self.assertFalse(r.passed)
                self.assertIn("setup step 1", r.details)
                self.assertEqual(r.live_evidence["verdict"], "rejected")
                self.assertEqual(r.live_evidence["stopped_at_setup_step"], 1)

    def test_full_suites_are_order_independent(self):
        """Every other row runs first against the same stateful target."""
        for cls in {c for c, _ in ROWS.values()}:
            with self.subTest(suite=cls.__name__):
                srv = _Server(StatefulCorrect())
                try:
                    suite = cls(url=srv.url, simulate=False)
                    suite.run_all()
                finally:
                    srv.close()
                mine = {r.test_id: r for r in suite.results if r.test_id in ROWS}
                self.assertTrue(mine)
                for rid, r in mine.items():
                    self.assertTrue(r.passed and not r.not_evaluated,
                                    f"{rid}: {r.details}")


def sweep(directory: Path) -> tuple[set[str], list[str]]:
    """``(stateful_rows, offenders)`` over every ``*.py`` in ``directory``.

    A stateful row: a ``test_*`` method that calls one non-``self`` object's
    ``authorize*``/``verify*``/``redeem*`` at least twice and hands `_finish`
    a live probe. An offender: such a row with no ``setup_payloads``.
    """
    import ast
    found, offenders = set(), []
    for f in sorted(directory.glob("*.py")):
        src = f.read_text()
        if "def _finish" not in src:
            continue
        for cls in ast.walk(ast.parse(src)):
            if not isinstance(cls, ast.ClassDef):
                continue
            for fn in cls.body:
                if not (isinstance(fn, ast.FunctionDef) and fn.name.startswith("test_")):
                    continue
                uses, finish = {}, None
                for n in ast.walk(fn):
                    if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)):
                        continue
                    if n.func.attr == "_finish":
                        finish = n
                    elif (isinstance(n.func.value, ast.Name) and n.func.value.id != "self"
                            and n.func.attr.startswith(("authorize", "verify", "redeem"))):
                        uses[n.func.value.id] = uses.get(n.func.value.id, 0) + 1
                if not finish or max(uses.values(), default=0) < 2:
                    continue
                kw = {k.arg: k.value for k in finish.keywords}
                probe = kw.get("attack_payload")
                if isinstance(probe, ast.Constant) and probe.value is None:
                    continue  # no live probe: INCONCLUSIVE live, not affected
                found.add(fn.name)
                if "setup_payloads" not in kw:
                    offenders.append(f"{f.name}:{fn.lineno} {fn.name}")
    return found, offenders


class EveryStatefulLiveRowReplaysItsSetup(unittest.TestCase):
    """The sweep, as a ratchet: a test that reuses one verifier instance for
    several decisions and sends a live probe must pass ``setup_payloads``.
    Its seeded control pair lives in `test_static_detectors_can_fire`."""

    def test_sweep(self):
        found, offenders = sweep(REPO_ROOT / "protocol_tests")
        self.assertEqual(offenders, [], "stateful rows sending only their last request live")
        self.assertEqual(found, {m for _, m in ROWS.values()})


if __name__ == "__main__":
    unittest.main()
