"""x402 and L402 verdicts need a payment surface: a URL that answers 402.

`x402_harness` and `l402_harness` grade a server that demands payment. Against
a host answering HTTP 404 to everything, and against one answering a bare 403
to everything, x402 PASSed 41 tests ("5/5 malformed authorizations rejected":
a 404 is not a 200) and FAILed six ("Expected HTTP 402, got 404"); l402 PASSed
14 ("4/4 malformed tokens rejected") and FAILed 12. The silence guard (#351)
fires only when nothing answered, so an error page counted as an answer.
`testing/test_verdicts_need_a_surface.py` registered the 146 cells.

Owner decision 2026-09-24: a URL that never answers HTTP 402 has no payment
surface. One rule, `http_helpers.payment_surface_detail`, used by both
modules' `_record`: one unpaid request to the protected resource (the request
the module's own challenge fetch sends), sent once per transport, decides it.

Truth table, each pole a real stdlib server on loopback:

    closed port, 404 everywhere, bare 403 everywhere       INCONCLUSIVE (all)
    402 + conformant challenge, rejects every payment      registered PASS
                                                            tests PASS; the
                                                            challenge checks PASS
    402 + conformant challenge, serves any paid request    the payment-rejection
                                                            tests FAIL
    402 with a non-conformant challenge                    the conformance
                                                            tests FAIL
    200 to everything (resource served without payment)    graded, as before:
                                                            X4-001 / L4-001 FAIL

The last row is deliberate. A 2xx on the protected resource is an observation
about that resource (the paywall is absent or bypassable), so it is not the
no-surface case, and the allow-all registers in test_permissive_host_state are
unchanged by this rule.
"""

from __future__ import annotations

import contextlib
import io
import socket
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.http_helpers import row_outcome  # noqa: E402
from protocol_tests.l402_harness import L402SecurityTests, L402Transport  # noqa: E402
from protocol_tests.x402_harness import X402SecurityTests, X402Transport  # noqa: E402

_MACAROON = ('L402 macaroon="AGIAJEemVQUTEyNCR0exk7ek90Cg==", '
             'invoice="lnbc1500n1pexample"')
_X402_CHALLENGE = {
    "X-Payment-Required": "true",
    "X-Payment-Amount": "1000000",
    "X-Payment-Currency": "USDC",
    "X-Payment-Recipient": "0x" + "ab" * 20,
    "X-Payment-Network": "base",
}

# The cells test_verdicts_need_a_surface registered on the 404 and 403 poles,
# per test ID, as measured at a858702 (origin/main before this change).
X402_WAS_PASS = frozenset(
    ["X4-002", "X4-003", "X4-005", "X4-006", "X4-008", "X4-009", "X4-010",
     "X4-012", "X4-014", "X4-015", "X4-016", "X4-017", "X4-018", "X4-019",
     "X4-020", "X4-024", "X4-025", "X4-026", "X4-027"]
    + [f"X4-0{n}" for n in range(31, 42)]
    + [f"X4-0{n}" for n in range(43, 54)])
X402_WAS_FAIL = frozenset(["X4-001", "X4-004", "X4-013", "X4-021", "X4-022", "X4-023"])
L402_WAS_PASS = frozenset(
    ["L4-002", "L4-003", "L4-007", "L4-011", "L4-019", "L4-020", "L4-021",
     "L4-023", "L4-025", "L4-027", "L4-029", "L4-031", "L4-032", "L4-033"])
L402_WAS_FAIL = frozenset(
    ["L4-001", "L4-004", "L4-005", "L4-006", "L4-009", "L4-010", "L4-015",
     "L4-016", "L4-017", "L4-018", "L4-022", "L4-030"])

#: Registered PASS tests that do not grade acceptance of a payment, so a
#: server that serves any paid request does not fail them: session-token and
#: attestation forgeries (the stub serves on a payment header, not a token),
#: leak and side-channel scans over the content returned, and L402 transport
#: resilience (oversized headers, a concurrent flood).
X402_NOT_ABOUT_PAYMENT_ACCEPTANCE = frozenset(
    ["X4-008", "X4-009", "X4-010", "X4-017", "X4-018", "X4-024", "X4-025", "X4-053"])
L402_NOT_ABOUT_PAYMENT_ACCEPTANCE = frozenset(["L4-029", "L4-031", "L4-033"])

#: Rows that grade the 402 challenge itself (and, for L402, the macaroon and
#: invoice it carries). A 402 whose challenge is not the protocol's must FAIL
#: them, and a conformant one must PASS them.
X402_CONFORMANCE = frozenset(["X4-001", "X4-004"])
L402_CONFORMANCE = L402_WAS_FAIL - {"L4-030"}


def _paid(headers) -> bool:
    auth = headers.get("Authorization") or ""
    return (headers.get("X-Payment-Authorization") is not None
            or bool(headers.get("X-Payment"))
            or auth.upper().startswith(("L402", "LSAT")))


def _handler(kind: str):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *args):
            pass

        def _answer(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            if kind == "404":
                status, headers, body = 404, {}, b"Not Found"
            elif kind == "403":
                status, headers, body = 403, {}, b"Forbidden"
            elif kind == "ok":
                status, headers, body = 200, {"Content-Type": "application/json"}, b'{"data":"x"}'
            elif kind == "nonconformant":
                status, headers, body = 402, {}, b"pay up"
            elif kind == "accept" and _paid(self.headers):
                status, headers, body = (200, {"Content-Type": "application/json"},
                                         b'{"data":"premium content"}')
            else:  # "reject", or "accept" on an unpaid request
                status = 402
                headers = {**_X402_CHALLENGE, "WWW-Authenticate": _MACAROON}
                body = b'{"error":"payment required"}'
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _answer

    return Handler


@contextlib.contextmanager
def _target(kind: str):
    if kind == "closed":
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        yield f"http://127.0.0.1:{port}"
        return
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _handler(kind))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


_CACHE: dict = {}


def _run(module: str, kind: str) -> dict:
    """test_id -> (outcome, details), for one module against one pole."""
    key = (module, kind)
    if key not in _CACHE:
        suite_cls, transport_cls = (
            (X402SecurityTests, X402Transport) if module == "x402"
            else (L402SecurityTests, L402Transport))
        with _target(kind) as url, contextlib.redirect_stdout(io.StringIO()):
            results = suite_cls(transport_cls(url)).run_all()
        _CACHE[key] = {r.test_id: (row_outcome(r), r.details) for r in results}
    return _CACHE[key]


def _with(rows: dict, outcome: str) -> set:
    return {tid for tid, (o, _d) in rows.items() if o == outcome}


class NoPaymentSurfaceIsInconclusive(unittest.TestCase):
    def test_every_row_is_inconclusive_on_every_no_surface_pole(self):
        for module in ("x402", "l402"):
            for kind in ("closed", "404", "403"):
                with self.subTest(module=module, pole=kind):
                    rows = _run(module, kind)
                    self.assertGreaterEqual(len(rows), 33)
                    graded = {t: o for t, (o, _d) in rows.items() if o != "INCONCLUSIVE"}
                    self.assertEqual(graded, {}, f"{module} graded on {kind}")

    def test_the_detail_names_the_missing_402(self):
        for module, word in (("x402", "no x402 payment surface"),
                             ("l402", "no L402 payment surface")):
            for kind, status in (("404", "status=404"), ("403", "status=403")):
                with self.subTest(module=module, pole=kind):
                    rows = _run(module, kind)
                    formerly = (X402_WAS_PASS | X402_WAS_FAIL if module == "x402"
                                else L402_WAS_PASS | L402_WAS_FAIL)
                    for tid in formerly:
                        detail = rows[tid][1]
                        self.assertIn(word, detail, tid)
                        self.assertIn(status, detail, tid)
                        self.assertIn("Original finding:", detail, tid)


class A402SurfaceIsStillGraded(unittest.TestCase):
    """The positive and negative controls: the rule must be able to be right."""

    CASES = (("x402", X402_WAS_PASS, X402_NOT_ABOUT_PAYMENT_ACCEPTANCE, X402_CONFORMANCE),
             ("l402", L402_WAS_PASS, L402_NOT_ABOUT_PAYMENT_ACCEPTANCE, L402_CONFORMANCE))

    def test_a_server_that_rejects_malformed_payments_passes(self):
        for module, was_pass, _n, conformance in self.CASES:
            with self.subTest(module=module):
                passing = _with(_run(module, "reject"), "PASS")
                self.assertEqual(was_pass - passing, set())
                self.assertEqual(conformance - passing, set())

    def test_a_server_that_accepts_malformed_payments_fails(self):
        for module, was_pass, not_payment, _c in self.CASES:
            with self.subTest(module=module):
                failing = _with(_run(module, "accept"), "FAIL")
                self.assertEqual((was_pass - not_payment) - failing, set())

    def test_a_non_conformant_challenge_fails_the_conformance_tests(self):
        for module, _p, _n, conformance in self.CASES:
            with self.subTest(module=module):
                failing = _with(_run(module, "nonconformant"), "FAIL")
                self.assertEqual(conformance - failing, set())

    def test_a_resource_served_without_payment_is_still_graded(self):
        """2xx is not the no-surface case (see the module docstring)."""
        for module, tid in (("x402", "X4-001"), ("l402", "L4-001")):
            with self.subTest(module=module):
                outcome, detail = _run(module, "ok")[tid]
                self.assertEqual(outcome, "FAIL")
                self.assertIn("Expected HTTP 402, got 200", detail)


class TheProbeIsOnePerTransport(unittest.TestCase):
    def test_the_probe_is_cached_on_the_transport_and_not_logged(self):
        for suite_cls, transport_cls, attr in (
                (X402SecurityTests, X402Transport, "_x402_payment_surface"),
                (L402SecurityTests, L402Transport, "_l402_payment_surface")):
            with self.subTest(suite=suite_cls.__name__), _target("404") as url:
                transport = transport_cls(url)
                suite = suite_cls(transport)
                self.assertFalse(suite.has_payment_surface())
                self.assertEqual(getattr(transport, attr)["status"], 404)
                self.assertEqual(suite._seen, [])
                # A second suite on the same transport reuses the answer.
                self.assertFalse(suite_cls(transport).has_payment_surface())


def _cli(module: str, url: str, *extra: str) -> int:
    proc = subprocess.run(
        [sys.executable, "-m", f"protocol_tests.{module}_harness", "--url", url, *extra],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=300, check=False)
    return proc.returncode


class ExitStatus(unittest.TestCase):
    def test_a_no_surface_run_exits_2(self):
        for module in ("x402", "l402"):
            for kind in ("closed", "404", "403"):
                with self.subTest(module=module, pole=kind), _target(kind) as url:
                    self.assertEqual(_cli(module, url), 2)

    def test_the_statistical_path_exits_2_without_a_surface(self):
        """`--trials N` counts trial passes only; with no surface it exits 2."""
        for module in ("x402", "l402"):
            with self.subTest(module=module), _target("404") as url:
                self.assertEqual(
                    _cli(module, url, "--trials", "2", "--categories",
                         "payment_challenge" if module == "x402" else "invoice_validation"),
                    2)

    def test_a_402_surface_still_exits_on_its_verdicts(self):
        for module in ("x402", "l402"):
            with self.subTest(module=module), _target("accept") as url:
                self.assertEqual(_cli(module, url), 1)
            with self.subTest(module=module, trials=2), _target("accept") as url:
                self.assertEqual(
                    _cli(module, url, "--trials", "2", "--categories",
                         "payment_challenge" if module == "x402" else "invoice_validation"),
                    1)


if __name__ == "__main__":
    unittest.main()
