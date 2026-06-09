#!/usr/bin/env python3
"""VS-R03 regression suite — verdict-correctness false negatives.

These guard the structural class found in VS-R03: harness verdict logic that trusts
attacker-/server-controlled signal as proof of defense, so a *successful* attack against
the system-under-test is silently scored as "blocked." Each test fails against the
pre-fix code and passes against the fix.

  Cluster A — MCP transport trust boundary + MCP-016 leak classification
  Cluster B — L402 liveness gate (transport failure / 5xx is never a "rejection")
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol_tests.mcp_harness import _strip_server_sentinels, MCPSecurityTests
from protocol_tests.l402_harness import _rejected, L402SecurityTests


class _FixedTransport:
    """Returns one fixed response for every call. Stands in for a (possibly malicious
    or unreachable) system-under-test without touching the network."""

    def __init__(self, resp):
        self._resp = resp
        self.url = "http://fixture.invalid"

    def send(self, message):  # MCP transport surface
        return dict(self._resp) if isinstance(self._resp, dict) else self._resp

    def get(self, path, headers=None, timeout=15.0):  # L402 transport surface
        return dict(self._resp) if isinstance(self._resp, dict) else self._resp

    def post(self, path, body=None, headers=None, timeout=15.0):
        return dict(self._resp) if isinstance(self._resp, dict) else self._resp


# ----------------------------------------------------------------------------
# Cluster A1 — server JSON must not collide with internal control sentinels
# ----------------------------------------------------------------------------
class TestMCPTransportTrustBoundary(unittest.TestCase):
    def test_strip_removes_injected_sentinels(self):
        # A malicious server tries to forge an "error/blocked" verdict by injecting
        # the harness's own sentinels into its 200 JSON body.
        out = _strip_server_sentinels({
            "result": {"contents": "root:x:0:0:/etc/passwd"},
            "_error": True, "_status": 400, "_exception": "forged",
        })
        self.assertNotIn("_error", out)
        self.assertNotIn("_status", out)
        self.assertNotIn("_exception", out)
        # Legitimate JSON-RPC payload is preserved.
        self.assertIn("result", out)

    def test_strip_preserves_real_jsonrpc_fields(self):
        out = _strip_server_sentinels({"jsonrpc": "2.0", "id": 1, "error": {"code": -32601}})
        self.assertEqual(out["error"]["code"], -32601)

    def test_strip_passes_through_non_dict(self):
        self.assertEqual(_strip_server_sentinels([1, 2, 3]), [1, 2, 3])
        self.assertIsNone(_strip_server_sentinels(None))


# ----------------------------------------------------------------------------
# Cluster A2 — MCP-016: a credential leak under an error envelope is a hit
# ----------------------------------------------------------------------------
class TestMCP016CredentialLeak(unittest.TestCase):
    def test_credential_leak_under_error_is_ssrf_hit(self):
        # SSRF sink exfiltrates AWS instance-metadata creds AND wraps them in a
        # JSON-RPC error envelope. Pre-fix this was scored "blocked"; it is a leak.
        leaked = {
            "error": {"code": -32000, "message": "internal error"},
            "result": {
                "AccessKeyId": "ASIAEXAMPLE",
                "SecretAccessKey": "wJalrXUtnFEMI/EXAMPLEKEY",
                "Expiration": "2026-06-09T00:00:00Z",
            },
        }
        suite = MCPSecurityTests(_FixedTransport(leaked))
        suite.test_mcp_ssrf_via_resource_uri()
        result = next(r for r in suite.results if r.test_id == "MCP-016")
        self.assertFalse(
            result.passed,
            "credential leak under an error envelope must be flagged as SSRF, not blocked",
        )

    def test_benign_host_echo_under_error_still_blocked(self):
        # A genuine rejection that merely echoes the target host (no credential
        # material) must still count as blocked — guards against over-correction.
        rejection = {"error": {"code": -32601, "message": "blocked request to 169.254.169.254"}}
        suite = MCPSecurityTests(_FixedTransport(rejection))
        suite.test_mcp_ssrf_via_resource_uri()
        result = next(r for r in suite.results if r.test_id == "MCP-016")
        self.assertTrue(result.passed, "benign host echo in an error is not a credential leak")


# ----------------------------------------------------------------------------
# Cluster B1 — L402 liveness gate
# ----------------------------------------------------------------------------
class TestL402LivenessGate(unittest.TestCase):
    def test_transport_failure_is_not_a_rejection(self):
        self.assertFalse(_rejected({"status": 0, "_error": True}))
        self.assertFalse(_rejected(None))
        self.assertFalse(_rejected({}))

    def test_server_fault_5xx_is_not_a_rejection(self):
        # A 5xx may itself be the attack succeeding (e.g. a parser fault from a
        # malformed-caveat payload) — it must not be scored as a clean rejection.
        self.assertFalse(_rejected({"status": 500}))
        self.assertFalse(_rejected({"status": 503}))

    def test_active_refusal_is_a_rejection(self):
        self.assertTrue(_rejected({"status": 401}))
        self.assertTrue(_rejected({"status": 402}))
        self.assertTrue(_rejected({"status": 403}))

    def test_success_is_not_a_rejection(self):
        self.assertFalse(_rejected({"status": 200}))

    def test_dead_server_does_not_yield_spurious_pass(self):
        # An unreachable/erroring server (status 0) presented with a fake preimage
        # must NOT report the attack as rejected. Pre-fix: passed=True (perfect pass
        # against a dead target). Post-fix: passed=False (observe-failure).
        suite = L402SecurityTests(_FixedTransport({"status": 0, "_error": True, "body": ""}))
        suite.test_l402_expired_token()
        result = next(r for r in suite.results if r.test_id == "L4-003")
        self.assertFalse(
            result.passed,
            "a dead/erroring server must not score a fake-preimage attack as rejected",
        )


if __name__ == "__main__":
    unittest.main()
