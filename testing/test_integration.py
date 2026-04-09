#!/usr/bin/env python3
"""End-to-end integration test: MCP harness against the bundled mock server.

R32 recommendation for CI coverage. Starts the mock MCP server in a subprocess,
runs the full harness against it, and validates expected pass/fail outcomes.
"""
import json
import os
import signal
import socket
import subprocess
import sys
import time
import unittest

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MOCK_SERVER_PORT = 8402
MOCK_SERVER_URL = f"http://localhost:{MOCK_SERVER_PORT}"
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 30-second timeout for the entire test class
TEST_TIMEOUT_S = 30


def _port_in_use(port: int) -> bool:
    """Check if a TCP port is already in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("localhost", port)) == 0


def _wait_for_server(port: int, timeout: float = 10.0) -> bool:
    """Poll until the server is accepting connections or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _port_in_use(port):
            return True
        time.sleep(0.1)
    return False


@unittest.skipIf(
    _port_in_use(MOCK_SERVER_PORT),
    f"Port {MOCK_SERVER_PORT} already in use -- skipping integration test",
)
class TestMCPIntegration(unittest.TestCase):
    """End-to-end: mock MCP server + harness."""

    server_proc = None
    _alarm_fired = False

    @classmethod
    def setUpClass(cls):
        """Start the mock MCP server subprocess."""
        # Set a class-level timeout via SIGALRM (Unix only)
        if hasattr(signal, "SIGALRM"):
            def _timeout_handler(signum, frame):
                cls._alarm_fired = True
                raise TimeoutError(
                    f"Integration test class exceeded {TEST_TIMEOUT_S}s timeout"
                )
            signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(TEST_TIMEOUT_S)

        cls.server_proc = subprocess.Popen(
            [sys.executable, "-m", "testing.mock_mcp_server"],
            cwd=PROJECT_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if not _wait_for_server(MOCK_SERVER_PORT):
            cls._kill_server()
            raise RuntimeError(
                f"Mock MCP server failed to start on port {MOCK_SERVER_PORT}"
            )

    @classmethod
    def tearDownClass(cls):
        """Stop the mock server and cancel the alarm."""
        cls._kill_server()
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)

    @classmethod
    def _kill_server(cls):
        if cls.server_proc and cls.server_proc.poll() is None:
            cls.server_proc.terminate()
            try:
                cls.server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.server_proc.kill()
                cls.server_proc.wait(timeout=2)

    # ------------------------------------------------------------------ #
    # Helper: run the harness as a library call (fast, in-process)
    # ------------------------------------------------------------------ #
    def _run_harness(self):
        """Run MCP harness in-process and return results list."""
        from protocol_tests.mcp_harness import MCPSecurityTests, StreamableHTTPTransport

        transport = StreamableHTTPTransport(MOCK_SERVER_URL)
        suite = MCPSecurityTests(transport, json_output=True)
        try:
            results = suite.run_all()
        finally:
            transport.close()
        return results

    # ------------------------------------------------------------------ #
    # Tests
    # ------------------------------------------------------------------ #

    def test_harness_runs_minimum_tests(self):
        """At least 10 tests should execute against the mock server."""
        results = self._run_harness()
        self.assertGreaterEqual(
            len(results), 10,
            f"Expected >= 10 tests, got {len(results)}",
        )

    def test_mcp001_fails_vulnerable_tool(self):
        """MCP-001 must FAIL: mock server exposes a deliberately vulnerable tool."""
        results = self._run_harness()
        mcp001 = [r for r in results if r.test_id == "MCP-001"]
        self.assertEqual(len(mcp001), 1, "MCP-001 result not found")
        self.assertFalse(
            mcp001[0].passed,
            "MCP-001 should FAIL (mock server has exfiltration URL in tool description)",
        )

    def test_mcp002_through_mcp007_pass(self):
        """MCP-002 through MCP-007 should all PASS against the mock server."""
        results = self._run_harness()
        results_by_id = {r.test_id: r for r in results}

        for tid in ["MCP-002", "MCP-003", "MCP-004", "MCP-005", "MCP-006", "MCP-007"]:
            with self.subTest(test_id=tid):
                self.assertIn(tid, results_by_id, f"{tid} result not found")
                self.assertTrue(
                    results_by_id[tid].passed,
                    f"{tid} should PASS but failed: {results_by_id[tid].details}",
                )

    def test_json_mode_output_valid(self):
        """--json mode should produce valid JSON on stdout."""
        proc = subprocess.run(
            [
                sys.executable, "-m", "protocol_tests.mcp_harness",
                "--transport", "http",
                "--url", MOCK_SERVER_URL,
                "--json",
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=TEST_TIMEOUT_S,
        )
        # Harness exits 1 because MCP-001 fails -- that is expected
        stdout = proc.stdout.strip()
        self.assertTrue(stdout, "No stdout from --json mode")

        report = json.loads(stdout)  # raises if not valid JSON
        self.assertIn("results", report)
        self.assertIn("summary", report)
        self.assertIsInstance(report["results"], list)
        self.assertGreaterEqual(report["summary"]["total"], 10)


if __name__ == "__main__":
    unittest.main()
