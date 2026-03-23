#!/usr/bin/env python3
"""Unit tests for MCP transport layer and JSON-RPC primitives.

Tests the request/response construction logic without needing a live server.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol_tests.mcp_harness import (
    jsonrpc_request,
    jsonrpc_notification,
    MCPTransport,
    StreamableHTTPTransport,
)


class TestJSONRPCRequest(unittest.TestCase):
    """JSON-RPC 2.0 request message construction."""

    def test_basic_request(self):
        msg = jsonrpc_request("tools/list")
        self.assertEqual(msg["jsonrpc"], "2.0")
        self.assertEqual(msg["method"], "tools/list")
        self.assertIn("id", msg)
        self.assertNotIn("params", msg)

    def test_request_with_params(self):
        msg = jsonrpc_request("tools/call", {"name": "get_data"})
        self.assertEqual(msg["params"], {"name": "get_data"})

    def test_request_with_custom_id(self):
        msg = jsonrpc_request("initialize", id="custom-id-42")
        self.assertEqual(msg["id"], "custom-id-42")

    def test_auto_generated_id_is_string(self):
        msg = jsonrpc_request("test")
        self.assertIsInstance(msg["id"], str)
        self.assertGreater(len(msg["id"]), 0)

    def test_none_params_excluded(self):
        msg = jsonrpc_request("test", params=None)
        self.assertNotIn("params", msg)

    def test_empty_params_included(self):
        msg = jsonrpc_request("test", params={})
        self.assertIn("params", msg)
        self.assertEqual(msg["params"], {})

    def test_serializable(self):
        msg = jsonrpc_request("tools/call", {"name": "test", "args": [1, 2, 3]})
        serialized = json.dumps(msg)
        deserialized = json.loads(serialized)
        self.assertEqual(deserialized["method"], "tools/call")


class TestJSONRPCNotification(unittest.TestCase):
    """JSON-RPC 2.0 notification (no id)."""

    def test_no_id_field(self):
        msg = jsonrpc_notification("notifications/initialized")
        self.assertNotIn("id", msg)

    def test_has_jsonrpc_version(self):
        msg = jsonrpc_notification("test")
        self.assertEqual(msg["jsonrpc"], "2.0")

    def test_with_params(self):
        msg = jsonrpc_notification("update", {"key": "value"})
        self.assertEqual(msg["params"], {"key": "value"})

    def test_without_params(self):
        msg = jsonrpc_notification("ping")
        self.assertNotIn("params", msg)


class TestMCPTransportBase(unittest.TestCase):
    """Base transport class contract."""

    def test_send_raises_not_implemented(self):
        t = MCPTransport()
        with self.assertRaises(NotImplementedError):
            t.send({"test": True})

    def test_send_raw_raises_not_implemented(self):
        t = MCPTransport()
        with self.assertRaises(NotImplementedError):
            t.send_raw(b"test")

    def test_close_is_noop(self):
        t = MCPTransport()
        t.close()  # should not raise


class TestStreamableHTTPTransportConstruction(unittest.TestCase):
    """StreamableHTTPTransport initialization (no network calls)."""

    def test_url_stored(self):
        t = StreamableHTTPTransport("http://localhost:8080/mcp")
        self.assertEqual(t.url, "http://localhost:8080/mcp")

    def test_default_empty_headers(self):
        t = StreamableHTTPTransport("http://localhost:8080")
        self.assertEqual(t.headers, {})

    def test_custom_headers(self):
        t = StreamableHTTPTransport("http://localhost:8080", headers={"X-Auth": "test"})
        self.assertEqual(t.headers["X-Auth"], "test")

    def test_session_id_initially_none(self):
        t = StreamableHTTPTransport("http://localhost:8080")
        self.assertIsNone(t.session_id)


if __name__ == "__main__":
    unittest.main()
