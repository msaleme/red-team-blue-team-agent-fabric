#!/usr/bin/env python3
"""Unit tests for MCP transport and JSON-RPC primitives."""
import json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from protocol_tests.mcp_harness import jsonrpc_request, jsonrpc_notification, MCPTransport, StreamableHTTPTransport


class TestJSONRPCRequest(unittest.TestCase):
    def test_structure(self):
        msg = jsonrpc_request("tools/list")
        self.assertEqual(msg["jsonrpc"], "2.0"); self.assertEqual(msg["method"], "tools/list"); self.assertIn("id", msg)
    def test_params(self): self.assertEqual(jsonrpc_request("x", {"k":"v"})["params"], {"k":"v"})
    def test_custom_id(self): self.assertEqual(jsonrpc_request("x", id="abc")["id"], "abc")
    def test_none_params(self): self.assertNotIn("params", jsonrpc_request("x", params=None))
    def test_roundtrip(self): self.assertEqual(json.loads(json.dumps(jsonrpc_request("x", {"a":[1]})))["method"], "x")


class TestJSONRPCNotification(unittest.TestCase):
    def test_no_id(self): self.assertNotIn("id", jsonrpc_notification("init"))
    def test_version(self): self.assertEqual(jsonrpc_notification("x")["jsonrpc"], "2.0")


class TestTransport(unittest.TestCase):
    def test_send_not_impl(self):
        with self.assertRaises(NotImplementedError): MCPTransport().send({})
    def test_close_noop(self): MCPTransport().close()
    def test_http_init(self):
        t = StreamableHTTPTransport("http://localhost:8080")
        self.assertEqual(t.url, "http://localhost:8080"); self.assertIsNone(t.session_id)


if __name__ == "__main__":
    unittest.main()
