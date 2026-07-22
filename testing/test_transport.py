#!/usr/bin/env python3
"""Unit tests for MCP transport and JSON-RPC primitives."""
import json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from protocol_tests.mcp_harness import (
    MODERN_PROTOCOL_VERSION,
    MCPTransport,
    StreamableHTTPTransport,
    _header_value,
    jsonrpc_notification,
    jsonrpc_request,
)


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

    def test_modern_request_metadata_and_headers(self):
        t = StreamableHTTPTransport("http://localhost:8080", protocol_version=MODERN_PROTOCOL_VERSION)
        request = t._prepare_modern_message(jsonrpc_request("tools/call", {"name": "scan"}))
        self.assertEqual(request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"], MODERN_PROTOCOL_VERSION)
        self.assertIn("io.modelcontextprotocol/clientInfo", request["params"]["_meta"])
        headers = t._request_headers(request)
        self.assertEqual(headers["MCP-Protocol-Version"], MODERN_PROTOCOL_VERSION)
        self.assertEqual(headers["Mcp-Method"], "tools/call")
        self.assertEqual(headers["Mcp-Name"], "scan")
        self.assertNotIn("Mcp-Session-Id", headers)

    def test_modern_resource_name_is_mirrored_and_encoded(self):
        t = StreamableHTTPTransport("http://localhost:8080", protocol_version=MODERN_PROTOCOL_VERSION)
        request = t._prepare_modern_message(jsonrpc_request("resources/read", {"uri": "file:///你好"}))
        self.assertTrue(t._request_headers(request)["Mcp-Name"].startswith("=?base64?"))

    def test_header_value_encodes_unsafe_values(self):
        self.assertEqual(_header_value("safe-value"), "safe-value")
        self.assertTrue(_header_value(" leading").startswith("=?base64?"))
        self.assertTrue(_header_value("=?base64?literal?=").startswith("=?base64?"))


if __name__ == "__main__":
    unittest.main()
