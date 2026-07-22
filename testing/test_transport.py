#!/usr/bin/env python3
"""Unit tests for MCP transport and JSON-RPC primitives."""
import json, os, sys, unittest
from unittest.mock import patch
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from protocol_tests.mcp_harness import (
    AUTO_PROTOCOL_VERSION,
    build_differential_report,
    LEGACY_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSION,
    MCPSecurityTests,
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

    def test_modern_raw_probe_carries_routing_headers(self):
        t = StreamableHTTPTransport("http://localhost:8080", protocol_version=MODERN_PROTOCOL_VERSION)
        with patch("urllib.request.urlopen") as urlopen:
            response = urlopen.return_value.__enter__.return_value
            response.read.return_value = b"{}"
            t.send_raw(b"not-json", mcp_method="tools/call", mcp_name="scan")
        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_header("Mcp-protocol-version"), MODERN_PROTOCOL_VERSION)
        self.assertEqual(request.get_header("Mcp-method"), "tools/call")
        self.assertEqual(request.get_header("Mcp-name"), "scan")
        self.assertIsNone(request.get_header("Mcp-session-id"))


class _AutoTransport(MCPTransport):
    def __init__(self, modern_response):
        self.protocol_version = AUTO_PROTOCOL_VERSION
        self.session_id = None
        self.modern_response = modern_response
        self.sent = []

    @property
    def is_auto(self):
        return self.protocol_version == AUTO_PROTOCOL_VERSION

    @property
    def is_modern(self):
        return self.protocol_version == MODERN_PROTOCOL_VERSION

    def send(self, message):
        self.sent.append(message)
        if message["method"] == "server/discover":
            return self.modern_response
        if message["method"] == "initialize":
            return {"result": {"serverInfo": {"name": "legacy"}, "capabilities": {}}}
        return None


class TestProtocolAutoSelection(unittest.TestCase):
    def test_auto_keeps_modern_when_discovery_succeeds(self):
        transport = _AutoTransport({"result": {"serverInfo": {"name": "modern"}, "capabilities": {}}})
        suite = MCPSecurityTests(transport, json_output=True)
        self.assertTrue(suite.initialize())
        self.assertEqual(suite.selected_protocol_version, MODERN_PROTOCOL_VERSION)
        self.assertEqual(transport.protocol_version, MODERN_PROTOCOL_VERSION)
        self.assertEqual([message["method"] for message in transport.sent], ["server/discover"])

    def test_auto_falls_back_to_legacy_initialization(self):
        transport = _AutoTransport(None)
        suite = MCPSecurityTests(transport, json_output=True)
        self.assertTrue(suite.initialize())
        self.assertEqual(suite.selected_protocol_version, LEGACY_PROTOCOL_VERSION)
        self.assertEqual(transport.protocol_version, LEGACY_PROTOCOL_VERSION)
        self.assertEqual([message["method"] for message in transport.sent], ["server/discover", "initialize", "notifications/initialized"])


class TestDifferentialReport(unittest.TestCase):
    def test_marks_claim_changes_and_missing_coverage(self):
        report = build_differential_report(
            {"results": [{"test_id": "MCP-001", "passed": True}, {"test_id": "MCP-002", "passed": False}]},
            {"results": [{"test_id": "MCP-001", "passed": True}, {"test_id": "MCP-002", "passed": True}, {"test_id": "MCP-RC-001", "passed": True}]},
        )
        claims = {claim["test_id"]: claim for claim in report["claims"]}
        self.assertEqual(claims["MCP-001"]["status"], "equivalent")
        self.assertEqual(claims["MCP-002"]["status"], "changed")
        self.assertEqual(claims["MCP-RC-001"]["status"], "modern_only")
        self.assertEqual(report["summary"], {"equivalent": 1, "changed": 1, "legacy_only": 0, "modern_only": 1})


if __name__ == "__main__":
    unittest.main()
