#!/usr/bin/env python3
"""Unit tests for MCP transport and JSON-RPC primitives."""
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from protocol_tests.mcp_harness import (
    AUTO_PROTOCOL_VERSION,
    build_differential_report,
    LEGACY_PROTOCOL_VERSION,
    MODERN_PROTOCOL_VERSION,
    MCPSecurityTests,
    _json_path,
    _replace_handle,
    _replace_task_id,
    MCPTransport,
    report_has_failure,
    StreamableHTTPTransport,
    _header_value,
    jsonrpc_notification,
    jsonrpc_request,
)


class TestJSONRPCRequest(unittest.TestCase):
    def test_structure(self):
        msg = jsonrpc_request("tools/list")
        self.assertEqual(msg["jsonrpc"], "2.0")
        self.assertEqual(msg["method"], "tools/list")
        self.assertIn("id", msg)
    def test_params(self): self.assertEqual(jsonrpc_request("x", {"k":"v"})["params"], {"k":"v"})
    def test_custom_id(self): self.assertEqual(jsonrpc_request("x", id="abc")["id"], "abc")
    def test_none_params(self): self.assertNotIn("params", jsonrpc_request("x", params=None))
    def test_roundtrip(self): self.assertEqual(json.loads(json.dumps(jsonrpc_request("x", {"a":[1]})))["method"], "x")


class TestJSONRPCNotification(unittest.TestCase):
    def test_no_id(self): self.assertNotIn("id", jsonrpc_notification("init"))
    def test_version(self): self.assertEqual(jsonrpc_notification("x")["jsonrpc"], "2.0")


class TestTransport(unittest.TestCase):
    def test_send_not_impl(self):
        with self.assertRaises(NotImplementedError):
            MCPTransport().send({})
    def test_close_noop(self): MCPTransport().close()
    def test_http_init(self):
        t = StreamableHTTPTransport("http://localhost:8080")
        self.assertEqual(t.url, "http://localhost:8080")
        self.assertIsNone(t.session_id)

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

    def test_modern_task_id_is_mirrored_as_routing_name(self):
        t = StreamableHTTPTransport("http://localhost:8080", protocol_version=MODERN_PROTOCOL_VERSION)
        request = t._prepare_modern_message(jsonrpc_request("tasks/get", {"taskId": "tenant-a/task-42"}))
        headers = t._request_headers(request)
        self.assertEqual(headers["Mcp-Method"], "tasks/get")
        self.assertEqual(headers["Mcp-Name"], "tenant-a/task-42")

    def test_header_value_encodes_unsafe_values(self):
        self.assertEqual(_header_value("safe-value"), "safe-value")
        self.assertTrue(_header_value(" leading").startswith("=?base64?"))
        self.assertTrue(_header_value("=?base64?literal?=").startswith("=?base64?"))

    def test_modern_header_override_reaches_security_probe(self):
        transport = StreamableHTTPTransport("http://localhost:8080", protocol_version=MODERN_PROTOCOL_VERSION)
        response = MagicMock()
        response.headers.get.side_effect = lambda key, default=None: "application/json" if key == "Content-Type" else default
        response.read.return_value = b'{}'
        response.status = 200
        with patch("protocol_tests.mcp_harness.urllib.request.urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value = response
            transport.send(
                jsonrpc_request("tools/list", {}),
                header_overrides={"Mcp-Method": "tools/call", "Mcp-Name": "__mcp_header_probe__"},
            )
            request = urlopen.call_args.args[0]
        headers = {name.lower(): value for name, value in request.header_items()}
        self.assertEqual(headers["mcp-method"], "tools/call")
        self.assertEqual(headers["mcp-name"], "__mcp_header_probe__")

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
        self.assertIsNone(getattr(suite, "_connection_error", None))


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

    def test_error_only_report_is_a_failure(self):
        self.assertTrue(report_has_failure({"results": [], "error": "connection refused"}))
        self.assertFalse(report_has_failure({"results": [{"passed": True}]}))


class _MRTRTransport(MCPTransport):
    is_modern = True

    def __init__(self):
        self.requests = []

    def send(self, message, **kwargs):
        self.requests.append(message)
        if len(self.requests) == 1:
            return {"result": {"resultType": "input_required", "requestState": "signed-state-A"}}
        return {"error": {"code": -32020, "message": "HeaderMismatchError"}}


class TestMRTRRequestState(unittest.TestCase):
    def test_failed_configured_probe_is_not_marked_not_applicable(self):
        class FailingTransport(MCPTransport):
            is_modern = True

            def send(self, message, **kwargs):
                return {"_error": "connection refused"}

        suite = MCPSecurityTests(
            FailingTransport(), json_output=True,
            mrtr_probe={"method": "tools/call", "params": {"name": "approval_probe"}},
        )
        suite.test_mcp_request_state_integrity()
        self.assertFalse(suite.results[0].passed)
        self.assertIn("failed", suite.results[0].details)

    def test_tampered_request_state_is_rejected(self):
        transport = _MRTRTransport()
        suite = MCPSecurityTests(
            transport,
            json_output=True,
            mrtr_probe={"method": "tools/call", "params": {"name": "approval_probe", "arguments": {}}},
        )
        suite.test_mcp_request_state_integrity()
        self.assertTrue(suite.results[0].passed)
        retry = transport.requests[1]
        self.assertNotEqual(retry["params"]["requestState"], "signed-state-A")
        self.assertEqual(retry["params"]["inputResponses"], {})

    def test_completed_request_state_replay_is_rejected(self):
        class ReplayTransport(MCPTransport):
            is_modern = True

            def __init__(self):
                self.calls = 0

            def send(self, message, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    return {"result": {"resultType": "input_required", "requestState": "single-use-state"}}
                if self.calls == 2:
                    return {"result": {"resultType": "complete", "content": []}}
                return {"error": {"code": -32000, "message": "requestState already consumed"}}

        suite = MCPSecurityTests(
            ReplayTransport(),
            json_output=True,
            mrtr_probe={"method": "tools/call", "params": {"name": "approval_probe", "arguments": {}}},
            mrtr_input_responses={"approve": {"action": "accept"}},
        )
        suite.test_mcp_request_state_replay()
        self.assertTrue(suite.results[0].passed)

    def test_cross_principal_request_state_is_rejected(self):
        class PrincipalTransport(MCPTransport):
            is_modern = True

            def __init__(self):
                self.headers = None
                self.calls = 0

            def send(self, message, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    self.headers = kwargs.get("header_overrides")
                    return {"result": {"resultType": "input_required", "requestState": "principal-bound-state"}}
                self.headers = kwargs.get("header_overrides")
                return {"error": {"code": -32000, "message": "principal mismatch"}}

        transport = PrincipalTransport()
        suite = MCPSecurityTests(
            transport,
            json_output=True,
            mrtr_probe={"method": "tools/call", "params": {"name": "approval_probe", "arguments": {}}},
            mrtr_input_responses={"approve": {"action": "accept"}},
            mrtr_attacker_headers={"Authorization": "Bearer attacker"},
        )
        suite.test_mcp_request_state_principal_binding()
        self.assertTrue(suite.results[0].passed)
        self.assertEqual(transport.headers, {"Authorization": "Bearer attacker"})

    def test_cross_request_request_state_is_rejected(self):
        class BindingTransport(MCPTransport):
            is_modern = True

            def __init__(self):
                self.calls = []

            def send(self, message, **kwargs):
                self.calls.append(message)
                if len(self.calls) == 1:
                    return {"result": {"resultType": "input_required", "requestState": "request-bound-state"}}
                return {"error": {"code": -32000, "message": "request binding mismatch"}}

        transport = BindingTransport()
        suite = MCPSecurityTests(
            transport,
            json_output=True,
            mrtr_probe={"method": "tools/call", "params": {"name": "approve_transfer", "arguments": {"amount": 10}}},
            mrtr_input_responses={"approve": {"action": "accept"}},
            mrtr_altered_probe={"method": "tools/call", "params": {"name": "approve_transfer", "arguments": {"amount": 1000}}},
        )
        suite.test_mcp_request_state_request_binding()
        self.assertTrue(suite.results[0].passed)
        self.assertEqual(transport.calls[1]["params"]["arguments"]["amount"], 1000)


class TestExplicitHandleIsolation(unittest.TestCase):
    def test_failed_handle_create_is_not_marked_not_applicable(self):
        class FailingHandleTransport(MCPTransport):
            supports_header_overrides = True

            def send(self, message, **kwargs):
                return {"error": {"code": -32000, "message": "create failed"}}

        suite = MCPSecurityTests(
            FailingHandleTransport(), json_output=True,
            handle_create={"method": "tools/call", "params": {"name": "create_basket"}},
            handle_access={"method": "tools/call", "params": {"name": "read_basket"}},
            handle_attacker_headers={"Authorization": "Bearer tenant-b"},
        )
        suite.test_mcp_explicit_handle_isolation()
        self.assertFalse(suite.results[0].passed)
        self.assertIn("failed", suite.results[0].details)

    def test_replaces_handle_and_rejects_cross_principal_access(self):
        class HandleTransport(MCPTransport):
            supports_header_overrides = True

            def __init__(self):
                self.calls = []

            def send(self, message, **kwargs):
                self.calls.append((message, kwargs))
                if len(self.calls) == 1:
                    return {"result": {"basket": {"id": "tenant-a-handle"}}}
                return {"error": {"code": -32000, "message": "handle not authorized"}}

        transport = HandleTransport()
        suite = MCPSecurityTests(
            transport, json_output=True,
            handle_create={"method": "tools/call", "params": {"name": "create_basket"}, "handlePath": "result.basket.id"},
            handle_access={"method": "tools/call", "params": {"name": "read_basket", "arguments": {"basket_id": "$HANDLE"}}},
            handle_attacker_headers={"Authorization": "Bearer tenant-b"},
        )
        suite.test_mcp_explicit_handle_isolation()
        self.assertTrue(suite.results[0].passed)
        self.assertEqual(transport.calls[1][0]["params"]["arguments"]["basket_id"], "tenant-a-handle")
        self.assertEqual(transport.calls[1][1]["header_overrides"], {"Authorization": "Bearer tenant-b"})
        self.assertEqual(_json_path({"a": {"b": 1}}, "a.b"), 1)
        self.assertEqual(_replace_handle({"x": ["$HANDLE"]}, "h"), {"x": ["h"]})


class TestTaskIsolation(unittest.TestCase):
    def test_failed_task_create_is_not_marked_not_applicable(self):
        class FailingTaskTransport(MCPTransport):
            is_modern = True
            supports_header_overrides = True

            def send(self, message, **kwargs):
                return {"error": {"code": -32000, "message": "task create failed"}}

        suite = MCPSecurityTests(
            FailingTaskTransport(), json_output=True,
            task_create={"method": "tools/call", "params": {"name": "create_test_task"}},
            task_read={"method": "tasks/get", "params": {"taskId": "$TASK_ID"}},
            task_attacker_headers={"Authorization": "Bearer tenant-b"},
        )
        suite.test_mcp_task_cross_principal_isolation()
        self.assertFalse(suite.results[0].passed)
        self.assertIn("failed", suite.results[0].details)

    def test_cross_principal_task_read_is_rejected_and_task_id_is_replaced(self):
        class TaskTransport(MCPTransport):
            is_modern = True
            supports_header_overrides = True

            def __init__(self):
                self.calls = []

            def send(self, message, **kwargs):
                self.calls.append((message, kwargs))
                if len(self.calls) == 1:
                    return {"result": {"taskId": "tenant-a-task"}}
                return {"error": {"code": -32001, "message": "task not authorized"}}

        transport = TaskTransport()
        suite = MCPSecurityTests(
            transport, json_output=True,
            task_create={"method": "tools/call", "params": {"name": "create_test_task"}},
            task_read={"method": "tasks/get", "params": {"taskId": "$TASK_ID"}},
            task_attacker_headers={"Authorization": "Bearer tenant-b"},
        )
        suite.test_mcp_task_cross_principal_isolation()
        self.assertTrue(suite.results[0].passed)
        self.assertEqual(transport.calls[1][0]["params"]["taskId"], "tenant-a-task")
        self.assertEqual(transport.calls[1][1]["header_overrides"], {"Authorization": "Bearer tenant-b"})
        self.assertEqual(_replace_task_id({"task": "$TASK_ID"}, "task-1"), {"task": "task-1"})

    def test_cross_principal_task_read_that_succeeds_fails(self):
        class LeakyTaskTransport(MCPTransport):
            is_modern = True
            supports_header_overrides = True

            def send(self, message, **kwargs):
                if message["method"] == "tools/call":
                    return {"result": {"taskId": "tenant-a-task"}}
                return {"result": {"taskId": "tenant-a-task", "status": "working"}}

        suite = MCPSecurityTests(
            LeakyTaskTransport(), json_output=True,
            task_create={"method": "tools/call", "params": {"name": "create_test_task"}},
            task_read={"method": "tasks/get", "params": {"taskId": "$TASK_ID"}},
            task_attacker_headers={"Authorization": "Bearer tenant-b"},
        )
        suite.test_mcp_task_cross_principal_isolation()
        self.assertFalse(suite.results[0].passed)


class TestCacheScopeMetadata(unittest.TestCase):
    def test_modern_listing_requires_scope_and_ttl(self):
        class CacheTransport(MCPTransport):
            is_modern = True
            def send(self, message, **kwargs):
                return {"result": {"tools": [], "cacheScope": "private", "ttlMs": 5000}}
        suite = MCPSecurityTests(CacheTransport(), json_output=True)
        suite.test_mcp_cache_scope_metadata()
        self.assertTrue(suite.results[0].passed)

    def test_modern_resource_read_requires_scope_and_ttl(self):
        class ResourceCacheTransport(MCPTransport):
            is_modern = True

            def send(self, message, **kwargs):
                self.message = message
                return {"result": {"contents": [], "cacheScope": "private", "ttlMs": 5000}}

        transport = ResourceCacheTransport()
        suite = MCPSecurityTests(transport, json_output=True, cache_resource_uri="file:///approved/status")
        suite.test_mcp_resource_cache_metadata()
        self.assertTrue(suite.results[0].passed)
        self.assertEqual(transport.message["params"], {"uri": "file:///approved/status"})

    def test_boolean_ttl_is_not_accepted_as_cache_metadata(self):
        class BooleanTTLTransport(MCPTransport):
            is_modern = True

            def send(self, message, **kwargs):
                return {"result": {"tools": [], "cacheScope": "private", "ttlMs": True}}

        suite = MCPSecurityTests(BooleanTTLTransport(), json_output=True)
        suite.test_mcp_cache_scope_metadata()
        self.assertFalse(suite.results[0].passed)

    def test_boolean_ttl_is_not_accepted_for_resources(self):
        class BooleanResourceTTLTransport(MCPTransport):
            is_modern = True

            def send(self, message, **kwargs):
                return {"result": {"contents": [], "cacheScope": "private", "ttlMs": False}}

        suite = MCPSecurityTests(
            BooleanResourceTTLTransport(), json_output=True, cache_resource_uri="file:///approved/status"
        )
        suite.test_mcp_resource_cache_metadata()
        self.assertFalse(suite.results[0].passed)

    def test_authorized_revocation_removes_stale_capability(self):
        class CacheRevocationTransport(MCPTransport):
            is_modern = True

            def send(self, message, **kwargs):
                if message["method"] == "tools/list":
                    self.tool_reads = getattr(self, "tool_reads", 0) + 1
                    return {"result": {"tools": ([{"name": "deploy"}] if self.tool_reads == 1 else [{"name": "read_status"}])}}
                if message["method"] == "admin/revoke-capability":
                    return {"result": {"revoked": "deploy"}}

        transport = CacheRevocationTransport()
        suite = MCPSecurityTests(
            transport, json_output=True,
            cache_invalidation={"method": "admin/revoke-capability", "params": {"name": "deploy"}},
            cache_verify={"method": "tools/list", "params": {}},
            cache_forbidden_tool="deploy",
        )
        suite.test_mcp_cache_revocation()
        self.assertTrue(suite.results[0].passed)

    def test_stale_capability_after_revocation_fails(self):
        class StaleCacheTransport(MCPTransport):
            is_modern = True

            def send(self, message, **kwargs):
                if message["method"] == "admin/revoke-capability":
                    return {"result": {"revoked": "deploy"}}
                return {"result": {"tools": [{"name": "deploy"}]}}

        suite = MCPSecurityTests(
            StaleCacheTransport(), json_output=True,
            cache_invalidation={"method": "admin/revoke-capability", "params": {"name": "deploy"}},
            cache_verify={"method": "tools/list", "params": {}},
            cache_forbidden_tool="deploy",
        )
        suite.test_mcp_cache_revocation()
        self.assertFalse(suite.results[0].passed)

    def test_undiscoverable_capability_does_not_pass_revocation(self):
        class MissingCapabilityTransport(MCPTransport):
            is_modern = True

            def __init__(self):
                self.calls = []

            def send(self, message, **kwargs):
                self.calls.append(message["method"])
                return {"result": {"tools": [{"name": "read_status"}]}}

        transport = MissingCapabilityTransport()
        suite = MCPSecurityTests(
            transport, json_output=True,
            cache_invalidation={"method": "admin/revoke-capability", "params": {"name": "deploy"}},
            cache_verify={"method": "tools/list", "params": {}},
            cache_forbidden_tool="deploy",
        )
        suite.test_mcp_cache_revocation()
        self.assertFalse(suite.results[0].passed)
        self.assertEqual(transport.calls, ["tools/list"])


if __name__ == "__main__":
    unittest.main()
