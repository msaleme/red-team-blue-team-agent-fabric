"""Controlled receiver-boundary characterization for the optional MCP SDK."""

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


mcp = pytest.importorskip("mcp")
from mcp import types  # noqa: E402
from mcp.server.lowlevel import Server  # noqa: E402


def test_lowlevel_server_resolves_a_loopback_tool_schema_reference() -> None:
    """Document SDK behavior only: a synthetic loopback $ref is retrieved on call."""

    requests: list[str] = []
    calls: list[tuple[str, dict[str, str]]] = []

    class SchemaHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
            requests.append(self.path)
            body = json.dumps(
                {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                    "additionalProperties": False,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/schema+json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    http = ThreadingHTTPServer(("127.0.0.1", 0), SchemaHandler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        schema_url = f"http://127.0.0.1:{http.server_port}/synthetic-schema.json"
        server = Server("schema-boundary-probe")
        server._tool_cache["probe"] = types.Tool(
            name="probe", description="synthetic local probe", inputSchema={"$ref": schema_url}
        )

        @server.call_tool()
        async def call_tool(name: str, arguments: dict[str, str]) -> dict[str, bool]:
            calls.append((name, arguments))
            return {"ok": True}

        request = types.CallToolRequest(
            params=types.CallToolRequestParams(name="probe", arguments={"value": "synthetic"})
        )
        result = asyncio.run(server.request_handlers[types.CallToolRequest](request))
    finally:
        http.shutdown()
        http.server_close()

    assert requests == ["/synthetic-schema.json"]
    assert calls == [("probe", {"value": "synthetic"})]
    assert result.root.isError is False


def test_lowlevel_server_does_not_invoke_handler_when_loopback_schema_is_missing() -> None:
    """Characterize the failed-resolution path without any external endpoint."""

    requests: list[str] = []
    calls: list[tuple[str, dict[str, str]]] = []

    class MissingSchemaHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
            requests.append(self.path)
            self.send_error(404)

        def log_message(self, format: str, *args: object) -> None:
            return

    http = ThreadingHTTPServer(("127.0.0.1", 0), MissingSchemaHandler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        schema_url = f"http://127.0.0.1:{http.server_port}/missing-schema.json"
        server = Server("schema-boundary-probe")
        server._tool_cache["probe"] = types.Tool(
            name="probe", description="synthetic local probe", inputSchema={"$ref": schema_url}
        )

        @server.call_tool()
        async def call_tool(name: str, arguments: dict[str, str]) -> dict[str, bool]:
            calls.append((name, arguments))
            return {"ok": True}

        request = types.CallToolRequest(
            params=types.CallToolRequestParams(name="probe", arguments={"value": "synthetic"})
        )
        result = asyncio.run(server.request_handlers[types.CallToolRequest](request))
    finally:
        http.shutdown()
        http.server_close()

    assert requests == ["/missing-schema.json"]
    assert calls == []
    assert result.root.isError is True
