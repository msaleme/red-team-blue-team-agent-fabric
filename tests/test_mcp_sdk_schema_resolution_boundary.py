"""Controlled receiver-boundary characterization for the optional MCP SDK.

SDK v2 advertises a reference-bearing schema but does not resolve it or apply
it to tool-call arguments.  The harness's own fail-closed reference policy is
therefore the enforcement boundary; this module only records SDK behavior.
"""

import asyncio
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

mcp = pytest.importorskip("mcp")
from mcp import Client, types  # noqa: E402
from mcp.server.lowlevel import Server  # noqa: E402


def _make_server(schema_url: str, calls: list[tuple[str, dict[str, str]]]) -> Server:
    async def list_tools(_ctx: object, _params: object) -> types.ListToolsResult:
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="probe",
                    description="synthetic local probe",
                    inputSchema={"type": "object", "$ref": schema_url},
                )
            ]
        )

    async def call_tool(
        _ctx: object, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        calls.append((params.name, params.arguments or {}))
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="ok")]
        )

    return Server("schema-boundary-probe", on_list_tools=list_tools, on_call_tool=call_tool)


def _call_probe(server: Server, arguments: dict[str, str]) -> types.CallToolResult:
    async def run() -> types.CallToolResult:
        async with Client(server, mode="legacy") as client:
            listed = await client.list_tools()
            assert listed.tools[0].input_schema["type"] == "object"
            return await client.call_tool("probe", arguments)

    return asyncio.run(run())


def _assert_reference_is_not_fetched(
    response: Callable[[BaseHTTPRequestHandler], None],
    path: str,
    arguments: dict[str, str],
) -> None:
    requests: list[str] = []
    calls: list[tuple[str, dict[str, str]]] = []

    class SchemaHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            response(self)

        def log_message(self, format: str, *args: object) -> None:
            return

    http = ThreadingHTTPServer(("127.0.0.1", 0), SchemaHandler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        server = _make_server(f"http://127.0.0.1:{http.server_port}/{path}", calls)
        result = _call_probe(server, arguments)
    finally:
        http.shutdown()
        http.server_close()

    assert requests == []
    assert calls == [("probe", arguments)]
    assert result.is_error is False


def test_sdk_v2_does_not_fetch_a_loopback_tool_schema_reference() -> None:
    """A valid advertised external reference is not retrieved by SDK v2."""

    def response(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(200)
        handler.end_headers()

    _assert_reference_is_not_fetched(response, "synthetic-schema.json", {"value": "synthetic"})


def test_sdk_v2_does_not_fetch_a_missing_loopback_schema_reference() -> None:
    """A missing external reference does not affect SDK v2 tool admission."""

    def response(handler: BaseHTTPRequestHandler) -> None:
        handler.send_error(404)

    _assert_reference_is_not_fetched(response, "missing-schema.json", {"value": "synthetic"})


def test_sdk_v2_does_not_validate_arguments_against_loopback_schema_reference() -> None:
    """SDK v2 calls the handler even when arguments violate the advertised schema."""

    def response(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(200)
        handler.end_headers()

    _assert_reference_is_not_fetched(response, "synthetic-schema.json", {"wrong": "synthetic"})


def test_sdk_v2_does_not_fetch_a_malformed_loopback_schema_reference() -> None:
    """Malformed remote schema content is not observed at the SDK v2 boundary."""

    def response(handler: BaseHTTPRequestHandler) -> None:
        body = b'{"type":"object",'
        handler.send_response(200)
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    _assert_reference_is_not_fetched(response, "malformed-schema.json", {"value": "synthetic"})
