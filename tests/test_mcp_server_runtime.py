"""Regression coverage for MCP SDK runtime configuration."""

from unittest.mock import Mock

from mcp_server.server import create_server, run_server


def test_create_server_uses_mcpserver() -> None:
    server = create_server()

    assert type(server).__name__ == "MCPServer"


def test_http_runner_passes_bind_settings_to_mcpserver_run() -> None:
    server = Mock()

    run_server(server, transport="http", host="127.0.0.1", port=18400)

    server.run.assert_called_once_with(
        transport="streamable-http", host="127.0.0.1", port=18400
    )
