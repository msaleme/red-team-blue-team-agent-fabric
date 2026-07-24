"""Regression coverage for MCP SDK runtime configuration."""

from unittest.mock import Mock

from mcp_server.server import create_server, run_server


def test_create_server_passes_http_bind_settings_to_fastmcp() -> None:
    server = create_server(host="127.0.0.1", port=18400)

    assert server.settings.host == "127.0.0.1"
    assert server.settings.port == 18400


def test_http_runner_uses_current_fastmcp_run_signature() -> None:
    server = Mock()

    run_server(server, transport="http")

    server.run.assert_called_once_with(transport="streamable-http")
