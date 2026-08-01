"""Released-SDK Streamable HTTP input-validation characterization.

This loopback-only regression deliberately tests the bundled server through the
public Streamable HTTP client, rather than the SDK's in-memory ``Client``.
It records the server-side tool-schema boundary only.  It does not establish
gateway behavior, external receiver behavior, or final-wire conformance.
"""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest

mcp = pytest.importorskip("mcp")
from mcp import ClientSession  # noqa: E402
from mcp.client.streamable_http import streamable_http_client  # noqa: E402


REPO_ROOT = Path(__file__).resolve().parents[1]


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for_listener(port: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.2)
            if connection.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise AssertionError("bundled MCP server did not bind its loopback port")


@contextmanager
def _streamable_server() -> Iterator[str]:
    port = _free_loopback_port()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "mcp_server",
            "--transport",
            "http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_listener(port)
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_streamable_http_rejects_invalid_tool_arguments_before_handler_execution() -> None:
    """The bundled v2 server rejects a missing required ``url`` at its tool boundary."""

    async def call_invalid_tool(endpoint: str):
        async with streamable_http_client(endpoint) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                return await session.call_tool("scan_mcp_server", {"wrong": "synthetic"})

    with _streamable_server() as endpoint:
        result = asyncio.run(call_invalid_tool(endpoint))

    assert result.is_error is True
    assert len(result.content) == 1
    assert result.content[0].type == "text"
    assert "url" in result.content[0].text
    assert "Field required" in result.content[0].text
