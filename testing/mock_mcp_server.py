#!/usr/bin/env python3
"""Checkout alias for the shipped mock MCP server.

The server moved to `protocol_tests/mock_mcp_server.py` so that it is in the
wheel (R3-12). This module keeps `python -m testing.mock_mcp_server` and
`import mock_mcp_server` working for anything in the checkout that still
uses the old path. New references should use:

    python -m protocol_tests.mock_mcp_server
"""
from __future__ import annotations

from protocol_tests.mock_mcp_server import (  # noqa: F401
    DEFAULT_HOST,
    DEFAULT_PORT,
    MockMCPHandler,
    ReusableTCPServer,
    main,
    run_server,
)

__all__ = ["DEFAULT_HOST", "DEFAULT_PORT", "MockMCPHandler", "ReusableTCPServer",
           "main", "run_server"]

if __name__ == "__main__":
    raise SystemExit(main())
