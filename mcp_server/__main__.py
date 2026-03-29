#!/usr/bin/env python3
"""Entry point for the Agent Security Harness MCP server.

Usage:
    python -m mcp_server                                    # stdio (default)
    python -m mcp_server --transport http --port 8400       # HTTP
    python -m mcp_server --transport http --api-key SECRET  # HTTP with auth
"""

from __future__ import annotations

import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Agent Security Harness MCP Server",
        epilog="Example: python -m mcp_server --transport http --port 8400",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport mode (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8400,
        help="HTTP port (only used with --transport http, default: 8400)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="HTTP bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="Optional API key for authenticated tools (full_security_audit)",
    )

    args = parser.parse_args()

    try:
        from mcp_server.server import create_server, run_server
    except ImportError as e:
        print(
            f"Error: {e}\n\n"
            "The MCP server requires the 'mcp' package. Install it with:\n"
            "  pip install 'agent-security-harness[mcp-server]'\n"
            "  # or: pip install mcp>=1.0.0",
            file=sys.stderr,
        )
        sys.exit(1)

    # #108 - Warn when MCP server runs without authentication
    if not args.api_key:
        print(
            "WARNING: MCP server running without authentication. "
            "Full audit and AIUC-1 tools are unrestricted.\n"
            "Use --api-key <key> to require authentication for expensive operations.",
            file=sys.stderr,
        )

    server = create_server(api_key=args.api_key)
    run_server(server, transport=args.transport, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
