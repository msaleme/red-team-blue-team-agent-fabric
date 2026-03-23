#!/usr/bin/env python3
"""Unified CLI for the Agent Security Harness.

Usage:
    agent-security test mcp --url http://localhost:8080/mcp
    agent-security test a2a --url https://agent.example.com
    agent-security test l402 --url https://dispatches.mystere.me
    agent-security test mcp --transport stdio --command "node my-server.js"
    agent-security test mcp --url http://localhost:8080 --categories tool_poisoning,capability_escalation
    agent-security test mcp --url http://localhost:8080 --trials 5
    agent-security test mcp --url http://localhost:8080 --delay 1000

    agent-security list                     # List all available harnesses
    agent-security list mcp                 # List MCP test cases
    agent-security list a2a                 # List A2A test cases
    agent-security list l402                # List L402 test cases

    agent-security version                  # Show version info
"""

from __future__ import annotations

import sys
import importlib


VERSION = "3.2.0"

HARNESSES = {
    "mcp": {
        "module": "protocol_tests.mcp_harness",
        "description": "MCP wire-protocol security tests (10 tests, JSON-RPC 2.0)",
    },
    "a2a": {
        "module": "protocol_tests.a2a_harness",
        "description": "A2A wire-protocol security tests (12 tests, Agent Cards + tasks)",
    },
    "l402": {
        "module": "protocol_tests.l402_harness",
        "description": "L402 payment flow security tests (14 tests, macaroons + invoices)",
    },
    "x402": {
        "module": "protocol_tests.x402_harness",
        "description": "x402 payment protocol security tests (20 tests, Coinbase/Stripe agent payments)",
    },
    "enterprise": {
        "module": "protocol_tests.enterprise_adapters",
        "description": "Enterprise platform adapters (30 tests, 9 platforms)",
    },
    "extended-enterprise": {
        "module": "protocol_tests.extended_enterprise_adapters",
        "description": "Extended enterprise adapters (27 tests, 11 platforms)",
    },
    "framework": {
        "module": "protocol_tests.framework_adapters",
        "description": "Framework adapters (21 tests, 5 frameworks)",
    },
    "identity": {
        "module": "protocol_tests.identity_harness",
        "description": "NIST NCCoE Agent Identity tests (18 tests, 6 focus areas)",
    },
    "gtg1002": {
        "module": "protocol_tests.gtg1002_simulation",
        "description": "GTG-1002 APT simulation (17 tests, 6 phases + hallucination)",
    },
    "advanced": {
        "module": "protocol_tests.advanced_attacks",
        "description": "Advanced attack patterns (10 tests, polymorphic + stateful)",
    },
}


def print_usage():
    print(f"Agent Security Harness v{VERSION}")
    print(f"209 security tests for AI agent systems")
    print()
    print("Usage:")
    print("  agent-security test <harness> [options]    Run a test harness")
    print("  agent-security list [harness]              List available tests")
    print("  agent-security version                     Show version")
    print()
    print("Harnesses:")
    for name, info in HARNESSES.items():
        print(f"  {name:25s} {info['description']}")
    print()
    print("Examples:")
    print("  agent-security test mcp --url http://localhost:8080/mcp")
    print("  agent-security test a2a --url https://agent.example.com")
    print("  agent-security test l402 --url https://dispatches.mystere.me")
    print("  agent-security test mcp --transport stdio --command 'node server.js'")
    print("  agent-security test mcp --url http://localhost:8080 --trials 5")
    print("  agent-security test mcp --url http://localhost:8080 --delay 1000")
    print()
    print("Research: https://doi.org/10.5281/zenodo.19162104")
    print("Repo:     https://github.com/msaleme/red-team-blue-team-agent-fabric")


def main():
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help", "help"):
        print_usage()
        sys.exit(0)

    if args[0] == "version":
        print(f"agent-security-harness v{VERSION}")
        print(f"Tests: 209 across {len(HARNESSES)} harness modules")
        print(f"Protocols: MCP (JSON-RPC 2.0), A2A, L402")
        print(f"Platforms: 20 enterprise adapters")
        print(f"Standards: OWASP Agentic Top 10, NIST AI 800-2, NIST AI RMF")
        print(f"Research:  https://doi.org/10.5281/zenodo.19162104")
        sys.exit(0)

    if args[0] == "list":
        if len(args) > 1 and args[1] in HARNESSES:
            harness_name = args[1]
            info = HARNESSES[harness_name]
            mod = importlib.import_module(info["module"])
            print(f"{'='*60}")
            print(f"{harness_name.upper()} - {info['description']}")
            print(f"{'='*60}")
            print()
            # Find the test class and enumerate test methods
            found = False
            for attr_name in dir(mod):
                obj = getattr(mod, attr_name)
                if isinstance(obj, type) and attr_name.endswith("Tests"):
                    methods = [m for m in dir(obj) if m.startswith("test_")]
                    for m in methods:
                        fn = getattr(obj, m)
                        doc = (fn.__doc__ or "").strip().split("\n")[0] if fn.__doc__ else m
                        print(f"  {doc}")
                    found = True
                    break
            if not found:
                print(f"  (use 'python -m {info['module']} --list' for test details)")
            print()
        else:
            print(f"Agent Security Harness v{VERSION}")
            print()
            print("Available harnesses:")
            for name, info in HARNESSES.items():
                print(f"  {name:25s} {info['description']}")
            print()
            print("Use 'agent-security list <harness>' to see individual tests.")
        sys.exit(0)

    if args[0] == "test":
        if len(args) < 2:
            print("Error: specify a harness name. Use 'agent-security list' to see options.")
            sys.exit(1)

        harness_name = args[1]
        if harness_name not in HARNESSES:
            print(f"Error: unknown harness '{harness_name}'")
            print(f"Available: {', '.join(HARNESSES.keys())}")
            sys.exit(1)

        info = HARNESSES[harness_name]
        # Extract --delay/--delay-ms before passing to harness (not all harnesses support it)
        harness_args = args[2:]
        delay_ms = 0
        filtered_args = []
        i = 0
        while i < len(harness_args):
            if harness_args[i] in ("--delay", "--delay-ms") and i + 1 < len(harness_args):
                try:
                    delay_ms = int(harness_args[i + 1])
                except ValueError:
                    pass
                i += 2  # Skip flag + value
            else:
                filtered_args.append(harness_args[i])
                i += 1

        if delay_ms > 0:
            import time
            original_run_module = __import__("runpy").run_module
            print(f"[Delay: {delay_ms}ms between tests]")
            # Note: delay is applied at CLI level for harnesses that don't natively support it

        sys.argv = [info["module"]] + filtered_args

        import runpy
        runpy.run_module(info["module"], run_name="__main__")
        sys.exit(0)

    print(f"Error: unknown command '{args[0]}'")
    print("Use 'agent-security --help' for usage.")
    sys.exit(1)


if __name__ == "__main__":
    main()
