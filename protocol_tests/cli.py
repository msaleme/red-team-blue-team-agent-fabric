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

import os
import sys
import importlib


VERSION = "3.9.0"

HARNESSES = {
    "mcp": {
        "module": "protocol_tests.mcp_harness",
        "description": "MCP wire-protocol security tests (13 tests, JSON-RPC 2.0)",
    },
    "a2a": {
        "module": "protocol_tests.a2a_harness",
        "description": "A2A wire-protocol security tests (12 tests, Agent Cards + tasks)",
    },
    "l402": {
        "module": "protocol_tests.l402_harness",
        "description": "L402 payment flow security tests (33 tests, macaroons + invoices)",
    },
    "x402": {
        "module": "protocol_tests.x402_harness",
        "description": "x402 payment protocol security tests (25 tests, Coinbase/Stripe agent payments)",
    },
    "enterprise": {
        "module": "protocol_tests.enterprise_adapters",
        "description": "Enterprise platform adapters (31 tests, 9 platforms)",
    },
    "extended-enterprise": {
        "module": "protocol_tests.extended_enterprise_adapters",
        "description": "Extended enterprise adapters (27 tests, 11 platforms)",
    },
    "framework": {
        "module": "protocol_tests.framework_adapters",
        "description": "Framework adapters (24 tests, 5 frameworks)",
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
    "over-refusal": {
        "module": "protocol_tests.over_refusal_harness",
        "description": "Over-refusal / false positive rate tests (25 tests, legitimate request validation)",
    },
    "provenance": {
        "module": "protocol_tests.provenance_harness",
        "description": "Provenance & tool attestation tests (15 tests, supply chain + attestation bypass)",
    },
    "jailbreak": {
        "module": "protocol_tests.jailbreak_harness",
        "description": "Expanded jailbreak corpus (25 tests, DAN + smuggling + persistence)",
    },
    "return-channel": {
        "module": "protocol_tests.return_channel_harness",
        "description": "Return channel poisoning tests (8 tests, output sanitization + context manipulation)",
    },
    "capability-profile": {
        "module": "protocol_tests.capability_profile_harness",
        "description": "Capability profile validation tests (10 tests, executor boundary enforcement)",
    },
    "harmful-output": {
        "module": "protocol_tests.harmful_output_harness",
        "description": "Harmful output content tests (10 tests, AIUC-1 C003/C004)",
    },
    "cbrn": {
        "module": "protocol_tests.cbrn_harness",
        "description": "CBRN content prevention tests (8 tests, AIUC-1 F002)",
    },
    "incident-response": {
        "module": "protocol_tests.incident_response_harness",
        "description": "Incident response validation tests (8 tests, AIUC-1 E001-E003)",
    },
    "cve-2026-25253": {
        "module": "protocol_tests.cve_2026_25253_harness",
        "description": "CVE-2026-25253 reproduction suite (8 tests, MCP supply chain poisoning)",
    },
    "aiuc1": {
        "module": "protocol_tests.aiuc1_compliance_harness",
        "description": "AIUC-1 compliance tests (12 tests, incident response + CBRN + harmful content)",
    },
    "cloud-agents": {
        "module": "protocol_tests.cloud_agent_harness",
        "description": "Cloud agent platform tests (25 tests, 5 platforms: Bedrock, Azure, Vertex, Agentforce, watsonx)",
    },
    "autogen": {
        "module": "protocol_tests.autogen_harness",
        "description": "AutoGen multi-agent security tests (10 tests, conversation injection + delegation + speaker selection)",
    },
    "memory": {
        "module": "protocol_tests.memory_harness",
        "description": "Memory & continuity security tests (10 tests, cross-session leakage + poisoning + extraction)",
    },
    "multi-agent": {
        "module": "protocol_tests.multi_agent_harness",
        "description": "Multi-agent interaction security tests (12 tests, delegation poisoning + trust boundary bypass)",
    },
    "crewai-cve": {
        "module": "protocol_tests.crewai_cve_harness",
        "description": "CrewAI CVE reproduction suite (10 tests, CVE-2026-2275/2285/2286/2287 sandbox escape + SSRF + file read)",
    },
    "community": {
        "module": "protocol_tests.community_runner",
        "description": "Community-contributed attack patterns (YAML-based, extensible)",
    },
    "intent-contract": {
        "module": "protocol_tests.intent_contract_harness",
        "description": "Intent contract validation tests (8 tests, intent declaration + scope + escalation)",
    },
}


def print_usage():
    print(f"Agent Security Harness v{VERSION}")
    print(f"431 security tests for AI agent systems")
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
    print("  agent-security test mcp --url http://localhost:8080 --json")
    print("  agent-security test mcp --url http://localhost:8080 --html report.html")
    print()
    print("Attestation & Configuration:")
    print("  agent-security publish --attestation <file> --server-name <name>")
    print("  agent-security verify --registry-id <id>")
    print("  agent-security config --no-telemetry")
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
        print(f"Tests: 431 across {len(HARNESSES)} harness modules")
        print(f"Protocols: MCP (JSON-RPC 2.0), A2A, L402, x402")
        print(f"Platforms: 25 cloud + 20 enterprise adapters")
        print(f"Standards: OWASP Agentic Top 10, NIST AI 800-2, NIST AI RMF, AIUC-1")
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

    if args[0] == "config":
        # Handle config subcommands (e.g. --no-telemetry)
        if "--no-telemetry" in args:
            from pathlib import Path
            import json as _json
            cfg_dir = Path.home() / ".agent-security"
            cfg_dir.mkdir(parents=True, exist_ok=True)
            cfg_file = cfg_dir / "telemetry.json"
            cfg_file.write_text(_json.dumps({"enabled": False}, indent=2) + "\n")
            print("Telemetry disabled. Config written to ~/.agent-security/telemetry.json")
            sys.exit(0)
        elif "--telemetry" in args:
            from pathlib import Path
            import json as _json
            cfg_dir = Path.home() / ".agent-security"
            cfg_dir.mkdir(parents=True, exist_ok=True)
            cfg_file = cfg_dir / "telemetry.json"
            cfg_file.write_text(_json.dumps({"enabled": True}, indent=2) + "\n")
            print("Telemetry enabled.")
            sys.exit(0)
        else:
            print("Usage: agent-security config [--no-telemetry | --telemetry]")
            sys.exit(1)

    if args[0] == "publish":
        # #115 - Publish attestation report to registry
        import argparse as _ap
        pub_parser = _ap.ArgumentParser(prog="agent-security publish")
        pub_parser.add_argument("--attestation", required=True, help="Path to attestation report JSON file")
        pub_parser.add_argument("--server-name", required=True, help="Human-readable server name")
        pub_parser.add_argument("--contact", default=None, help="Optional contact email")
        pub_args = pub_parser.parse_args(args[1:])

        import json as _json
        try:
            with open(pub_args.attestation) as f:
                report = _json.load(f)
        except FileNotFoundError:
            print(f"Error: file not found: {pub_args.attestation}", file=sys.stderr)
            sys.exit(1)
        except _json.JSONDecodeError as e:
            print(f"Error: invalid JSON in {pub_args.attestation}: {e}", file=sys.stderr)
            sys.exit(1)

        from protocol_tests.attestation_registry import publish_attestation
        try:
            result = publish_attestation(
                report=report,
                server_name=pub_args.server_name,
                contact=pub_args.contact,
            )
        except (ValueError, RuntimeError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        print(_json.dumps(result, indent=2))
        sys.exit(0)

    if args[0] == "verify":
        # #115 - Verify attestation by registry ID
        import argparse as _ap
        ver_parser = _ap.ArgumentParser(prog="agent-security verify")
        ver_parser.add_argument("--registry-id", required=True, help="Registry ID to verify")
        ver_args = ver_parser.parse_args(args[1:])

        import json as _json
        from protocol_tests.attestation_registry import verify_attestation
        try:
            result = verify_attestation(ver_args.registry_id)
        except (ValueError, RuntimeError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        print(_json.dumps(result, indent=2))
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
        # Extract --delay/--delay-ms, --no-telemetry, and --json before passing to harness
        harness_args = args[2:]
        delay_ms = 0
        no_telemetry = False
        json_output = False
        html_output = None  # Path for --html report
        filtered_args = []
        i = 0
        while i < len(harness_args):
            if harness_args[i] in ("--delay", "--delay-ms") and i + 1 < len(harness_args):
                try:
                    delay_ms = int(harness_args[i + 1])
                except ValueError:
                    pass
                i += 2  # Skip flag + value
            elif harness_args[i] == "--no-telemetry":
                no_telemetry = True
                i += 1
            elif harness_args[i] == "--json":
                json_output = True
                i += 1
            elif harness_args[i] == "--html" and i + 1 < len(harness_args):
                html_output = harness_args[i + 1]
                json_output = True  # --html implies --json (needs JSON to generate HTML)
                i += 2
            else:
                filtered_args.append(harness_args[i])
                i += 1

        # CLI --no-telemetry flag (path 3 for opt-out)
        if no_telemetry:
            os.environ["AGENT_SECURITY_TELEMETRY"] = "off"

        # --json flag: tell harnesses to output JSON to stdout (#103)
        if json_output:
            os.environ["AGENT_SECURITY_JSON_OUTPUT"] = "1"
            # Also pass --json through to harness modules that support it
            filtered_args.append("--json")

        if delay_ms > 0:
            os.environ["AGENT_SECURITY_DELAY_MS"] = str(delay_ms)
            if not json_output:
                print(f"[Delay: {delay_ms}ms between tests]")

        sys.argv = [info["module"]] + filtered_args

        import runpy
        ns = runpy.run_module(info["module"], run_name="__main__")

        # Send anonymous telemetry after harness completes (#112).
        # Extract actual test counts from the harness namespace if available.
        # Harnesses typically store results in _results, results, or similar.
        try:
            from protocol_tests.telemetry import send_telemetry_event

            # Try to extract counts from the module namespace
            test_count = 0
            pass_count = 0
            fail_count = 0

            # Check common result patterns from harness modules
            for key in ("_results", "results", "test_results"):
                result_list = ns.get(key)
                if isinstance(result_list, (list, tuple)) and result_list:
                    test_count = len(result_list)
                    for r in result_list:
                        status = ""
                        if hasattr(r, "status"):
                            status = str(getattr(r.status, "value", r.status)).upper()
                        elif isinstance(r, dict):
                            status = str(r.get("status", "")).upper()
                        if status == "PASS":
                            pass_count += 1
                        elif status in ("FAIL", "ERROR"):
                            fail_count += 1
                    break

            # Also check unittest-style result objects
            if test_count == 0:
                for key in ("_test_result", "test_result"):
                    tr = ns.get(key)
                    if tr and hasattr(tr, "testsRun"):
                        test_count = tr.testsRun
                        fail_count = len(getattr(tr, "failures", [])) + len(getattr(tr, "errors", []))
                        pass_count = test_count - fail_count
                        break

            send_telemetry_event(module=harness_name, tests=test_count, passed=pass_count, failed=fail_count)
        except Exception:
            pass  # Telemetry must never break the CLI

        # --html <path>: generate self-contained HTML report (#112)
        if html_output:
            try:
                import json as _json

                _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                if _repo_root not in sys.path:
                    sys.path.insert(0, _repo_root)
                from scripts.html_report import generate_html as _gen_html

                report_json = None
                for key in ("_json_report", "json_report", "_report"):
                    candidate = ns.get(key)
                    if isinstance(candidate, dict) and "results" in candidate:
                        report_json = candidate
                        break

                if report_json is None:
                    result_list_raw = None
                    for key in ("_results", "results", "test_results"):
                        candidate = ns.get(key)
                        if isinstance(candidate, (list, tuple)) and candidate:
                            result_list_raw = candidate
                            break
                    if result_list_raw:
                        serialized = []
                        for r in result_list_raw:
                            if isinstance(r, dict):
                                serialized.append(r)
                            elif hasattr(r, "__dict__"):
                                d = {}
                                for attr in ("test_id", "name", "passed", "status",
                                             "severity", "module", "category",
                                             "detail", "error", "reason"):
                                    v = getattr(r, attr, None)
                                    if v is not None:
                                        d[attr] = (
                                            str(v)
                                            if not isinstance(v, (bool, int, float))
                                            else v
                                        )
                                serialized.append(d)
                        report_json = {"results": serialized, "target": "unknown"}

                if report_json:
                    _html_out = _gen_html(report_json)
                    with open(html_output, "w") as _hf:
                        _hf.write(_html_out)
                    print(f"HTML report written to {html_output}", file=sys.stderr)
                else:
                    print("Warning: could not generate HTML -- no results found",
                          file=sys.stderr)
            except Exception as e:
                print(f"Warning: HTML report generation failed: {e}", file=sys.stderr)

        sys.exit(0)

    print(f"Error: unknown command '{args[0]}'")
    print("Use 'agent-security --help' for usage.")
    sys.exit(1)


if __name__ == "__main__":
    main()
