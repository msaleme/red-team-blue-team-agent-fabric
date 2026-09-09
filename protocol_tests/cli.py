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
    agent-security --version                # Same, conventional flag form
"""

from __future__ import annotations

import importlib
import importlib.util  # `importlib` alone does not expose .util
import json as _json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone

from protocol_tests.version import get_harness_version

# Single source of truth: pyproject.toml (via version.py), never hardcoded (issue #5)
VERSION = get_harness_version()

# ---------------------------------------------------------------------------
# Simulate-mode helpers  (#152 — R31)
# ---------------------------------------------------------------------------

# Regexes matching the patterns in count_tests.py
_TEST_ID_RE = re.compile(r'test_id\s*=\s*["\']([^"\']+)["\']')
_ARG_ID_RE = re.compile(
    r'(?:self\._test_\w+|_test_\w+)\(\s*["\']'
    r'([A-Z]+-[A-Z0-9]+[a-z]?)'
    r'["\']'
)
_ERR_SUFFIX = "-ERR"

# name= that immediately follows test_id= on the same line or nearby
_TEST_ID_NAME_RE = re.compile(
    r'test_id\s*=\s*["\']([^"\']+)["\']'
    r'[^)]*?name\s*=\s*["\']([^"\']+)["\']'
)

# category= that follows test_id= in the same constructor call
_TEST_ID_CATEGORY_RE = re.compile(
    r'test_id\s*=\s*["\']([^"\']+)["\']'
    r'[^)]*?(?:category|attack_pattern)\s*=\s*["\']([^"\']+)["\']'
)


def _extract_test_catalog(module_path: str) -> list[dict]:
    """Extract test IDs, names, and categories from a harness source file.

    Returns a list of dicts with keys: test_id, name, category.
    Uses the same regex strategy as scripts/count_tests.py.
    """
    text = open(module_path).read()

    # Collect unique test IDs (same logic as count_tests.py)
    ids = set(_TEST_ID_RE.findall(text))
    ids |= set(_ARG_ID_RE.findall(text))
    ids = {i for i in ids if not i.endswith(_ERR_SUFFIX)}

    # Build name/category lookups
    id_to_name: dict[str, str] = {}
    for tid, name in _TEST_ID_NAME_RE.findall(text):
        if tid in ids:
            id_to_name[tid] = name

    id_to_cat: dict[str, str] = {}
    for tid, cat in _TEST_ID_CATEGORY_RE.findall(text):
        if tid in ids:
            id_to_cat[tid] = cat

    catalog: list[dict] = []
    for tid in sorted(ids):
        catalog.append({
            "test_id": tid,
            "name": id_to_name.get(tid, tid),
            "category": id_to_cat.get(tid, "general"),
        })
    return catalog


def _report_path_from(args: list[str]) -> str | None:
    """`--report PATH` or `--report=PATH` from the harness-bound argv, else None."""
    for i, a in enumerate(args):
        if a == "--report" and i + 1 < len(args):
            return args[i + 1]
        if a.startswith("--report="):
            return a.partition("=")[2]
    return None


def _simulate_harness(harness_name: str, info: dict,
                      json_output: bool, html_output: str | None,
                      report_path: str | None = None) -> None:
    """Generate synthetic results for a harness without a live target.

    Every row is INCONCLUSIVE, not passed.

    `report_path` is honoured here because the dispatcher exits before the
    module would ever see `--report`. `agent-security test mcp --simulate
    --report x.json` exited 0 and wrote nothing -- silent success on a request
    that was not performed, which is the same shape as a pass that was not
    earned. Found by the third external review, 2026-09-07. The file carries
    the same dict `--json` prints; a write failure is a non-zero exit.

    This previously emitted `"passed": True` for every test, so a simulated run
    produced 100% pass, risk score 0, AUROC 1.0000 -- a clean bill of health for
    a run that contacted nothing. The repo's own schema already defines the
    right word: `inconclusive` means "the control was not exercised -- the
    target did not service the request". A simulated run is definitionally
    that.

    It is deliberately not `"passed": False` either. A fail asserts the control
    did not hold, which a run that never made a request cannot establish.
    """
    mod = importlib.import_module(info["module"])
    catalog = _extract_test_catalog(mod.__file__)

    if not catalog:
        print(f"Warning: no test IDs found in {info['module']}", file=sys.stderr)
        sys.exit(1)

    timestamp = datetime.now(timezone.utc).isoformat()
    results = []
    for entry in catalog:
        results.append({
            "test_id": entry["test_id"],
            "name": entry["name"],
            "category": entry["category"],
            "passed": False,
            # The canonical structural marker (http_helpers.INCONCLUSIVE_FIELDS),
            # not a renderer-private `inconclusive` key. One vocabulary: a
            # consumer that reads the shared predicate classifies this row
            # exactly as it classifies a harness result object.
            "not_evaluated": True,
            # The INCONCLUSIVE_PREFIX form, so the consumers that classify on
            # the details string agree with the consumers that read the field.
            "details": (
                "INCONCLUSIVE - simulated run; no target was contacted, so "
                "this control was not exercised"
            ),
            "simulated": True,
        })

    report = {
        "suite": info["description"],
        "harness": harness_name,
        "timestamp": timestamp,
        "mode": "simulation",
        "summary": {
            "total": len(results),
            "passed": 0,
            "failed": 0,
            "inconclusive": len(results),
            # Nothing was serviced, so there is no denominator and no rate.
            # A rate of zero would be a claim; absence is not.
            "serviced": 0,
            "pass_rate": None,
            "simulated": True,
        },
        "status": "inconclusive",
        "results": results,
    }

    if json_output:
        print(_json.dumps(report, indent=2))
    else:
        print(f"{'=' * 60}")
        print(f"SIMULATION: {harness_name.upper()} — {info['description']}")
        print(f"{'=' * 60}")
        print("Mode: SIMULATION (no live target)")
        print(f"Tests: {len(results)}")
        print()
        for r in results:
            print(f"  [SIM] {r['test_id']:12s} {r['name']}")
        print()
        # The JSON said every row was unevaluated and this line said they all
        # passed. Same run, two answers; the one a human reads was the wrong one.
        print(f"Result: {len(results)}/{len(results)} INCONCLUSIVE "
              f"(simulated; no target contacted, nothing exercised)")

    # --report: the same document --json prints, at the path that was asked for.
    if report_path:
        try:
            with open(report_path, "w", encoding="utf-8") as _rf:
                _json.dump(report, _rf, indent=2)
        except OSError as e:
            print(f"error: could not write --report {report_path}: {e}",
                  file=sys.stderr)
            sys.exit(1)
        print(f"Report written to {report_path}", file=sys.stderr)

    # --html support
    if html_output:
        try:
            _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if _repo_root not in sys.path:
                sys.path.insert(0, _repo_root)
            from scripts.html_report import generate_html as _gen_html
            _html_out = _gen_html(report)
            with open(html_output, "w") as _hf:
                _hf.write(_html_out)
            print(f"HTML report written to {html_output}", file=sys.stderr)
        except Exception as e:
            print(f"Warning: HTML report generation failed: {e}", file=sys.stderr)

    # Telemetry. This sent `passed=len(results), failed=0` while every row
    # above is `not_evaluated: True`: the console said N/N INCONCLUSIVE, the
    # report said passed 0, and the event said N passed. Same run, third
    # answer. Count the rows with the shared three-state predicate, so the
    # event can only say what the rows say.
    try:
        from protocol_tests.telemetry import send_telemetry_event, verdict_counts
        send_telemetry_event(module=harness_name, **verdict_counts(results))
    except Exception:
        pass

#: The one reason a live event can give for carrying no counts. A fixed
#: token, not free text: the payload is documented field by field in
#: docs/PRIVACY.md and a free-text field is an undocumented one.
COUNTS_UNAVAILABLE_REASON = "results_not_exposed_and_no_report_written"


def _report_counts(report_path: str | None) -> dict | None:
    """Three-state counts read back from a report the harness wrote, or None.

    The rows are counted with the same `verdict_counts` the namespace path
    uses, so a written report and an in-memory result list can only give one
    answer for one run."""
    if not report_path:
        return None
    try:
        with open(report_path, encoding="utf-8") as fh:
            report = _json.load(fh)
    except (OSError, ValueError):
        return None
    rows = report.get("results") if isinstance(report, dict) else None
    if not isinstance(rows, list) or not rows:
        return None
    from protocol_tests.telemetry import verdict_counts
    return verdict_counts(rows)


def _live_run_counts(ns: dict, report_path: str | None = None) -> dict:
    """Three-state telemetry counts for a live run, or an explicit absence.

    Reads the same names the inline version read (`_results`, `results`,
    `test_results`, then a unittest-style `_test_result` / `test_result`) and
    counts them with `telemetry.verdict_counts`, so a row the target never
    serviced is reported as INCONCLUSIVE instead of vanishing. The inline
    version counted only `status == "PASS"` / `FAIL` / `ERROR` and, for the
    unittest shape, `passed = testsRun - failed` -- a residual bucket that
    scored every skipped test as a pass. Here `skipped` is INCONCLUSIVE and
    `passed` is what is left after both, so the four counts always sum.

    Every harness `main()` ends in `sys.exit()`, `SystemExit` carries no
    namespace, and results live on a harness instance rather than at module
    level, so in practice `ns` is `{}`. Until 2026-09-08 that case returned
    0/0/0/0: an installed AP2 run whose report held 17 rows sent
    `tests:0, passed:0, failed:0, inconclusive:0` (fourth external review,
    R4-12). Zero observations and unavailable counts are different states,
    and an event about a known non-empty run must not publish measured-looking
    zeros. So, in order:

    1. results in the namespace -- counted;
    2. a unittest result in the namespace -- counted;
    3. a report the harness wrote to `report_path` -- its rows counted, which
       is real data the CLI already has;
    4. otherwise `counts_available: False` with a fixed `reason`, and NO
       count fields. The sender omits them rather than sending null, so a
       consumer summing `tests` across events cannot read absence as zero.
    """
    from protocol_tests.telemetry import verdict_counts

    for key in ("_results", "results", "test_results"):
        result_list = ns.get(key)
        if isinstance(result_list, (list, tuple)) and result_list:
            return {**verdict_counts(result_list), "counts_available": True}

    for key in ("_test_result", "test_result"):
        tr = ns.get(key)
        if tr and hasattr(tr, "testsRun"):
            tests = int(tr.testsRun)
            failed = len(getattr(tr, "failures", [])) + len(getattr(tr, "errors", []))
            inconclusive = len(getattr(tr, "skipped", []))
            passed = max(tests - failed - inconclusive, 0)
            return {"tests": tests, "passed": passed, "failed": failed,
                    "inconclusive": inconclusive, "counts_available": True}

    from_report = _report_counts(report_path)
    if from_report is not None:
        return {**from_report, "counts_available": True}

    return {"counts_available": False, "reason": COUNTS_UNAVAILABLE_REASON}

HARNESSES = {
    "mcp": {
        "module": "protocol_tests.mcp_harness",
        "description": "MCP wire-protocol security tests (33 tests, JSON-RPC 2.0)",
    },
    "mcp-supplychain": {
        "module": "protocol_tests.mcp_supplychain",
        "description": "MCP supply-chain / framework-layer pre-flight tests (4 tests, binary resolution + install scripts + pinning)",
    },
    "a2a": {
        "module": "protocol_tests.a2a_harness",
        "description": "A2A wire-protocol security tests (13 tests, Agent Cards + tasks)",
    },
    "l402": {
        "module": "protocol_tests.l402_harness",
        "description": "L402 payment flow security tests (33 tests, macaroons + invoices)",
    },
    "x402": {
        "module": "protocol_tests.x402_harness",
        "description": "x402 payment protocol security tests (54 tests, Coinbase/Stripe agent payments)",
    },
    "x402-fireblocks": {
        "module": "protocol_tests.x402_fireblocks_harness",
        "description": "x402 Fireblocks security-extension conformance (17 tests, request integrity + spend governance + batch settlement)",
    },
    "ap2": {
        "module": "protocol_tests.ap2_harness",
        "description": "AP2 mandate-chain conformance (17 tests, Intent/Cart/Payment mandate authorization, FIDO-governed)",
    },
    "receipt-claim": {
        "module": "protocol_tests.receipt_claim_harness",
        "description": "Receipt claim-level verification (11 tests, format-valid-but-claim-invalid receipts rejected on semantic grounds)",
    },
    "ucp-acp": {
        "module": "protocol_tests.ucp_acp_harness",
        "description": "UCP/ACP merchant-journey conformance (12 tests, agent-profile + cross-merchant cart + delegated checkout)",
    },
    "card-token": {
        "module": "protocol_tests.card_token_harness",
        "description": "Card-network agentic-token conformance (12 tests, Visa TAP / Mastercard Agentic Tokens funding instrument)",
    },
    "settlement-finality": {
        "module": "protocol_tests.settlement_finality_harness",
        "description": "Denial-of-settlement / finality conformance (8 tests, release-before-finality, reorg, withheld-settlement liveness)",
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
        "description": "Framework adapters (15 tests, 6 frameworks)",
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
    "delegation-chain": {
        "module": "protocol_tests.delegation_chain_harness",
        "description": "Multi-hop delegated-authority attenuation (11 tests, per-hop narrowing + audience + expiry/revocation + confused deputy)",
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
    "mcp-tool-poisoning": {
        "module": "protocol_tests.mcp_tool_poisoning_harness",
        "description": "MCP tool-poisoning reproduction suite (10 tests, Invariant Labs Tool Poisoning + ClawHub RFC #99; CVE-009/010 map to CVE-2026-35625/35629)",
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
        "description": "Memory & continuity security tests (12 tests, cross-session leakage + poisoning + extraction + namespace scoping boundaries)",
    },
    "multi-agent": {
        "module": "protocol_tests.multi_agent_harness",
        "description": "Multi-agent interaction security tests (19 tests, delegation poisoning + trust boundary bypass + race-condition pretexts + delegated spend bounds)",
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
    "kill-switch": {
        "module": "protocol_tests.kill_switch_harness",
        "description": "Kill-switch compliance tests (4 tests, termination latency + bypass resistance)",
    },
    "watermark": {
        "module": "protocol_tests.watermark_harness",
        "description": "Watermark adversarial tests (5 tests, forgery + stripping + extraction resistance)",
    },
    "benchmark-integrity": {
        "module": "protocol_tests.benchmark_integrity_harness",
        "description": "Benchmark integrity tests (7 tests, UC Berkeley RDI eval pipeline vulnerabilities)",
    },
    "governance-modification": {
        "module": "protocol_tests.governance_modification_harness",
        "description": "Governance self-modification tests (6 tests, agent gate/threshold/permission tampering)",
    },
    "skill-security": {
        "module": "protocol_tests.skill_security_harness",
        "description": "Skill supply chain security (8 tests, SSP RFC #99)",
    },
    "tool-search": {
        "module": "protocol_tests.tool_search_harness",
        "description": "Embedding-based tool search security (6 tests, ranking manipulation + unsigned injection + post-discovery access control)",
    },
    "ptc": {
        "module": "protocol_tests.ptc_harness",
        "description": "Programmatic Tool Calling sandbox security (6 tests, destructive opt-in + sandbox exfiltration + container isolation)",
    },
    "prompt-caching": {
        "module": "protocol_tests.prompt_caching_harness",
        "description": "Prompt caching isolation security (6 tests, cross-session bleed + tenant key collision + cache-prefix injection)",
    },
    "hitl": {
        "module": "protocol_tests.hitl_harness",
        "description": "Human-in-the-loop security tests (8 tests, OWASP Agentic T10 reviewer exposure + T15 agent-to-human manipulation)",
    },
    "extended-thinking": {
        "module": "protocol_tests.extended_thinking_harness",
        "description": "Extended thinking tamper-evidence conformance (6 tests, signature tampering + cross-conversation replay + redaction leakage)",
    },
    "agent-data-injection": {
        "module": "protocol_tests.agent_data_injection",
        "description": (
            "Agent data injection: forged provenance, fabricated tool history, "
            "delimiter-shaped boundaries (3 tests, needs HARNESS_ADI_MODEL)"
        ),
    },
}


def _total_tests() -> int:
    """Compute total test count by summing the leading number in each harness description."""
    total = 0
    for info in HARNESSES.values():
        m = re.search(r'\((\d+)\s+tests', info["description"])
        if m:
            total += int(m.group(1))
    return total


def _module_declares_flag(harness_name: str, flag: str) -> bool:
    """Whether a harness module declares `flag` in its own argparse.

    Derived from the module source, not from a maintained list. A maintained
    list is the thing that drifts: the CLI already carried the comment "pass
    --json through to harness modules that support it" directly above a line
    that appended it unconditionally, so the intent was recorded and the
    implementation did not match it.

    Located through importlib rather than a relative path, so the answer does
    not depend on the working directory the CLI was invoked from.
    """
    info = HARNESSES.get(harness_name)
    if not info:
        return False
    try:
        spec = importlib.util.find_spec(info["module"])
        origin = spec.origin if spec else None
        if not origin:
            return False
        with open(origin, encoding="utf-8") as fh:
            src = fh.read()
    except (ImportError, OSError, ValueError):
        # Unreadable module: say the flag is absent rather than guess. The
        # caller turns that into a clear refusal, which beats dispatching and
        # letting argparse fail with "unrecognized arguments" from a submodule.
        return False
    return bool(re.search(r'add_argument\(\s*["\']' + re.escape(flag) + r'["\']', src))


def _json_capable_count() -> int:
    """How many registered harnesses declare --json. Derived, so it cannot drift."""
    return sum(1 for name in HARNESSES if _module_declares_flag(name, "--json"))


def _test_bearing_modules() -> int:
    """Registered harnesses that actually contribute tests. NOT len(HARNESSES).

    `community` hosts community-contributed YAML patterns and ships none of its
    own, so 44 commands are registered and 43 bear tests. Derived from the same
    descriptions `_total_tests` sums, so the numerator and denominator of the
    banner cannot drift apart.

    testing/test_code_quality.py::_harness_count fixed exactly this conflation
    for README and TEST-INVENTORY on 2026-08-09, computing the figure from
    scripts/count_tests.py instead of len(HARNESSES). The `--version` banner was
    not reached by that repair and kept printing the registered count against the
    test total, so `agent-security --version` said "606 across 44 harness
    modules" while the README it shipped beside said 43. Flagged 2026-08-29.
    """
    return sum(1 for info in HARNESSES.values()
               if re.search(r'\((\d+)\s+tests', info["description"]))


def print_usage():
    print(f"Agent Security Harness v{VERSION}")
    print(f"{_total_tests()} security tests for AI agent systems")
    print()
    print("Usage:")
    print("  agent-security test <harness> [options]    Run a test harness")
    print("  agent-security list [harness]              List available tests")
    print("  agent-security version | --version | -V    Show version")
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
    print("  agent-security test mcp --simulate --json")
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

    # Accept the conventional flags as well as the subcommand. `--version` is
    # the first thing anyone types to confirm which build they are on, and it
    # previously exited with "unknown command". That matters most right after
    # an upgrade, which is exactly when it was failing.
    if args[0] in ("version", "--version", "-V"):
        print(f"agent-security-harness v{VERSION}")
        print(f"Tests: {_total_tests()} across {_test_bearing_modules()} test-bearing "
              f"modules ({len(HARNESSES)} registered harnesses)")
        print("Protocols: MCP (JSON-RPC 2.0), A2A, L402, x402")
        print("Platforms: 25 cloud + 20 enterprise adapters")
        print("Standards: OWASP Agentic Top 10, NIST AI 800-2, NIST AI RMF, AIUC-1")
        print("Research:  https://doi.org/10.5281/zenodo.19162104")
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
            import json as _json
            from pathlib import Path
            cfg_dir = Path.home() / ".agent-security"
            cfg_dir.mkdir(parents=True, exist_ok=True)
            cfg_file = cfg_dir / "telemetry.json"
            cfg_file.write_text(_json.dumps({"enabled": False}, indent=2) + "\n")
            print("Telemetry disabled. Config written to ~/.agent-security/telemetry.json")
            sys.exit(0)
        elif "--telemetry" in args:
            import json as _json
            from pathlib import Path
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
        # Extract --delay/--delay-ms, --no-telemetry, --json, --simulate before passing to harness
        harness_args = args[2:]
        delay_ms = 0
        no_telemetry = False
        json_output = False
        simulate = False
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
            elif harness_args[i] == "--simulate":
                simulate = True
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
        #
        # Only 11 of the 44 registered harnesses declare --json. This block
        # appended it to all of them, so `test a2a --json` and 32 others died on
        # "unrecognized arguments: --json" from inside the submodule, exit 2,
        # after the CLI had already advertised the flag as common. Refuse before
        # dispatch with an accurate message instead. Reported 2026-08-29.
        if json_output:
            if not _module_declares_flag(harness_name, "--json"):
                print(f"error: `{harness_name}` does not support --json.",
                      file=sys.stderr)
                print(file=sys.stderr)
                print("--json is not yet a common contract across this CLI: "
                      f"{_json_capable_count()} of {len(HARNESSES)} registered "
                      "harnesses declare it.", file=sys.stderr)
                if _module_declares_flag(harness_name, "--report"):
                    print(f"\nUse:  agent-security test {harness_name} "
                          "--report <path>\nwhich writes the same JSON to a file.",
                          file=sys.stderr)
                sys.exit(2)
            os.environ["AGENT_SECURITY_JSON_OUTPUT"] = "1"
            filtered_args.append("--json")

        if delay_ms > 0:
            os.environ["AGENT_SECURITY_DELAY_MS"] = str(delay_ms)
            if not json_output:
                print(f"[Delay: {delay_ms}ms between tests]")

        # --simulate: generate synthetic output without a live server (#152)
        # For aiuc1, pass --simulate through (it handles simulation natively).
        # For all other harnesses, intercept here and produce synthetic JSON.
        if simulate and harness_name != "aiuc1":
            _simulate_harness(harness_name, info, json_output, html_output,
                              report_path=_report_path_from(filtered_args))
            sys.exit(0)

        # For aiuc1 with --simulate, pass the flag through to the module
        if simulate and harness_name == "aiuc1":
            filtered_args.append("--simulate")

        # The documented MCP example is
        #
        #     agent-security test mcp --url http://localhost:8080/mcp
        #
        # and it did not work: mcp_harness requires an explicit --transport, so
        # the principal operator path in the CLI help and the README exited 2
        # with {"error": "--transport required"}. Reported 2026-08-30 by an
        # independent review of the v4.17.0 tag.
        #
        # Infer http from --url when no transport was given. An explicit
        # --transport always wins, and stdio stays explicit because it takes a
        # --command rather than a --url, so there is nothing to infer it from.
        if (_module_declares_flag(harness_name, "--transport")
                and any(a == "--url" or a.startswith("--url=") for a in filtered_args)
                and not any(a == "--transport" or a.startswith("--transport=")
                            for a in filtered_args)):
            filtered_args += ["--transport", "http"]

        # --html needs a report to render. If the operator asked for HTML but
        # not JSON, ask the harness for a throwaway report we can read back.
        _side_report = None
        # The operator's own --report path, read before the --html side report
        # is appended so the two are never confused (R4-08).
        _operator_report = _report_path_from(filtered_args)
        if html_output and _module_declares_flag(harness_name, "--report") and not any(
                a == "--report" or a.startswith("--report=") for a in filtered_args):
            _side_report = os.path.join(
                tempfile.gettempdir(), f"agent-security-html-{os.getpid()}.json")
            filtered_args += ["--report", _side_report]

        sys.argv = [info["module"]] + filtered_args

        import runpy
        # Every harness main() ends in sys.exit(), which raises SystemExit.
        # Nothing here caught it, so everything below -- telemetry AND the
        # entire --html block -- was unreachable on this path. `--html` is
        # advertised in print_usage() and produced a file for 0 of 45
        # harnesses: exit 0, no file, no warning. Catch it, finish the work,
        # then exit with the code the harness asked for.
        _harness_exit = 0
        try:
            ns = runpy.run_module(info["module"], run_name="__main__")
        except SystemExit as exc:
            _harness_exit = exc.code if isinstance(exc.code, int) else (
                0 if exc.code is None else 1
            )
            ns = getattr(exc, "_ns", None) or {}

        # Send anonymous telemetry after harness completes (#112).
        # Extract actual test counts from the harness namespace if available;
        # failing that, from the report the harness wrote (`--report PATH`, or
        # the throwaway one --html asked for). With neither, the event says
        # the counts are unavailable rather than zero (R4-12).
        try:
            from protocol_tests.telemetry import send_telemetry_event
            send_telemetry_event(
                module=harness_name,
                **_live_run_counts(ns, report_path=_report_path_from(filtered_args)))
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
                # 41 of 45 harnesses keep their results in main()'s locals, so
                # they never appear in the module namespace and the namespace
                # scan below finds nothing. Every harness that declares
                # --report can write one, so ask it for a file and render that.
                # This is why --html produced nothing even once SystemExit was
                # caught: the block was reachable and still had no data.
                if _side_report and os.path.exists(_side_report):
                    try:
                        with open(_side_report) as _fh:
                            _candidate = _json.load(_fh)
                        if isinstance(_candidate, dict) and "results" in _candidate:
                            report_json = _candidate
                    except (OSError, ValueError):
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

        if _side_report:
            try:
                os.remove(_side_report)
            except OSError:
                pass

        # The comment above promised "exit with the code the harness asked
        # for", and the line here was `sys.exit(0)`. A usage error inside the
        # harness (argparse exit 2, no report written) therefore became a
        # successful run to any CI job reading the status; an independent
        # review reproduced it with
        #     agent-security test skill-security --url ... --report out.json
        # (R4-08, fourth external review, 2026-09-08). Propagate the child's
        # code, and when the operator asked for a file that never appeared,
        # say so and refuse to exit 0.
        _problems = []
        if _harness_exit != 0:
            _problems.append(f"harness `{harness_name}` exited {_harness_exit}")
        if _operator_report and not os.path.exists(_operator_report):
            _problems.append(f"--report {_operator_report} was requested and no file was written")
        if html_output and not os.path.exists(html_output):
            _problems.append(f"--html {html_output} was requested and no file was written")
        if _problems:
            print("error: " + "; ".join(_problems), file=sys.stderr)
        sys.exit(_harness_exit if _harness_exit != 0 else (1 if _problems else 0))

    print(f"Error: unknown command '{args[0]}'")
    print("Use 'agent-security --help' for usage.")
    sys.exit(1)


if __name__ == "__main__":
    main()
