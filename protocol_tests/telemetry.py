"""Anonymous usage telemetry for agent-security-harness.

WHAT THIS SENDS: version, module_name, test_count, passed, failed, inconclusive, os, python_version, timestamp
WHAT THIS NEVER SENDS: URLs, results, payloads, credentials, IPs

OPT IN: export AGENT_SECURITY_TELEMETRY=on

This module is intentionally small (<100 lines) so you can audit it in 2 minutes.
Source: https://github.com/msaleme/red-team-blue-team-agent-fabric/blob/main/protocol_tests/telemetry.py
"""
from __future__ import annotations

import json
import os
import platform
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

# There is no default telemetry endpoint, deliberately.
#
# Until 2026-08-04 this defaulted to https://telemetry.agentsecurity.dev, a domain
# this project does not own and never did. It was fabricated alongside the registry
# host and the privacy contact in 6b6a64c (2026-03-28). Telemetry was opt-in and
# off by default, so this only fired for users who explicitly enabled it -- but for
# those users it sent module names and test counts to a third party.
#
# A security tool must not have a silent default destination. Telemetry is now
# disabled unless BOTH an opt-in and an endpoint you control are configured.
TELEMETRY_ENDPOINT = os.environ.get("AGENT_SECURITY_TELEMETRY_URL", "").strip()

_CFG_DIR = Path.home() / ".agent-security"
_CFG_FILE = _CFG_DIR / "telemetry.json"
_NOTICE_MARKER = _CFG_DIR / "telemetry-notice-shown"
_FIRST_RUN_NOTICE = """agent-security-harness: Anonymous usage statistics are OFF by default.
This project operates no telemetry endpoint, so opting in alone sends nothing.
To collect your own: export AGENT_SECURITY_TELEMETRY_URL=<a host you control>
                    export AGENT_SECURITY_TELEMETRY=on
Details: docs/PRIVACY.md
"""

def _is_disabled() -> bool:
    """Check endpoint, env var, and config file. Telemetry is OFF by default.

    Two independent conditions must both hold before anything is sent:
    - An endpoint is configured via AGENT_SECURITY_TELEMETRY_URL. There is no
      default, so with nothing set there is nowhere to send and telemetry is off.
    - The user opted in, via AGENT_SECURITY_TELEMETRY=on/true/1 or a config file
      containing {"enabled": true}.

    The endpoint check comes first and is not overridable by opting in. An opt-in
    is consent to share with a destination the operator chose, not consent to
    share with whatever host happens to be compiled in.
    """
    if not TELEMETRY_ENDPOINT:
        return True  # No destination configured: nothing to send anywhere.

    # Check config file first - explicit config takes precedence
    try:
        if json.loads(_CFG_FILE.read_text()).get("enabled") is True:
            return False  # Explicitly enabled via config
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass

    # Check environment variable - must be explicitly enabled
    env = os.environ.get("AGENT_SECURITY_TELEMETRY", "").lower()
    if env in ("on", "true", "1"):
        return False  # Explicitly enabled via env var

    return True  # Default: disabled (GDPR-safe opt-in)

def _show_first_run_notice() -> None:
    """Print telemetry notice to stderr on first run. Impossible to miss."""
    if _NOTICE_MARKER.exists():
        return
    print(_FIRST_RUN_NOTICE, file=sys.stderr, flush=True)
    try:
        _CFG_DIR.mkdir(parents=True, exist_ok=True)
        _NOTICE_MARKER.touch()
    except OSError:
        pass  # Non-fatal: notice shows again next time

def _post(payload: bytes) -> None:
    """Fire-and-forget POST. 2s timeout. Failures silently ignored. Never retries."""
    try:
        req = Request(TELEMETRY_ENDPOINT, data=payload,
                      headers={"Content-Type": "application/json"})
        urlopen(req, timeout=2)  # noqa: S310 -- audited, payload is fixed schema
    except Exception:
        pass  # Never retry. Never block. Never raise.

def verdict_counts(results) -> dict:
    """Three-state counts for a telemetry event: tests, passed, failed, inconclusive.

    Both call sites in `cli.py` previously computed these inline, and neither
    had a word for INCONCLUSIVE. The simulated path sent
    `passed=len(results), failed=0` -- every row in that run is marked
    `not_evaluated: True`, so a simulated run of N tests reported N passes to
    whatever endpoint the operator had pointed telemetry at. The live path
    counted `status == "PASS"` and put everything else in silence.

    Absence of a detected attack is not evidence a control held (CLAUDE.md
    item 8). A row is INCONCLUSIVE when the shared predicate says so; only a
    row that was serviced AND carries `passed: True` is a pass; a serviced row
    that does not is a fail. A row that carries neither a `passed` verdict nor
    a recognisable status established nothing and is counted INCONCLUSIVE,
    never as a pass. The four counts always sum: `tests == passed + failed +
    inconclusive`, so `failed=0` is a finding, not a default.

    Accepts result objects and dict rows (a serialised report), because
    `is_inconclusive` accepts both and this helper should not narrow it.
    """
    from protocol_tests.http_helpers import is_inconclusive

    tests = passed = failed = inconclusive = 0
    for r in results:
        tests += 1
        get = r.get if isinstance(r, dict) else (lambda f, d=None: getattr(r, f, d))
        status = get("status", "")
        status = str(getattr(status, "value", status) or "").upper()
        if is_inconclusive(r) or status == "INCONCLUSIVE":
            inconclusive += 1
            continue
        verdict = get("passed", None)
        if verdict is None:
            if status == "PASS":
                verdict = True
            elif status in ("FAIL", "ERROR"):
                verdict = False
            else:
                inconclusive += 1  # No verdict of any shape: nothing established.
                continue
        if verdict:
            passed += 1
        else:
            failed += 1
    return {"tests": tests, "passed": passed, "failed": failed,
            "inconclusive": inconclusive}

def send_telemetry_event(module: str, tests: int, passed: int, failed: int,
                         inconclusive: int = 0) -> None:
    """Send a single anonymous telemetry event. Non-blocking.

    `inconclusive` is the count of rows the target never serviced (or a
    simulated run, which services nothing). It defaults to 0 so callers that
    predate the field keep working; new callers should pass the output of
    `verdict_counts` rather than computing the three buckets by hand.
    """
    if _is_disabled():
        return
    _show_first_run_notice()
    from protocol_tests.version import get_harness_version
    payload = json.dumps({
        "v": get_harness_version(),      # Which version is running
        "module": module,                 # Which harness (e.g. "mcp") -- NOT a URL
        "tests": tests,                   # How many tests ran
        "passed": passed,                 # Pass count only -- no details about which tests
        "failed": failed,                 # Fail count only -- no details about which tests
        "inconclusive": inconclusive,     # Unserviced count only -- never scored as a pass
        "os": platform.system().lower(),  # OS family for platform bug triage
        "py": f"{sys.version_info.major}.{sys.version_info.minor}",  # Python compat
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }).encode()
    threading.Thread(target=_post, args=(payload,), daemon=True).start()

def telemetry_payload_example() -> dict:
    """Return a sample payload so users can see exactly what's sent."""
    from protocol_tests.version import get_harness_version
    return {"v": get_harness_version(), "module": "mcp", "tests": 13, "passed": 9,
            "failed": 2, "inconclusive": 2, "os": "linux", "py": "3.12",
            "ts": "2026-03-28T00:00:00Z"}
