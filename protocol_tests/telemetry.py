"""Anonymous usage telemetry for agent-security-harness.

WHAT THIS SENDS: version, module_name, test_count, passed, failed, os, python_version, timestamp
WHAT THIS NEVER SENDS: URLs, results, payloads, credentials, IPs

OPT IN: export AGENT_SECURITY_TELEMETRY=on

This module is intentionally small (<100 lines) so you can audit it in 2 minutes.
Source: https://github.com/msaleme/red-team-blue-team-agent-fabric/blob/main/protocol_tests/telemetry.py
"""
from __future__ import annotations
import json, os, platform, sys, threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

# Configurable endpoint -- override for self-hosted deployments
TELEMETRY_ENDPOINT = os.environ.get(
    "AGENT_SECURITY_TELEMETRY_URL", "https://telemetry.agentsecurity.dev/v1/event")

_CFG_DIR = Path.home() / ".agent-security"
_CFG_FILE = _CFG_DIR / "telemetry.json"
_NOTICE_MARKER = _CFG_DIR / "telemetry-notice-shown"
_FIRST_RUN_NOTICE = """agent-security-harness: Anonymous usage statistics are OFF by default.
To help improve the framework: export AGENT_SECURITY_TELEMETRY=on
Details: docs/PRIVACY.md
"""

def _is_disabled() -> bool:
    """Check env var and config file. Telemetry is OFF by default (opt-in).

    Telemetry is only enabled when explicitly opted in via:
    - Environment variable: AGENT_SECURITY_TELEMETRY=on/true/1
    - Config file: {"enabled": true}
    """
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

def send_telemetry_event(module: str, tests: int, passed: int, failed: int) -> None:
    """Send a single anonymous telemetry event. Non-blocking."""
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
        "os": platform.system().lower(),  # OS family for platform bug triage
        "py": f"{sys.version_info.major}.{sys.version_info.minor}",  # Python compat
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }).encode()
    threading.Thread(target=_post, args=(payload,), daemon=True).start()

def telemetry_payload_example() -> dict:
    """Return a sample payload so users can see exactly what's sent."""
    from protocol_tests.version import get_harness_version
    return {"v": get_harness_version(), "module": "mcp", "tests": 13, "passed": 11,
            "failed": 2, "os": "linux", "py": "3.12", "ts": "2026-03-28T00:00:00Z"}
