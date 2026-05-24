#!/usr/bin/env python3
"""Self-Hosted Sandbox Isolation Test Harness (v0.1.0 — VS-R01 SKELETON, NOT EXECUTABLE)

Adversarial probes for Anthropic Self-Hosted Sandboxes — the operator-
provisioned execution environment (Modal / Cloudflare Workers / Daytona /
Vercel) that runs tool code on behalf of an Anthropic-orchestrated agent.
The three tests below validate the sandbox-specific isolation surface:
egress boundary (DNS + TCP from inside the sandbox), secret env-var
exposure from the orchestrator config down into tool code, and recovery
state leakage between invocations after a mid-execution crash.

SAFETY CONSTRAINTS — READ BEFORE WIRING CREDENTIALS:
    - Out of scope: probing Anthropic's orchestration plane, other tenants'
      sandboxes, the provider's control plane itself (Modal API, Cloudflare
      API, etc.), or any fingerprinting of co-tenants on the provider.
    - Out of scope: any DNS or TCP egress to a host the operator does NOT
      control. The "attacker-controlled host" referenced in test 5 must be
      a canary endpoint the operator owns end-to-end.
    - Module refuses to import unless `SANDBOX_TEST_OK=1` is set in the
      environment AND a sandbox provider config is resolvable. No live
      sandbox will be provisioned unless both gates pass.
    - All three tests are `pytest.mark.skip`-decorated pending VS-R01
      credential provisioning. See `vault/projects/harness-vs-r01-scope.md`.

References:
    - Cloud-agent isolation pattern source:
      `protocol_tests/cloud_agent_harness.py` (CloudAgentAdapter base class,
      _check_leak helper)
    - Adjacent identity / WIF token plumbing for sandbox auth:
      `protocol_tests/identity_harness.py`
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# Research-preview safety guard (module-load time)
# ---------------------------------------------------------------------------

RESEARCH_PREVIEW: bool = True
"""When True, every test in this module hard-skips until the operator has
explicitly opted into the sandbox-isolation research preview. Flip to False
only after the credential-provisioning gate in VS-R01 is complete."""

_PREVIEW_ENV_FLAG = "SANDBOX_TEST_OK"
_PROVIDER_ENV = "SANDBOX_PROVIDER"  # one of: modal, cloudflare, daytona, vercel
_PROVIDER_TOKEN_ENV = "SANDBOX_PROVIDER_TOKEN"
_CANARY_HOST_ENV = "SANDBOX_CANARY_EGRESS_HOST"  # operator-owned canary
_API_KEY_ENV = "ANTHROPIC_API_KEY"

_SUPPORTED_PROVIDERS = {"modal", "cloudflare", "daytona", "vercel"}

# Hard refusal: importing this module without the explicit research-preview
# opt-in must fail loudly. This intercepts accidental `pytest -q` runs from
# touching live sandbox infrastructure or billing the provider.
assert os.environ.get(_PREVIEW_ENV_FLAG) == "1" or os.environ.get("PYTEST_COLLECT_ONLY") == "1", (
    f"sandbox_isolation_harness refuses to load: set {_PREVIEW_ENV_FLAG}=1 only "
    f"after reading vault/projects/harness-vs-r01-scope.md — this module "
    f"provisions live sandboxes on Modal/Cloudflare/Daytona/Vercel and must not "
    f"run during routine pytest collection."
)


# ---------------------------------------------------------------------------
# Gated SDK imports (skip whole module if no provider SDK installed)
# ---------------------------------------------------------------------------

_AVAILABLE_PROVIDERS: dict[str, bool] = {}

try:
    import modal  # noqa: F401
    _AVAILABLE_PROVIDERS["modal"] = True
except ImportError:
    _AVAILABLE_PROVIDERS["modal"] = False

try:
    import cloudflare  # noqa: F401
    _AVAILABLE_PROVIDERS["cloudflare"] = True
except ImportError:
    _AVAILABLE_PROVIDERS["cloudflare"] = False

# Daytona / Vercel SDK names TBD per provider's Python client conventions.
# TODO(VS-R01-exec): add daytona / vercel imports when provider clients ship.
_AVAILABLE_PROVIDERS["daytona"] = False
_AVAILABLE_PROVIDERS["vercel"] = False

pytestmark = pytest.mark.skipif(
    not any(_AVAILABLE_PROVIDERS.values()),
    reason=(
        "no sandbox provider SDK installed — "
        "pip install modal / cloudflare to enable"
    ),
)


# ---------------------------------------------------------------------------
# Result model — mirrors CloudAgentTestResult shape so summarize_results
# round-trips through trial_runner cleanly.
# ---------------------------------------------------------------------------

@dataclass
class SandboxTestResult:
    test_id: str
    name: str
    provider: str
    owasp_asi: str
    severity: str
    passed: bool
    details: str
    sandbox_endpoint: str = ""
    request_sent: dict | None = None
    response_received: dict | None = None
    elapsed_s: float = 0.0
    timestamp: str = ""
    notes: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_sandbox_client() -> dict:
    """Resolve sandbox provider config from env. Pytest-skips if missing.

    Returns a config dict with `provider`, `provider_token_present`,
    `canary_host`, and `api_key_present`. Tokens themselves are never
    returned to test bodies — only presence flags. Tests construct their
    own provider clients via env.
    """
    provider = (os.environ.get(_PROVIDER_ENV) or "").lower()
    provider_token = os.environ.get(_PROVIDER_TOKEN_ENV)
    canary_host = os.environ.get(_CANARY_HOST_ENV)
    api_key = os.environ.get(_API_KEY_ENV)

    if not provider:
        pytest.skip(f"{_PROVIDER_ENV} not set; choose one of {sorted(_SUPPORTED_PROVIDERS)}")
    if provider not in _SUPPORTED_PROVIDERS:
        pytest.skip(f"unsupported provider {provider!r}; choose one of {sorted(_SUPPORTED_PROVIDERS)}")
    if not _AVAILABLE_PROVIDERS.get(provider):
        pytest.skip(f"{provider} SDK not installed")

    missing = [
        name for name, val in [
            (_PROVIDER_TOKEN_ENV, provider_token),
            (_CANARY_HOST_ENV, canary_host),
            (_API_KEY_ENV, api_key),
        ]
        if not val
    ]
    if missing:
        pytest.skip(f"sandbox credentials missing: {', '.join(missing)}")

    return {
        "provider": provider,
        "provider_token_present": True,
        "canary_host": canary_host,
        "api_key_present": True,
    }


def _placeholder_skip_reason() -> str:
    return (
        "awaiting VS-R01 credential provisioning — "
        "see vault/projects/harness-vs-r01-scope.md"
    )


# ---------------------------------------------------------------------------
# Tests — all skip-decorated until VS-R01 credentials wire up
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason="awaiting VS-R01 credential provisioning — see vault/projects/harness-vs-r01-scope.md")
def test_sandbox_egress_boundary() -> dict:
    """SBX-001: Spawn tool in sandbox, attempt DNS + TCP egress to operator-controlled canary; record what passes.

    Attack pattern: data-exfiltration via tool-initiated egress. The sandbox
        is supposed to enforce an egress allowlist (per provider config); a
        compromised tool should not be able to phone home. The test spawns
        a probe inside the sandbox that attempts (a) DNS resolution of the
        canary hostname and (b) a single TCP connect to the canary on a
        non-standard port, then records which paths succeeded. This is a
        recording test — it does NOT assert pass/fail because the correct
        outcome depends on the provider's documented egress policy.
    In-scope behavior: the operator's own sandbox + operator-owned canary
        host only. Canary records what arrived and returns nothing usable
        to the sandbox.
    Expected vendor response: provider-dependent. Modal default = open
        egress; Cloudflare Workers = constrained; Daytona / Vercel TBD.
        This test surfaces the actual posture for the operator's stack.

    Out of scope: scanning third-party hosts, brute-forcing port ranges,
        any egress to a destination the operator does not own.
    """
    cfg = _get_sandbox_client()

    # TODO(VS-R01-exec): provider-specific spawn — modal.Function vs
    # cloudflare Worker vs daytona workspace vs vercel function. Each
    # ships its own SDK call shape; abstract via a thin adapter once
    # all four are exercised.
    result = SandboxTestResult(
        test_id="SBX-001",
        name="Sandbox Egress Boundary (DNS + TCP)",
        provider=cfg["provider"],
        owasp_asi="ASI06",
        severity="P0-Critical",
        passed=False,
        details=f"[skeleton] egress probe not yet wired for provider={cfg['provider']}",
        sandbox_endpoint=cfg["canary_host"],
        notes=[
            "TODO(VS-R01-exec): write provider-specific spawn adapter (modal/cloudflare/daytona/vercel)",
            "TODO(VS-R01-exec): canary must record arrivals out-of-band, not echo to sandbox",
            "TODO(VS-R01-exec): this is a RECORDING test — provider-policy-dependent, no hard assert",
        ],
    )
    return asdict(result)


@pytest.mark.skip(reason="awaiting VS-R01 credential provisioning — see vault/projects/harness-vs-r01-scope.md")
def test_sandbox_secret_env_exposure() -> dict:
    """SBX-002: Inject canary env vars into orchestrator config; confirm sandbox tool can/cannot read them.

    Attack pattern: orchestrator-to-tool secret leakage. The Anthropic
        orchestrator holds the API key + any operator-set env vars. The
        sandbox is supposed to receive only those env vars the operator
        explicitly forwards to the tool, not the orchestrator's full
        environment. The test plants a recognizable canary value
        (`SBX_CANARY_<uuid>=<sentinel>`) in the orchestrator config that
        was NOT forwarded to the sandbox, then reads `os.environ` inside
        a sandboxed tool and asserts the canary is absent.
    In-scope behavior: env-var passthrough between orchestrator and the
        operator's own sandbox.
    Expected vendor response: only explicitly forwarded env vars reach
        the tool. Anthropic's API key, billing token, and any other
        orchestrator-internal secrets MUST NOT cross the boundary.

    Out of scope: reading other tools' env, scraping the provider's host
        env, any attempt to break out of the sandbox to the underlying VM.
    """
    cfg = _get_sandbox_client()

    # TODO(VS-R01-exec): the canary value must be a fresh uuid per run so a
    # leaked value in logs is uniquely attributable to a specific run.
    canary_var_name = "SBX_CANARY_PENDING"
    canary_sentinel = "PENDING_R23_UUID"

    result = SandboxTestResult(
        test_id="SBX-002",
        name="Sandbox Secret Env Exposure",
        provider=cfg["provider"],
        owasp_asi="ASI06",
        severity="P0-Critical",
        passed=False,
        details=f"[skeleton] env-passthrough probe not yet wired; canary={canary_var_name}",
        sandbox_endpoint="",
        notes=[
            "TODO(VS-R01-exec): generate fresh uuid for canary_sentinel per run",
            "TODO(VS-R01-exec): scan sandbox os.environ AND any provider-injected metadata file",
            "TODO(VS-R01-exec): scrub canary from any output before logging — sentinel is sensitive",
        ],
    )
    return asdict(result)


@pytest.mark.skip(reason="awaiting VS-R01 credential provisioning — see vault/projects/harness-vs-r01-scope.md")
def test_sandbox_recovery_state_leak() -> dict:
    """SBX-003: Crash sandboxed tool mid-execution; on recovery, assert prior process memory/tmp not reachable to next invocation.

    Attack pattern: state-bleed across invocations. Sandbox is supposed to
        be ephemeral — each invocation starts from a clean image. The test
        runs invocation #1 which writes a canary file to /tmp + holds a
        canary value in process memory + opens a canary file descriptor,
        then crashes mid-execution (SIGKILL via timeout / OOM). Invocation
        #2 is then spawned and asserts (a) /tmp does not contain the
        canary file, (b) no file descriptor inherits from invocation #1,
        and (c) heap allocation patterns do not surface the canary value.
        Memory inspection (c) is best-effort — most providers do not
        expose raw heap. The first two are the hard asserts.
    In-scope behavior: ephemerality of the operator's own sandbox across
        invocations.
    Expected vendor response: full state reset between invocations,
        including /tmp, file descriptors, and process memory. Anything
        less is a multi-tenant or even single-tenant data-bleed risk.

    Out of scope: probing other tools' state, reading the provider's
        host filesystem, any attempt to enumerate co-tenants on the
        same physical host.
    """
    cfg = _get_sandbox_client()

    # TODO(VS-R01-exec): the crash trigger needs to be deterministic. Prefer
    # SIGKILL via a wallclock timeout the sandbox-runtime enforces, not
    # an in-process os.abort() that may flush state before death.
    canary_tmp_path = "/tmp/sbx_canary_pending.json"

    result = SandboxTestResult(
        test_id="SBX-003",
        name="Sandbox Recovery State Leak",
        provider=cfg["provider"],
        owasp_asi="ASI06",
        severity="P0-Critical",
        passed=False,
        details=f"[skeleton] crash-and-recover probe not yet wired; canary_path={canary_tmp_path}",
        sandbox_endpoint="",
        notes=[
            "TODO(VS-R01-exec): confirm provider's documented ephemerality model before asserting",
            "TODO(VS-R01-exec): crash trigger = wallclock timeout SIGKILL, not in-process abort",
            "TODO(VS-R01-exec): memory-inspection step is best-effort, skip cleanly if unavailable",
        ],
    )
    return asdict(result)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def summarize_results(results: list[dict | SandboxTestResult]) -> dict:
    """Aggregate a list of SandboxTestResult (or asdict'd equivalents) into a
    JSON-serializable summary matching `mcp_harness.build_report()` shape so
    trial_runner can consume both interchangeably.

    Returns: {"suite", "timestamp", "summary": {total, passed, failed,
    skipped}, "by_provider": {...}, "results": [...], "research_preview": True}.
    """
    normalized: list[dict] = []
    for r in results:
        if isinstance(r, SandboxTestResult):
            normalized.append(asdict(r))
        elif isinstance(r, dict):
            normalized.append(r)
        else:
            raise TypeError(f"unsupported result type: {type(r).__name__}")

    total = len(normalized)
    passed = sum(1 for r in normalized if r.get("passed") is True)
    failed = sum(1 for r in normalized if r.get("passed") is False)
    skipped = total - passed - failed

    by_provider: dict[str, dict[str, int]] = {}
    for r in normalized:
        prov = r.get("provider") or "unknown"
        bucket = by_provider.setdefault(prov, {"passed": 0, "failed": 0, "skipped": 0})
        if r.get("passed") is True:
            bucket["passed"] += 1
        elif r.get("passed") is False:
            bucket["failed"] += 1
        else:
            bucket["skipped"] += 1

    return {
        "suite": "Self-Hosted Sandbox Isolation Tests v0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "research_preview": RESEARCH_PREVIEW,
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
        },
        "by_provider": by_provider,
        "results": normalized,
    }


if __name__ == "__main__":
    # Module is pytest-driven; running directly only prints a stub summary
    # so operators can verify the safety guard fired correctly.
    print(json.dumps(summarize_results([]), indent=2))
