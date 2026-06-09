"""MCP Supply-Chain / Framework-Layer Pre-Flight Security Tests (v1.0).

Closes harness issue #206. The protocol suite (`mcp_harness.py`, MCP-001..018)
exercises the JSON-RPC wire surface. It does NOT observe the binary-resolution
and package-install path that runs *before* the first JSON-RPC byte is exchanged.

An operator who allowlists `npx`/`uvx` has pinned the launcher *name*, not what
that launcher executes. A malicious `postinstall`, a `$PATH`-shadowed shim, or a
dependency-confusion hit all fire before the protocol harness can see a request.

This module adds a distinct framework-layer family (`MCP-F-*`) of STATIC,
pre-flight checks. They complement — never replace — the protocol suite.

    MCP-F-001  Binary resolution     — resolve what actually executes (shadowing)
    MCP-F-002  Install-script audit  — flag network/fs-mutating install scripts
    MCP-F-003  Dependency-confusion  — public-registry resolvability (network-gated)
    MCP-F-004  Launcher pinning      — flag unpinned `npx -y pkg` / `uvx pkg`

Inputs are a launch command and/or an MCP client config (`mcpServers`), plus an
optional project root to walk `node_modules/.bin` and `.venv/bin`. No live MCP
server or transport is required.

Usage:
    # one launcher
    python -m protocol_tests.mcp_supplychain --command "npx -y some-mcp-server"

    # a real MCP client config (claude_desktop_config.json / mcp.json)
    python -m protocol_tests.mcp_supplychain --config mcp.json --project-root .

    # CI-safe smoke run
    python -m protocol_tests.mcp_supplychain --simulate
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
import time
import urllib.request
from dataclasses import asdict
from datetime import datetime, timezone

# Reuse the protocol suite's result + severity types so reports stay uniform.
from protocol_tests.mcp_harness import MCPTestResult, Severity

# ---------------------------------------------------------------------------
# Static-analysis patterns (no execution — these only read text)
# ---------------------------------------------------------------------------

# Install scripts that reach the network from inside a lifecycle hook.
INSTALL_SCRIPT_NETWORK_RE = re.compile(
    r"\b(curl|wget|nc|ncat|scp|ftp)\b"
    r"|https?://"
    r"|\bnode\s+-e\b|\bnode\s+--eval\b"
    r"|\bpython3?\s+-c\b"
    r"|\bfetch\(|\brequire\(['\"]https?['\"]\)|\bInvoke-WebRequest\b",
    re.IGNORECASE,
)

# Install scripts that mutate the filesystem outside the package dir.
INSTALL_SCRIPT_FS_RE = re.compile(
    r"\brm\s+-rf\b|\bchmod\b|\bchown\b|\bmv\s+/|\bcp\s+/|\bln\s+-s\b"
    r"|>\s*/(?:etc|usr|bin|root|home)|~/\.|/\.ssh|/\.aws",
    re.IGNORECASE,
)

# npm lifecycle hooks that run on install.
NPM_INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish")

# A launcher that resolves package names rather than a fixed binary.
PKG_LAUNCHERS = {"npx", "uvx", "pnpm", "yarn", "bunx", "pipx"}


# ---------------------------------------------------------------------------
# Command / config parsing
# ---------------------------------------------------------------------------

def parse_launch_command(command: str) -> dict:
    """Decompose an MCP launch command into structured fields.

    Returns: {raw, launcher, args, package, version_pin, auto_yes}
    `package` is the resolved package spec for a package-launcher (npx/uvx/...),
    else None. `version_pin` is the @version / ==version / SHA if present.
    """
    raw = command.strip()
    try:
        parts = shlex.split(raw)
    except ValueError:
        parts = raw.split()
    if not parts:
        return {"raw": raw, "launcher": None, "args": [], "package": None,
                "version_pin": None, "auto_yes": False}

    launcher = parts[0]
    args = parts[1:]
    launcher_base = os.path.basename(launcher)
    auto_yes = any(a in ("-y", "--yes") for a in args)

    package = None
    package_name = None
    version_pin = None
    if launcher_base in PKG_LAUNCHERS:
        # First non-flag argument is the package spec.
        for a in args:
            if a.startswith("-"):
                continue
            package = a
            break
        if package:
            # npm style: name@version ; ignore leading @scope/ in scoped names.
            scope_prefix = ""
            spec = package
            if spec.startswith("@"):
                scope_prefix, _, rest = spec.partition("/")
                spec = rest
            if "@" in spec:
                _, _, version_pin = spec.partition("@")
            # uv/pip style: name==version
            if version_pin is None and "==" in package:
                version_pin = package.split("==", 1)[1]
            # Bare package name (version + scope-suffix stripped). npm/pip install
            # under the bare name, so manifest/registry lookups MUST use this —
            # `evil@1.2.3` is not a node_modules directory.
            base = spec.split("@", 1)[0].split("==", 1)[0]
            package_name = f"{scope_prefix}/{base}" if scope_prefix else base

    return {
        "raw": raw,
        "launcher": launcher,
        "launcher_base": launcher_base,
        "args": args,
        "package": package,
        "package_name": package_name,
        "version_pin": version_pin or None,
        "auto_yes": auto_yes,
    }


def load_servers(command: str | None, config: str | None) -> list[dict]:
    """Build a list of parsed launch specs from --command and/or --config."""
    servers: list[dict] = []
    if command:
        spec = parse_launch_command(command)
        spec["server_name"] = "(--command)"
        servers.append(spec)
    if config:
        with open(config) as f:
            cfg = json.load(f)
        for name, entry in (cfg.get("mcpServers") or cfg.get("servers") or {}).items():
            cmd = entry.get("command", "")
            cmd_args = entry.get("args", []) or []
            full = " ".join([cmd, *cmd_args]).strip()
            spec = parse_launch_command(full)
            spec["server_name"] = name
            servers.append(spec)
    return servers


# ---------------------------------------------------------------------------
# Binary resolution (MCP-F-001)
# ---------------------------------------------------------------------------

def resolve_binary_candidates(name: str, project_root: str | None,
                              path_env: str | None) -> list[dict]:
    """Return every executable match for `name`, in invocation-precedence order.

    Project-local bin dirs (node_modules/.bin, .venv/bin, venv/bin) take
    precedence over $PATH, mirroring how npm/uv launchers actually resolve.
    Each candidate is tagged with its source and whether its directory is
    world-writable (a shadowing risk).
    """
    # An explicit path launcher (contains a separator, e.g. "/opt/x/server"
    # or "./server") is invoked literally — resolve THAT path, not a $PATH
    # search by basename, which would mischaracterize what actually runs.
    if os.sep in name or (os.altsep and os.altsep in name):
        target = name if os.path.isabs(name) else os.path.join(project_root or os.getcwd(), name)
        if os.path.isfile(target) or os.path.islink(target):
            directory = os.path.dirname(target)
            try:
                world_writable = bool(os.stat(directory).st_mode & 0o002)
            except OSError:
                world_writable = False
            return [{"path": target, "source": "explicit path",
                     "executable": os.access(target, os.X_OK),
                     "dir_world_writable": world_writable}]
        return []

    name = os.path.basename(name)
    search: list[tuple[str, str]] = []  # (directory, source-label)

    if project_root:
        for rel, label in (
            ("node_modules/.bin", "project node_modules/.bin"),
            (".venv/bin", "project .venv/bin"),
            ("venv/bin", "project venv/bin"),
        ):
            search.append((os.path.join(project_root, rel), label))

    for d in (path_env or os.environ.get("PATH", "")).split(os.pathsep):
        if d:
            search.append((d, "$PATH"))

    candidates: list[dict] = []
    for directory, source in search:
        cand = os.path.join(directory, name)
        if os.path.isfile(cand) or os.path.islink(cand):
            try:
                executable = os.access(cand, os.X_OK)
            except OSError:
                executable = False
            try:
                world_writable = bool(os.stat(directory).st_mode & 0o002)
            except OSError:
                world_writable = False
            candidates.append({
                "path": cand,
                "source": source,
                "executable": executable,
                "dir_world_writable": world_writable,
            })
    return candidates


# ---------------------------------------------------------------------------
# Install-script inspection (MCP-F-002)
# ---------------------------------------------------------------------------

def inspect_npm_install_scripts(package: str | None, project_root: str | None) -> dict:
    """Read an installed package's package.json lifecycle scripts (if present)."""
    if not package or not project_root:
        return {"found": False, "reason": "no package or project root"}
    pkg_dir = os.path.join(project_root, "node_modules", package)
    manifest = os.path.join(pkg_dir, "package.json")
    if not os.path.isfile(manifest):
        return {"found": False, "reason": f"not installed at {manifest}"}
    try:
        with open(manifest) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return {"found": False, "reason": f"unreadable manifest: {e}"}

    scripts = data.get("scripts", {}) or {}
    findings = []
    for hook in NPM_INSTALL_HOOKS:
        body = scripts.get(hook)
        if not body:
            continue
        entry = {"hook": hook, "script": body,
                 "network": bool(INSTALL_SCRIPT_NETWORK_RE.search(body)),
                 "fs_mutating": bool(INSTALL_SCRIPT_FS_RE.search(body))}
        findings.append(entry)
    return {"found": True, "manifest": manifest, "hooks": findings}


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

class MCPSupplyChainTests:
    """Framework-layer (MCP-F-*) static pre-flight checks for MCP servers."""

    def __init__(self, command: str | None = None, config: str | None = None,
                 project_root: str | None = None, path_env: str | None = None,
                 allow_network: bool = False, simulate: bool = False,
                 json_output: bool = False):
        self.command = command
        self.config = config
        self.project_root = project_root
        self.path_env = path_env
        self.allow_network = allow_network
        self.simulate = simulate
        self.json_output = json_output
        self.results: list[MCPTestResult] = []
        self.servers = [] if simulate else load_servers(command, config)

    def _record(self, r: MCPTestResult) -> None:
        self.results.append(r)

    def _simulated(self, test_id: str, name: str, category: str,
                   owasp: str, sev: str) -> MCPTestResult:
        return MCPTestResult(
            test_id=test_id, name=name, category=category, owasp_asi=owasp,
            severity=sev, passed=True,
            details="[simulate] static check compiled; no config inspected",
            mcp_method="N/A (static pre-flight)",
        )

    # -- MCP-F-001 -----------------------------------------------------------
    def test_mcp_f_001_binary_resolution(self) -> None:
        t0 = time.monotonic()
        if self.simulate:
            self._record(self._simulated(
                "MCP-F-001", "Launcher Binary Resolution",
                "framework_binary_resolution", "ASI06", Severity.HIGH.value))
            return
        flagged = []
        details_lines = []
        for s in self.servers:
            launcher = s.get("launcher")
            if not launcher:
                continue
            cands = resolve_binary_candidates(launcher, self.project_root, self.path_env)
            if not cands:
                details_lines.append(f"{s['server_name']}: '{launcher}' unresolved in search path")
                continue
            first = cands[0]
            # Shadowing: the first match sits in a world-writable or project-local
            # dir while a later $PATH match also exists for the same name.
            later_path = [c for c in cands[1:] if c["source"] == "$PATH"]
            risky_first = first["dir_world_writable"] or first["source"] != "$PATH"
            shadowing = len(cands) > 1 and risky_first and later_path
            if shadowing:
                flagged.append(s["server_name"])
                details_lines.append(
                    f"{s['server_name']}: '{launcher}' resolves to {first['path']} "
                    f"({first['source']}, world_writable={first['dir_world_writable']}) "
                    f"SHADOWING {later_path[0]['path']}")
            elif first["dir_world_writable"]:
                # Even without a second candidate, a world-writable binary dir is
                # tamperable — anyone can replace the binary before it runs.
                flagged.append(s["server_name"])
                details_lines.append(
                    f"{s['server_name']}: '{launcher}' -> {first['path']} "
                    f"({first['source']}) WORLD-WRITABLE DIR (tamperable)")
            else:
                details_lines.append(
                    f"{s['server_name']}: '{launcher}' -> {first['path']} ({first['source']})")
        passed = not flagged
        self._record(MCPTestResult(
            test_id="MCP-F-001", name="Launcher Binary Resolution",
            category="framework_binary_resolution", owasp_asi="ASI06",
            severity=Severity.HIGH.value, passed=passed,
            details=("; ".join(details_lines) or "no launchers to resolve")
                    + (f" | FLAGGED: {flagged}" if flagged else ""),
            mcp_method="N/A (static pre-flight)",
            elapsed_s=round(time.monotonic() - t0, 3)))

    # -- MCP-F-002 -----------------------------------------------------------
    def test_mcp_f_002_install_scripts(self) -> None:
        t0 = time.monotonic()
        if self.simulate:
            self._record(self._simulated(
                "MCP-F-002", "Install-Script Inspection",
                "framework_install_scripts", "ASI06", Severity.CRITICAL.value))
            return
        risky = []
        details_lines = []
        for s in self.servers:
            # Look up by BARE package name — npm installs `evil@1.2.3` under `evil`.
            info = inspect_npm_install_scripts(s.get("package_name"), self.project_root)
            if not info["found"]:
                details_lines.append(f"{s['server_name']}: not inspectable ({info['reason']})")
                continue
            for hook in info["hooks"]:
                tag = []
                if hook["network"]:
                    tag.append("NETWORK")
                if hook["fs_mutating"]:
                    tag.append("FS-MUTATING")
                marker = f"[{','.join(tag)}]" if tag else "[benign]"
                # Both network-callable AND filesystem-mutating install hooks are
                # findings — an install-time `rm -rf` or `~/.ssh` write is as much
                # a supply-chain risk as an exfil call.
                if hook["network"] or hook["fs_mutating"]:
                    risky.append(f"{s['server_name']}:{hook['hook']}{marker}")
                details_lines.append(
                    f"{s['server_name']}:{hook['hook']} {marker} -> {hook['script'][:80]}")
        passed = not risky
        self._record(MCPTestResult(
            test_id="MCP-F-002", name="Install-Script Inspection",
            category="framework_install_scripts", owasp_asi="ASI06",
            severity=Severity.CRITICAL.value, passed=passed,
            details=("; ".join(details_lines) or "no installed packages to inspect")
                    + (f" | RISKY INSTALL SCRIPTS: {risky}" if risky else ""),
            mcp_method="N/A (static pre-flight)",
            elapsed_s=round(time.monotonic() - t0, 3)))

    # -- MCP-F-003 (network-gated) ------------------------------------------
    def test_mcp_f_003_dependency_confusion(self) -> None:
        t0 = time.monotonic()
        if self.simulate:
            self._record(self._simulated(
                "MCP-F-003", "Dependency-Confusion Resolvability",
                "framework_dependency_confusion", "ASI06", Severity.HIGH.value))
            return
        if not self.allow_network:
            self._record(MCPTestResult(
                test_id="MCP-F-003", name="Dependency-Confusion Resolvability",
                category="framework_dependency_confusion", owasp_asi="ASI06",
                severity=Severity.HIGH.value, passed=True,
                details="skipped — network required (re-run with --allow-network)",
                mcp_method="N/A (static pre-flight)",
                elapsed_s=round(time.monotonic() - t0, 3)))
            return
        flagged = []
        details_lines = []
        for s in self.servers:
            name = s.get("package_name")
            if not name:
                continue
            internal_looking = bool(re.search(r"internal|corp|private|intra", name, re.I)) \
                or (not name.startswith("@") and name.count("-") >= 2)
            public = self._npm_public(name)
            details_lines.append(
                f"{s['server_name']}: {name} public_npm={public} internal_named={internal_looking}")
            if public and internal_looking:
                flagged.append(s["server_name"])
        passed = not flagged
        self._record(MCPTestResult(
            test_id="MCP-F-003", name="Dependency-Confusion Resolvability",
            category="framework_dependency_confusion", owasp_asi="ASI06",
            severity=Severity.HIGH.value, passed=passed,
            details=("; ".join(details_lines) or "no packages to check")
                    + (f" | INTERNAL-LOOKING NAMES ON PUBLIC REGISTRY: {flagged}" if flagged else ""),
            mcp_method="N/A (static pre-flight)",
            elapsed_s=round(time.monotonic() - t0, 3)))

    @staticmethod
    def _npm_public(package: str) -> bool:
        name = package.rsplit("@", 1)[0] if "@" in package[1:] else package
        url = "https://registry.npmjs.org/" + urllib.request.quote(name, safe="@/")
        try:
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False

    # -- MCP-F-004 -----------------------------------------------------------
    def test_mcp_f_004_pinning(self) -> None:
        t0 = time.monotonic()
        if self.simulate:
            self._record(self._simulated(
                "MCP-F-004", "Launcher Version Pinning",
                "framework_pinning", "ASI06", Severity.MEDIUM.value))
            return
        unpinned = []
        details_lines = []
        for s in self.servers:
            if not s.get("package"):
                continue  # direct-binary launchers have no package to pin
            if s.get("version_pin"):
                details_lines.append(
                    f"{s['server_name']}: {s['package']} pinned@{s['version_pin']}")
            else:
                unpinned.append(s["server_name"])
                yes = " (auto-confirm -y)" if s.get("auto_yes") else ""
                details_lines.append(
                    f"{s['server_name']}: {s['package']} UNPINNED{yes}")
        passed = not unpinned
        self._record(MCPTestResult(
            test_id="MCP-F-004", name="Launcher Version Pinning",
            category="framework_pinning", owasp_asi="ASI06",
            severity=Severity.MEDIUM.value, passed=passed,
            details=("; ".join(details_lines) or "no package launchers to check")
                    + (f" | UNPINNED: {unpinned}" if unpinned else ""),
            mcp_method="N/A (static pre-flight)",
            elapsed_s=round(time.monotonic() - t0, 3)))

    CATEGORIES = (
        "framework_binary_resolution", "framework_install_scripts",
        "framework_dependency_confusion", "framework_pinning",
    )

    # -- runner --------------------------------------------------------------
    def run_all(self, categories: list[str] | None = None) -> list[MCPTestResult]:
        tests = {
            "framework_binary_resolution": [self.test_mcp_f_001_binary_resolution],
            "framework_install_scripts": [self.test_mcp_f_002_install_scripts],
            "framework_dependency_confusion": [self.test_mcp_f_003_dependency_confusion],
            "framework_pinning": [self.test_mcp_f_004_pinning],
        }
        if categories:
            unknown = [c for c in categories if c not in tests]
            if unknown:
                # Fail loudly: a bad filter that silently runs zero checks would
                # read as "suite passed" to CI/operators.
                raise ValueError(
                    f"unknown categor{'y' if len(unknown) == 1 else 'ies'}: "
                    f"{unknown}; valid: {list(tests)}")
        selected = ({k: v for k, v in tests.items() if k in categories}
                    if categories else tests)
        for _cat, fns in selected.items():
            for fn in fns:
                try:
                    fn()
                except Exception as e:  # never let one check abort the suite
                    self._record(MCPTestResult(
                        test_id="MCP-F-ERR", name="framework check error",
                        category="error", owasp_asi="ASI06",
                        severity=Severity.LOW.value, passed=False,
                        details=f"{type(e).__name__}: {e}",
                        mcp_method="N/A (static pre-flight)"))
        return self.results


# ---------------------------------------------------------------------------
# Report + CLI
# ---------------------------------------------------------------------------

def build_report(results: list[MCPTestResult], error: str | None = None) -> dict:
    report = {
        "suite": "MCP Supply-Chain Pre-Flight Tests v1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed),
        },
        "results": [asdict(r) for r in results],
    }
    if error:
        report["error"] = error
    return report


def main() -> None:
    ap = argparse.ArgumentParser(
        description="MCP Supply-Chain / Framework-Layer Pre-Flight Security Tests (MCP-F-*)")
    ap.add_argument("--command", help="A single MCP server launch command, e.g. 'npx -y some-server'")
    ap.add_argument("--config", help="Path to an MCP client config JSON (mcpServers)")
    ap.add_argument("--project-root", help="Project root to walk node_modules/.bin and .venv/bin")
    ap.add_argument("--categories", help="Comma-separated category filter")
    ap.add_argument("--report", help="Output JSON report path")
    ap.add_argument("--json", action="store_true", dest="json_output",
                    help="Emit JSON to stdout (no human-readable text)")
    ap.add_argument("--simulate", action="store_true",
                    help="Compile checks without inspecting a config (CI smoke)")
    ap.add_argument("--allow-network", action="store_true",
                    help="Enable MCP-F-003 registry lookups (otherwise skipped)")
    args = ap.parse_args()

    json_output = args.json_output or os.environ.get("AGENT_SECURITY_JSON_OUTPUT") == "1"

    if not args.simulate and not args.command and not args.config:
        msg = "one of --command, --config, or --simulate is required"
        print(json.dumps({"error": msg}) if json_output else f"ERROR: {msg}",
              file=sys.stderr if not json_output else sys.stdout)
        sys.exit(1)

    suite = MCPSupplyChainTests(
        command=args.command, config=args.config, project_root=args.project_root,
        allow_network=args.allow_network, simulate=args.simulate,
        json_output=json_output)
    cats = [c.strip() for c in args.categories.split(",")] if args.categories else None
    try:
        results = suite.run_all(cats)
    except ValueError as e:
        print(json.dumps({"error": str(e)}) if json_output else f"ERROR: {e}",
              file=sys.stdout if json_output else sys.stderr)
        sys.exit(1)
    report = build_report(results)

    if args.report:
        with open(args.report, "w") as f:
            json.dump(report, f, indent=2, default=str)
        if not json_output:
            print(f"Report written to {args.report}")

    if json_output:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(f"\nMCP Supply-Chain Pre-Flight — {report['summary']['passed']}/"
              f"{report['summary']['total']} passed")
        for r in results:
            mark = "PASS" if r.passed else "FAIL"
            print(f"  [{mark}] {r.test_id} {r.name}: {r.details}")

    sys.exit(0 if all(r.passed for r in results) else 2)


if __name__ == "__main__":
    main()
