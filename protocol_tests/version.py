"""Shared harness version utility.

Centralises the version lookup so it isn't duplicated across scripts.
"""
from __future__ import annotations

from pathlib import Path


def get_harness_version() -> str:
    """Read version from importlib.metadata or pyproject.toml fallback."""
    try:
        from importlib.metadata import version as pkg_version
        return pkg_version("agent-security-harness")
    except Exception:
        pass
    try:
        _toml = Path(__file__).resolve().parent.parent / "pyproject.toml"
        for line in _toml.read_text().splitlines():
            if line.strip().startswith("version"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return "unknown"
