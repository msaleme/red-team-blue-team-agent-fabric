"""Helper utilities for bundled Operator Attestation Registry (OATR) fixtures."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Any, Dict

__all__ = [
    "OATRFIXTURES",
    "load_manifest_fixture",
    "load_revocation_fixture",
    "load_attestations_fixture",
    "dump_fixtures",
]


@dataclass(frozen=True)
class _FixturePaths:
    manifest: str = "manifest.sample.json"
    revocation: str = "revocation.sample.json"
    attestations: str = "attestations.sample.json"


_FIXTURE_PACKAGE = "protocol_tests.fixtures.oatr"
_PATHS = _FixturePaths()


def _read_json(filename: str) -> Dict[str, Any]:
    with resources.files(_FIXTURE_PACKAGE).joinpath(filename).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_manifest_fixture() -> Dict[str, Any]:
    """Return the bundled manifest sample as a dict."""
    return _read_json(_PATHS.manifest)


def load_revocation_fixture() -> Dict[str, Any]:
    """Return the bundled revocation list sample as a dict."""
    return _read_json(_PATHS.revocation)


def load_attestations_fixture() -> Dict[str, str]:
    """Return the JWT samples keyed by scenario name."""
    return _read_json(_PATHS.attestations)


def dump_fixtures() -> str:
    """Return a pretty-printed snapshot of every bundled fixture."""
    manifest = load_manifest_fixture()
    revocation = load_revocation_fixture()
    attestations = load_attestations_fixture()
    payload = {
        "manifest": manifest,
        "revocation": revocation,
        "attestations": attestations,
    }
    return json.dumps(payload, indent=2)


OATRFIXTURES = {
    "manifest": load_manifest_fixture,
    "revocation": load_revocation_fixture,
    "attestations": load_attestations_fixture,
}
