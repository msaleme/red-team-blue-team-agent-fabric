"""The 2026-08-04 fabricated-infrastructure defect.

Commit 6b6a64c (2026-03-28) shipped three references to infrastructure this
project does not own and never did:

- ``https://registry.agentsecurity.dev/v1/attestation`` as the default publish target
- ``https://telemetry.agentsecurity.dev/v1/event`` as the default telemetry target
- ``trusted@synapseops.com`` as the data-protection contact in docs/PRIVACY.md

Every ``agent-security publish`` run without an override posted a signed
attestation, including the optional user-supplied contact email, to a third
party. Telemetry was opt-in and off by default, which bounded that half.

The fix is the *absence* of a default, not a corrected default. These tests guard
that absence, and guard the two hosts and the contact address from reappearing
anywhere in the shipped package.
"""

from __future__ import annotations

import importlib
import os
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Hosts and addresses that were never ours. Kept as fragments so this file does
# not itself become a source of the strings when grepped loosely.
FORBIDDEN = ("agentsecurity" + ".dev", "trusted@" + "synapseops.com")

PACKAGE_DIRS = ("protocol_tests", "mcp_server", "community_modules", "conformance")
DOC_FILES = ("docs/PRIVACY.md", "docs/attestation-registry.md", "README.md")


class TestNoDefaultRegistryEndpoint(unittest.TestCase):
    def setUp(self) -> None:
        self.env = patch.dict(os.environ, {}, clear=False)
        self.env.start()
        os.environ.pop("AGENT_SECURITY_REGISTRY_URL", None)
        self.reg = importlib.import_module("protocol_tests.attestation_registry")

    def tearDown(self) -> None:
        self.env.stop()

    def test_import_succeeds_without_configuration(self) -> None:
        """Importing must not require an endpoint; strip_sensitive_fields is offline."""
        importlib.reload(self.reg)
        cleaned = self.reg.strip_sensitive_fields({"target_url": "http://x", "ok": 1})
        self.assertNotIn("target_url", cleaned)
        self.assertEqual(cleaned["ok"], 1)

    def test_resolving_with_no_env_raises_rather_than_defaulting(self) -> None:
        with self.assertRaises(self.reg.RegistryNotConfigured) as ctx:
            self.reg.resolve_registry_endpoint()
        self.assertIn("AGENT_SECURITY_REGISTRY_URL", str(ctx.exception))

    def test_blank_env_is_treated_as_unset(self) -> None:
        for blank in ("", "   ", "\t"):
            with patch.dict(os.environ, {"AGENT_SECURITY_REGISTRY_URL": blank}):
                with self.assertRaises(self.reg.RegistryNotConfigured):
                    self.reg.resolve_registry_endpoint()

    def test_https_endpoint_is_accepted(self) -> None:
        with patch.dict(os.environ, {"AGENT_SECURITY_REGISTRY_URL": "https://r.example.com/v1"}):
            self.assertEqual(self.reg.resolve_registry_endpoint(), "https://r.example.com/v1")

    def test_plain_http_is_refused_except_on_loopback(self) -> None:
        with patch.dict(os.environ, {"AGENT_SECURITY_REGISTRY_URL": "http://r.example.com/v1"}):
            with self.assertRaises(ValueError):
                self.reg.resolve_registry_endpoint()
        with patch.dict(os.environ, {"AGENT_SECURITY_REGISTRY_URL": "http://localhost:9/v1"}):
            self.assertEqual(self.reg.resolve_registry_endpoint(), "http://localhost:9/v1")


class TestNoDefaultTelemetryEndpoint(unittest.TestCase):
    def setUp(self) -> None:
        os.environ.pop("AGENT_SECURITY_TELEMETRY_URL", None)
        self.tel = importlib.import_module("protocol_tests.telemetry")
        importlib.reload(self.tel)

    def test_no_endpoint_configured_by_default(self) -> None:
        self.assertEqual(self.tel.TELEMETRY_ENDPOINT, "")

    def test_disabled_when_no_endpoint_even_if_opted_in(self) -> None:
        """An opt-in is consent to a destination the operator chose, not to any host."""
        with patch.dict(os.environ, {"AGENT_SECURITY_TELEMETRY": "on"}):
            importlib.reload(self.tel)
            self.assertTrue(self.tel._is_disabled())

    def test_send_is_a_noop_with_no_endpoint(self) -> None:
        with patch.dict(os.environ, {"AGENT_SECURITY_TELEMETRY": "on"}):
            importlib.reload(self.tel)
            with patch.object(self.tel, "_post") as post:
                self.tel.send_telemetry_event(module="mcp", tests=1, passed=1, failed=0)
            post.assert_not_called()

    def test_opt_in_plus_endpoint_is_the_only_enabled_path(self) -> None:
        with patch.dict(
            os.environ,
            {"AGENT_SECURITY_TELEMETRY": "on", "AGENT_SECURITY_TELEMETRY_URL": "https://t.example.com/v1"},
        ):
            importlib.reload(self.tel)
            self.assertFalse(self.tel._is_disabled())


class TestForbiddenHostsAreGone(unittest.TestCase):
    """No shipped source or user-facing doc may reference the fabricated hosts."""

    def _scan(self, paths) -> list[str]:
        hits = []
        for path in paths:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                # Prose explaining what happened is allowed: a Python comment or a
                # Markdown blockquote. What is forbidden is a usable reference.
                if stripped.startswith("#") or stripped.startswith(">"):
                    continue
                for bad in FORBIDDEN:
                    if bad in line:
                        hits.append(f"{path.relative_to(ROOT)}:{lineno}: {stripped[:90]}")
        return hits

    def test_no_forbidden_host_in_package_source(self) -> None:
        files = [p for d in PACKAGE_DIRS for p in (ROOT / d).rglob("*.py") if "__pycache__" not in str(p)]
        self.assertTrue(files, "no package sources found to scan")
        self.assertEqual(self._scan(files), [], "fabricated host reintroduced in package source")

    def test_no_forbidden_contact_in_user_facing_docs(self) -> None:
        files = [ROOT / f for f in DOC_FILES if (ROOT / f).exists()]
        self.assertTrue(files, "no docs found to scan")
        self.assertEqual(self._scan(files), [], "fabricated contact or host reintroduced in docs")


class TestBadgeDoesNotClaimIndependence(unittest.TestCase):
    """A self-run harness result is I0. A badge must not say 'Verified by'."""

    def test_badge_label_says_tested_with(self) -> None:
        src = (ROOT / "protocol_tests" / "attestation_registry.py").read_text()
        self.assertIn("Tested with Agent Security Harness", src)
        badge_claims = re.findall(r'Verified by Agent Security Harness', src)
        self.assertEqual(badge_claims, [], "badge still claims independent verification")


if __name__ == "__main__":
    unittest.main()
