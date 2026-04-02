#!/usr/bin/env python3
"""Tests for OATR v1.2.0 fixtures: suspended_issuer, grace period enforcement.

Validates the 3 new test tokens (X4-028 through X4-030) added for
@open-agent-trust/registry v1.2.0, which introduced:
  - suspended_issuer: distinct from revoked_issuer (temporary vs permanent)
  - grace_period_expired: deprecated key past 90-day grace window

All tokens are real Ed25519-signed JWTs verified against the OATR SDK.
Tests are offline-only (no network calls). Uses the now/verification_time
parameter for deterministic time-dependent assertions.

Reference: https://github.com/FransDevelopment/open-agent-trust-registry
SDK: https://www.npmjs.com/package/@open-agent-trust/registry (v1.2.0)
"""
from __future__ import annotations

import base64
import json
import os
import struct
import unittest
from datetime import datetime, timezone
from pathlib import Path

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "oatr_test_tokens.json"


def _load_fixtures():
    with open(FIXTURES_PATH) as f:
        return json.load(f)


def _decode_jwt_parts(jwt_str: str) -> tuple[dict, dict, bytes]:
    """Decode a JWT into (header, payload, signature_bytes) without verification."""
    parts = jwt_str.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")

    def _b64url_decode(s: str) -> bytes:
        s += "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)

    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    signature = _b64url_decode(parts[2])
    return header, payload, signature


class TestOATRFixtureIntegrity(unittest.TestCase):
    """Validate fixture file structure and token format."""

    @classmethod
    def setUpClass(cls):
        cls.fixtures = _load_fixtures()

    def test_fixture_file_loads(self):
        """Fixture file is valid JSON with required top-level keys."""
        required = {"tokens", "manifest", "revocations", "test_audience",
                     "verification_time", "oatr_sdk_version"}
        self.assertTrue(required.issubset(set(self.fixtures.keys())))

    def test_all_10_tokens_present(self):
        """All 10 tokens (X4-021 through X4-030) are present."""
        expected_tokens = {
            "valid", "expired", "wrong_audience", "forged_unknown_issuer",
            "tampered_signature", "revoked_issuer", "unknown_kid",
            "suspended_issuer", "deprecated_within_grace", "deprecated_past_grace",
        }
        self.assertEqual(set(self.fixtures["tokens"].keys()), expected_tokens)

    def test_each_token_has_expected_field(self):
        """Every token entry has a jwt string and expected dict."""
        for name, token in self.fixtures["tokens"].items():
            with self.subTest(token=name):
                self.assertIn("jwt", token, f"{name} missing jwt")
                self.assertIn("expected", token, f"{name} missing expected")
                self.assertIsInstance(token["jwt"], str)
                self.assertIsInstance(token["expected"], dict)

    def test_sdk_version_is_120(self):
        """Fixtures declare OATR SDK v1.2.0."""
        self.assertEqual(self.fixtures["oatr_sdk_version"], "1.2.0")


class TestOATRV120SuspendedIssuer(unittest.TestCase):
    """X4-028: Suspended issuer — temporary, reversible status."""

    @classmethod
    def setUpClass(cls):
        cls.fixtures = _load_fixtures()
        cls.token = cls.fixtures["tokens"]["suspended_issuer"]
        cls.header, cls.payload, cls.sig = _decode_jwt_parts(cls.token["jwt"])
        cls.manifest = cls.fixtures["manifest"]

    def test_x4_028_expected_result(self):
        """X4-028: suspended_issuer token expects valid=false, reason=suspended_issuer."""
        self.assertFalse(self.token["expected"]["valid"])
        self.assertEqual(self.token["expected"]["reason"], "suspended_issuer")

    def test_x4_028_jwt_header_format(self):
        """X4-028: JWT has correct EdDSA header with agent-attestation+jwt type."""
        self.assertEqual(self.header["alg"], "EdDSA")
        self.assertEqual(self.header["typ"], "agent-attestation+jwt")
        self.assertEqual(self.header["iss"], "suspended-runtime")
        self.assertEqual(self.header["kid"], "suspended-runtime-2026-03")

    def test_x4_028_issuer_in_manifest_as_suspended(self):
        """X4-028: Issuer exists in manifest with status=suspended."""
        issuer = next(
            (e for e in self.manifest["entries"]
             if e["issuer_id"] == "suspended-runtime"), None
        )
        self.assertIsNotNone(issuer, "suspended-runtime not in manifest")
        self.assertEqual(issuer["status"], "suspended")

    def test_x4_028_key_is_active(self):
        """X4-028: The key itself is active — rejection is at issuer level, not key."""
        issuer = next(
            e for e in self.manifest["entries"]
            if e["issuer_id"] == "suspended-runtime"
        )
        key = next(
            k for k in issuer["public_keys"]
            if k["kid"] == "suspended-runtime-2026-03"
        )
        self.assertEqual(key["status"], "active")

    def test_x4_028_distinct_from_revoked(self):
        """X4-028: suspended_issuer is distinct from revoked_issuer."""
        revoked_token = self.fixtures["tokens"]["revoked_issuer"]
        self.assertNotEqual(
            self.token["expected"]["reason"],
            revoked_token["expected"]["reason"],
        )

    def test_x4_028_payload_audience_correct(self):
        """X4-028: JWT audience matches test_audience."""
        self.assertEqual(
            self.payload["aud"],
            self.fixtures["test_audience"],
        )


class TestOATRV120DeprecatedWithinGrace(unittest.TestCase):
    """X4-029: Deprecated key within 90-day grace period — should pass."""

    @classmethod
    def setUpClass(cls):
        cls.fixtures = _load_fixtures()
        cls.token = cls.fixtures["tokens"]["deprecated_within_grace"]
        cls.header, cls.payload, cls.sig = _decode_jwt_parts(cls.token["jwt"])
        cls.manifest = cls.fixtures["manifest"]
        cls.ctx = cls.token["verification_context"]

    def test_x4_029_expected_result(self):
        """X4-029: deprecated_within_grace expects valid=true."""
        self.assertTrue(self.token["expected"]["valid"])

    def test_x4_029_jwt_header_format(self):
        """X4-029: JWT has correct header for deprecated-runtime issuer."""
        self.assertEqual(self.header["alg"], "EdDSA")
        self.assertEqual(self.header["iss"], "deprecated-runtime")
        self.assertEqual(self.header["kid"], "deprecated-runtime-2026-03")

    def test_x4_029_key_is_deprecated(self):
        """X4-029: Key status in manifest is deprecated."""
        issuer = next(
            e for e in self.manifest["entries"]
            if e["issuer_id"] == "deprecated-runtime"
        )
        key = next(
            k for k in issuer["public_keys"]
            if k["kid"] == "deprecated-runtime-2026-03"
        )
        self.assertEqual(key["status"], "deprecated")

    def test_x4_029_within_grace_period(self):
        """X4-029: Days since deprecation < 90-day grace period."""
        self.assertLess(self.ctx["days_since_deprecation"], self.ctx["grace_period_days"])

    def test_x4_029_verification_context_present(self):
        """X4-029: Token includes verification_context for deterministic replay."""
        self.assertIn("now", self.ctx)
        self.assertIn("deprecated_at", self.ctx)
        self.assertIn("days_since_deprecation", self.ctx)
        self.assertEqual(self.ctx["days_since_deprecation"], 30)

    def test_x4_029_issuer_is_active(self):
        """X4-029: Issuer status is active (only the key is deprecated)."""
        issuer = next(
            e for e in self.manifest["entries"]
            if e["issuer_id"] == "deprecated-runtime"
        )
        self.assertEqual(issuer["status"], "active")


class TestOATRV120DeprecatedPastGrace(unittest.TestCase):
    """X4-030: Deprecated key past 90-day grace period — should fail."""

    @classmethod
    def setUpClass(cls):
        cls.fixtures = _load_fixtures()
        cls.token = cls.fixtures["tokens"]["deprecated_past_grace"]
        cls.header, cls.payload, cls.sig = _decode_jwt_parts(cls.token["jwt"])
        cls.manifest = cls.fixtures["manifest"]
        cls.ctx = cls.token["verification_context"]

    def test_x4_030_expected_result(self):
        """X4-030: deprecated_past_grace expects valid=false, reason=grace_period_expired."""
        self.assertFalse(self.token["expected"]["valid"])
        self.assertEqual(self.token["expected"]["reason"], "grace_period_expired")

    def test_x4_030_jwt_header_format(self):
        """X4-030: JWT uses same issuer/kid as within-grace token."""
        self.assertEqual(self.header["iss"], "deprecated-runtime")
        self.assertEqual(self.header["kid"], "deprecated-runtime-2026-03")

    def test_x4_030_past_grace_period(self):
        """X4-030: Days since deprecation > 90-day grace period."""
        self.assertGreater(self.ctx["days_since_deprecation"], self.ctx["grace_period_days"])

    def test_x4_030_verification_context_present(self):
        """X4-030: Token includes verification_context for deterministic replay."""
        self.assertIn("now", self.ctx)
        self.assertIn("deprecated_at", self.ctx)
        self.assertEqual(self.ctx["days_since_deprecation"], 120)

    def test_x4_030_distinct_from_revoked_key(self):
        """X4-030: grace_period_expired is distinct from revoked_key."""
        self.assertNotEqual(
            self.token["expected"]["reason"], "revoked_key",
            "grace_period_expired must be a distinct reason code"
        )

    def test_x4_030_same_key_as_within_grace(self):
        """X4-030: Uses the same public key as the within-grace token."""
        within = self.fixtures["tokens"]["deprecated_within_grace"]
        within_header, _, _ = _decode_jwt_parts(within["jwt"])
        self.assertEqual(self.header["kid"], within_header["kid"])
        self.assertEqual(self.header["iss"], within_header["iss"])


class TestOATRV120VerificationCodes(unittest.TestCase):
    """Validate the complete verification code table from SDK v1.2.0."""

    @classmethod
    def setUpClass(cls):
        cls.fixtures = _load_fixtures()
        cls.codes = cls.fixtures["verification_codes"]["codes"]

    def test_v120_new_codes_present(self):
        """SDK v1.2.0 added suspended_issuer and grace_period_expired."""
        self.assertIn("suspended_issuer", self.codes)
        self.assertIn("grace_period_expired", self.codes)

    def test_all_10_reason_codes_documented(self):
        """All 10 OATR verification reason codes are documented."""
        expected = {
            "unknown_issuer", "suspended_issuer", "revoked_issuer",
            "unknown_key", "revoked_key", "grace_period_expired",
            "expired_attestation", "invalid_signature",
            "audience_mismatch", "nonce_mismatch",
        }
        self.assertEqual(set(self.codes.keys()), expected)

    def test_every_token_reason_is_valid_code(self):
        """Every token's expected reason is a recognized verification code."""
        for name, token in self.fixtures["tokens"].items():
            reason = token["expected"].get("reason")
            if reason is not None:
                with self.subTest(token=name):
                    self.assertIn(reason, self.codes,
                                  f"{name} uses unknown reason: {reason}")


class TestOATRManifestFixture(unittest.TestCase):
    """Validate the mock manifest covers all test scenarios."""

    @classmethod
    def setUpClass(cls):
        cls.fixtures = _load_fixtures()
        cls.manifest = cls.fixtures["manifest"]

    def test_manifest_has_4_issuers(self):
        """Manifest has 4 issuers (test-harness, revoked, suspended, deprecated)."""
        self.assertEqual(len(self.manifest["entries"]), 4)
        self.assertEqual(self.manifest["total_issuers"], 4)

    def test_suspended_issuer_entry(self):
        """Suspended issuer has correct status in manifest."""
        issuer = next(
            (e for e in self.manifest["entries"]
             if e["issuer_id"] == "suspended-runtime"), None
        )
        self.assertIsNotNone(issuer)
        self.assertEqual(issuer["status"], "suspended")

    def test_deprecated_key_entry(self):
        """Deprecated key issuer has deprecated key status."""
        issuer = next(
            (e for e in self.manifest["entries"]
             if e["issuer_id"] == "deprecated-runtime"), None
        )
        self.assertIsNotNone(issuer)
        self.assertEqual(issuer["status"], "active")
        key = issuer["public_keys"][0]
        self.assertEqual(key["status"], "deprecated")

    def test_revocations_has_revoked_issuer(self):
        """Revocation list includes revoked-runtime."""
        revocations = self.fixtures["revocations"]
        revoked_ids = [r["issuer_id"] for r in revocations["revoked_issuers"]]
        self.assertIn("revoked-runtime", revoked_ids)


if __name__ == "__main__":
    unittest.main()
