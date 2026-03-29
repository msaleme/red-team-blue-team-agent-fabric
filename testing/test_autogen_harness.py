"""Unit tests for AutoGen harness module.

Validates test ID format, result structure, and category filtering.
"""

import pytest
from unittest.mock import patch
from protocol_tests.autogen_harness import AutoGenHarness, ALL_CATEGORIES


def _mock_post(*args, **kwargs):
    """Mock HTTP POST returning benign response."""
    return {"response": "I can help with that. 2+2 = 4.", "status": 200}


class TestAutoGenHarness:
    """Tests for the AutoGen security harness."""

    @patch("protocol_tests.autogen_harness.http_post", side_effect=_mock_post)
    def test_all_categories_run(self, mock_http):
        harness = AutoGenHarness("http://localhost:8000")
        results = harness.run_all()
        assert len(results) == 10, f"Expected 10 tests, got {len(results)}"

    @patch("protocol_tests.autogen_harness.http_post", side_effect=_mock_post)
    def test_speaker_selection_only(self, mock_http):
        harness = AutoGenHarness(
            "http://localhost:8000", categories={"speaker_selection"}
        )
        results = harness.run_all()
        assert all(r.test_id.startswith("AG-SP-") for r in results)
        assert len(results) == 3

    @patch("protocol_tests.autogen_harness.http_post", side_effect=_mock_post)
    def test_nested_escape_only(self, mock_http):
        harness = AutoGenHarness(
            "http://localhost:8000", categories={"nested_escape"}
        )
        results = harness.run_all()
        assert all(r.test_id.startswith("AG-NE-") for r in results)
        assert len(results) == 3

    @patch("protocol_tests.autogen_harness.http_post", side_effect=_mock_post)
    def test_message_spoofing_only(self, mock_http):
        harness = AutoGenHarness(
            "http://localhost:8000", categories={"message_spoofing"}
        )
        results = harness.run_all()
        assert all(r.test_id.startswith("AG-MS-") for r in results)
        assert len(results) == 4

    @patch("protocol_tests.autogen_harness.http_post", side_effect=_mock_post)
    def test_result_structure(self, mock_http):
        harness = AutoGenHarness("http://localhost:8000")
        results = harness.run_all()
        for r in results:
            assert r.test_id, "test_id must be set"
            assert r.name, "name must be set"
            assert r.attack_category in ALL_CATEGORIES
            assert r.owasp_asi.startswith("ASI")
            assert r.severity.startswith("P")
            assert r.endpoint.startswith("http")
            assert r.request_sent is not None, f"{r.test_id} missing request_sent"
            assert r.timestamp, f"{r.test_id} missing timestamp"

    @patch("protocol_tests.autogen_harness.http_post", side_effect=_mock_post)
    def test_ids_unique(self, mock_http):
        harness = AutoGenHarness("http://localhost:8000")
        results = harness.run_all()
        ids = [r.test_id for r in results]
        assert len(ids) == len(set(ids)), f"Duplicate test IDs: {ids}"

    @patch("protocol_tests.autogen_harness.http_post", side_effect=_mock_post)
    def test_benign_responses_pass(self, mock_http):
        """All tests should PASS when the server returns a benign response."""
        harness = AutoGenHarness("http://localhost:8000")
        results = harness.run_all()
        for r in results:
            assert r.passed, f"{r.test_id} should pass with benign response, got: {r.details}"
