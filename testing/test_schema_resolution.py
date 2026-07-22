"""Fixture tests for fail-closed A2A/MCP schema-resolution policy.

The fixtures are protocol-neutral by design: Agent Cards and MCP tool/resource
schemas both carry JSON Schema documents.  They demonstrate the policy layer
without making network or filesystem acquisition part of a test run.
"""

from __future__ import annotations

import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import patch

from protocol_tests.schema_resolution import (
    RegisteredSchema,
    check_reference_policy,
    field_collisions,
    normalize_wire_fields,
    references_fail_closed,
    validator_differential,
)


class _CountingHandler(BaseHTTPRequestHandler):
    requests = 0

    def do_GET(self):  # noqa: N802 - stdlib handler API
        type(self).requests += 1
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args):
        pass


class TestSchemaResolutionPolicy(unittest.TestCase):
    def setUp(self):
        _CountingHandler.requests = 0
        self.server = HTTPServer(("127.0.0.1", 0), _CountingHandler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}/schema.json"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_unregistered_http_reference_fails_closed_without_contact(self):
        doc = {"$ref": self.base_url}
        result = check_reference_policy(doc)
        self.assertFalse(result[0].allowed)
        self.assertEqual(result[0].reason, "unregistered external reference")
        self.assertEqual(_CountingHandler.requests, 0)

    def test_unregistered_file_reference_fails_closed_without_open(self):
        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / "sentinel.json"
            sentinel.write_text('{"opened": true}', encoding="utf-8")
            with patch("builtins.open", side_effect=AssertionError("must not open external ref")):
                result = check_reference_policy({"$ref": sentinel.as_uri()})
        self.assertFalse(result[0].allowed)
        self.assertEqual(result[0].reason, "unregistered external reference")

    def test_local_defs_reference_is_allowed(self):
        doc = {"$defs": {"value": {"type": "string"}}, "$ref": "#/$defs/value"}
        self.assertTrue(references_fail_closed(doc))

    def test_registered_reference_requires_matching_digest(self):
        identifier = "urn:example:schemas:agent-card:1.0.0"
        bundle = {"$defs": {"capability": {"type": "string"}}}
        registered = RegisteredSchema.from_document(identifier, bundle)
        self.assertTrue(references_fail_closed({"$ref": identifier + "#/$defs/capability"}, {identifier: registered}))

    def test_mutated_registered_bundle_fails_closed(self):
        identifier = "urn:example:schemas:tool:1.0.0"
        registered = RegisteredSchema.from_document(identifier, {"type": "object"})
        mutated = RegisteredSchema(identifier, {"type": "string"}, registered.sha256)
        result = check_reference_policy({"$ref": identifier}, {identifier: mutated})
        self.assertFalse(result[0].allowed)
        self.assertEqual(result[0].reason, "registered schema digest mismatch")

    def test_nested_references_are_all_checked(self):
        doc = {"allOf": [{"$ref": "#/$defs/value"}, {"items": {"$ref": "https://invalid.example/schema"}}]}
        results = check_reference_policy(doc)
        self.assertEqual([item.allowed for item in results], [True, False])


class TestWireAndValidatorFixtures(unittest.TestCase):
    aliases = {"task_id": ("taskId", "task_id"), "input_schema": ("inputSchema", "input_schema")}

    def test_equivalent_wire_fields_are_a_collision(self):
        self.assertEqual(field_collisions({"taskId": "a", "task_id": "b"}, self.aliases), ["task_id"])

    def test_collision_is_rejected_during_normalization(self):
        with self.assertRaisesRegex(ValueError, "input_schema"):
            normalize_wire_fields({"inputSchema": {}, "input_schema": {}}, self.aliases)

    def test_one_documented_spelling_normalizes_consistently(self):
        self.assertEqual(normalize_wire_fields({"taskId": "a"}, self.aliases), {"task_id": "a"})
        self.assertEqual(normalize_wire_fields({"task_id": "a"}, self.aliases), {"task_id": "a"})

    def test_validator_outcomes_detect_differential(self):
        self.assertTrue(validator_differential({"gateway": True, "sdk": False, "receiver": True}))

    def test_validator_outcomes_accept_consensus(self):
        self.assertFalse(validator_differential({"gateway": False, "sdk": False, "receiver": False}))
