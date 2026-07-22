"""Fail-closed schema-reference policy helpers for A2A and MCP fixtures.

These helpers deliberately do not resolve JSON Schema references.  A consuming
adapter can use them before handing a schema to a validator to ensure that only
locally registered, immutable schema bundles are eligible for resolution.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urldefrag


@dataclass(frozen=True)
class RegisteredSchema:
    """An allowlisted local schema bundle with an immutable content digest."""

    identifier: str
    document: dict[str, Any]
    sha256: str

    @classmethod
    def from_document(cls, identifier: str, document: dict[str, Any]) -> "RegisteredSchema":
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return cls(identifier=identifier, document=document, sha256=hashlib.sha256(canonical).hexdigest())


@dataclass(frozen=True)
class ReferencePolicyResult:
    """A policy-only result, never the result of remote or filesystem retrieval."""

    allowed: bool
    reason: str
    reference: str


def _walk_references(value: Any) -> list[str]:
    """Return every string-valued ``$ref`` from a JSON-compatible document."""
    refs: list[str] = []
    if isinstance(value, dict):
        ref = value.get("$ref")
        if isinstance(ref, str):
            refs.append(ref)
        for child in value.values():
            refs.extend(_walk_references(child))
    elif isinstance(value, list):
        for child in value:
            refs.extend(_walk_references(child))
    return refs


def check_reference_policy(
    document: dict[str, Any], registry: dict[str, RegisteredSchema] | None = None
) -> list[ReferencePolicyResult]:
    """Evaluate references without fetching network, files, or package registries.

    Local fragments are allowed.  Absolute or relative external identifiers are
    allowed only when their defragmented identifier is in ``registry`` and the
    registered bundle still matches its recorded digest.
    """
    registry = registry or {}
    results: list[ReferencePolicyResult] = []
    for reference in _walk_references(document):
        identifier, _fragment = urldefrag(reference)
        if not identifier:
            results.append(ReferencePolicyResult(True, "local fragment", reference))
            continue
        registered = registry.get(identifier)
        if registered is None:
            results.append(ReferencePolicyResult(False, "unregistered external reference", reference))
            continue
        expected = RegisteredSchema.from_document(registered.identifier, registered.document).sha256
        if expected != registered.sha256:
            results.append(ReferencePolicyResult(False, "registered schema digest mismatch", reference))
            continue
        results.append(ReferencePolicyResult(True, "allowlisted pinned schema", reference))
    return results


def references_fail_closed(document: dict[str, Any], registry: dict[str, RegisteredSchema] | None = None) -> bool:
    """True only when every declared reference is local or pinned in the registry."""
    return all(result.allowed for result in check_reference_policy(document, registry))


def field_collisions(payload: dict[str, Any], aliases: dict[str, tuple[str, str]]) -> list[str]:
    """Identify payloads that provide both documented spellings of one field."""
    return [
        semantic_name
        for semantic_name, (camel_case, snake_case) in aliases.items()
        if camel_case in payload and snake_case in payload
    ]


def normalize_wire_fields(
    payload: dict[str, Any], aliases: dict[str, tuple[str, str]]
) -> dict[str, Any]:
    """Normalize one documented spelling per field and reject ambiguous duplicates."""
    collisions = field_collisions(payload, aliases)
    if collisions:
        raise ValueError(f"ambiguous equivalent fields: {', '.join(collisions)}")
    normalized = dict(payload)
    for semantic_name, (camel_case, snake_case) in aliases.items():
        if camel_case in normalized:
            normalized[semantic_name] = normalized.pop(camel_case)
        elif snake_case in normalized:
            normalized[semantic_name] = normalized.pop(snake_case)
    return normalized


def validator_differential(boundary_outcomes: dict[str, bool]) -> bool:
    """Return True when named validation boundaries disagree on a fixture."""
    return len(set(boundary_outcomes.values())) > 1
