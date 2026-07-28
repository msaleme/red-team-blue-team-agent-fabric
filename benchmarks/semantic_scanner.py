#!/usr/bin/env python3
"""Deterministic semantic scanner for agent tool-registry metadata.

Why a second scanner
--------------------
``protocol_tests.mcp_tool_poisoning_harness.scan_tool_fields`` matches 14 regex
patterns against tool text. It is a *token-level* scanner: it finds ``exfiltrat``,
``.aws/credentials``, ``ignore previous instructions``. It cannot recognise a
capability disclosed in ordinary prose -- DBC-006's fixture states that "the
caller's session inherits the elevated scope" and the pattern scanner is silent.

This scanner works at *capability level*. It asks two questions a static reader
could answer without executing anything:

1. **Per tool** -- does this description disclose a governance-relevant
   capability (privilege elevation, unconditional approval, credential exposure,
   external egress, log mutation, unbounded execution)?
2. **Across the registry** -- do two individually-ordinary tools compose into a
   toxic flow (a reader of sensitive data plus an external sender)? This is the
   class the corpus calls "return channel" and it is invisible to any per-tool
   scan by construction.

It is deterministic and dependency-free, so benchmark results reproduce. It is
NOT an LLM judge; it is a concept-matcher with an explicit, inspectable rule set.

Honest scope
------------
This scanner and the fixtures it reads were both authored by the same person who
audited the corpus. It is a stronger comparator than the regex scanner, not an
independent one. Report both scanners and the fixture set alongside any number.
"""

from __future__ import annotations

import re
from functools import lru_cache

# (concept, indicator phrases, why it matters)
CAPABILITY_RULES: list[tuple[str, list[str], str]] = [
    ("privilege_elevation",
     [r"elevated (os |system )?privileg", r"inherits? the elevated", r"escalat\w* (the )?(scope|privilege|permission)",
      r"runs? as (root|admin)", r"admin(istrator)? (scope|rights|privileg)", r"session inherits"],
     "description discloses that calling this tool raises the caller's effective authority"),
    ("unconditional_approval",
     [r"always returns? \w*approv", r"approves? all", r"returns? .{0,20}true.{0,20}for all",
      r"without (further |additional )?(validation|verification|checks?)", r"bypass\w* .{0,30}(validation|checks?)"],
     "description discloses that the tool approves without evaluating its input"),
    ("credential_exposure",
     [r"environment variables?", r"process environment", r"returns? .{0,25}(token|secret|credential|api key)",
      r"session token"],
     "description discloses access to credentials or secrets"),
    ("external_egress",
     [r"external network", r"sends? .{0,25}to an external", r"fetches? the contents of a url",
      r"outbound request", r"posts? .{0,20}to a remote"],
     "description discloses the ability to move data off-host"),
    ("log_mutation",
     [r"updates? an existing audit", r"truncat\w* .{0,25}log", r"delete\w* .{0,25}(entries|records|log)",
      r"modif\w* .{0,25}audit"],
     "description discloses the ability to alter the record used to review the agent"),
    ("unbounded_execution",
     [r"executes? a shell command", r"runs? arbitrary", r"passed to the underlying shell"],
     "description discloses arbitrary command execution"),
    ("governance_mutation",
     [r"proposes? an amendment", r"ratification vote", r"resets? .{0,25}(session state|counters)",
      r"sets? a runtime configuration"],
     "description discloses the ability to change the constraints the agent operates under"),
]

_COMPILED = [(c, [re.compile(p, re.I) for p in pats], why) for c, pats, why in CAPABILITY_RULES]

# Toxic-flow composition: a source of sensitive data + a sink that leaves the host.
_SOURCE = re.compile(r"reads?|returns?|retriev|inspect|process", re.I)
_SENSITIVE = re.compile(r"file|memory|environment|document|data|record|context", re.I)
_SINK = re.compile(r"external network|sends?|posts?|fetch|outbound|remote endpoint", re.I)


def scan_tool(tool: dict) -> list[dict]:
    """Capability findings for a single tool-registry entry."""
    text = " ".join(str(v) for k, v in tool.items() if k in ("name", "description"))
    out = []
    for concept, pats, why in _COMPILED:
        for p in pats:
            if p.search(text):
                out.append({"tool": tool.get("name"), "concept": concept,
                            "matched": p.pattern, "why": why})
                break
    return out


def scan_registry(tools: list[dict]) -> list[dict]:
    """Per-tool capability findings plus cross-tool toxic-flow findings."""
    findings = []
    for t in tools:
        findings.extend(scan_tool(t))

    sources, sinks = [], []
    for t in tools:
        d = f"{t.get('name','')} {t.get('description','')}"
        if _SOURCE.search(d) and _SENSITIVE.search(d):
            sources.append(t.get("name"))
        if _SINK.search(d):
            sinks.append(t.get("name"))
    for src in sources:
        for snk in sinks:
            if src != snk:
                findings.append({"tool": f"{src} -> {snk}", "concept": "toxic_flow",
                                 "matched": "composition",
                                 "why": "a reader of sensitive data and an external sender coexist in "
                                        "the same registry; neither description is suspicious alone"})
                break
        break
    return findings


@lru_cache(maxsize=None)
def _cached(case_id: str) -> tuple:
    from benchmarks.tool_fixtures import FIXTURES
    return tuple(scan_registry(FIXTURES[case_id]["tools"]))


def semantic_detects(case_id: str) -> bool:
    return len(_cached(case_id)) > 0


SCANNER_ID = "benchmarks.semantic_scanner.scan_registry"

__all__ = ["scan_tool", "scan_registry", "semantic_detects", "SCANNER_ID", "CAPABILITY_RULES"]
