"""The OWASP Agentic Top 10 category titles, derived from one source.

Three modules carried their own hardcoded copy of this table -- evidence_pack,
html_report, and top10_failures -- and all three had drifted the same way:
every one of the ten titles disagreed with `docs/coverage/owasp-agentic-v1.1.yaml`
and with the published OWASP Top 10 for Agentic Applications (2026). They called
ASI02 "Privilege Escalation & Authorization Bypass" where the standard says
"Tool Misuse and Exploitation", and ASI10 "Multi-Agent Trust & Delegation" where
the standard says "Rogue Agents".

The crosswalk and the YAML were correct. The three auditor-facing renderers were
not, which is the worse place for it. A copy that has to be kept in sync is a
copy that will drift; this module exists so there is nothing to keep in sync.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

#: The canonical coverage source, relative to a package or repo root.
_REL = ("coverage", "owasp-agentic-v1.1.yaml")


def _candidates() -> list[Path]:
    here = Path(__file__).resolve().parent
    return [
        here.joinpath(*_REL),                    # installed wheel / symlinked checkout
        here.parent / "docs" / "coverage" / _REL[-1],  # repo root
    ]


def load_owasp_categories() -> dict[str, str]:
    """Return {ASI id: title}, read from the canonical YAML.

    Raises rather than falling back to a literal. A wrong title rendered
    confidently into an evidence pack is worse than a pack that fails to build:
    the first misinforms an auditor, the second stops and says so.
    """
    import yaml

    for candidate in _candidates():
        if not candidate.exists():
            continue
        found: dict[str, str] = {}

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                if str(node.get("id", "")).startswith("ASI") and "title" in node:
                    found[node["id"]] = node["title"]
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(yaml.safe_load(candidate.read_text()))
        if found:
            return dict(sorted(found.items()))

    raise FileNotFoundError(
        "owasp-agentic-v1.1.yaml was not found in "
        f"{[str(c) for c in _candidates()]}. The OWASP category titles have "
        "exactly one source and this build does not ship it."
    )


OWASP_AGENTIC_CATEGORIES: dict[str, str] = load_owasp_categories()
