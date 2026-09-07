"""The OWASP category titles must have one source, and it must be the standard's.

Three renderers carried their own hardcoded copy -- `evidence_pack`,
`html_report`, `top10_failures` -- and every one of the ten titles in all three
had drifted from `docs/coverage/owasp-agentic-v1.1.yaml` AND from the published
OWASP Top 10 for Agentic Applications (2026):

    ASI02  standard: "Tool Misuse and Exploitation"
           shipped:  "Privilege Escalation & Authorization Bypass"
    ASI10  standard: "Rogue Agents"
           shipped:  "Multi-Agent Trust & Delegation"

The crosswalk and the YAML were right; the three auditor-facing renderers were
wrong. Every evidence pack generated to date mislabels all ten categories.

Two properties are pinned here. The first is that there is ONE source. The
second is that the source matches the published standard -- because a single
consistent source that is uniformly wrong would satisfy the first property
while still misinforming every reader.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol_tests.owasp_taxonomy import OWASP_AGENTIC_CATEGORIES, load_owasp_categories

#: Transcribed from the OWASP Top 10 for Agentic Applications (2026), the
#: published ASI01-ASI10. This is the only place a literal belongs: it is the
#: external fact the internal source is checked against, not a second copy for
#: rendering. If OWASP revises the list, this is what must be updated first.
PUBLISHED_2026 = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution (RCE)",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

#: Every module that renders these titles to a human.
RENDERERS = ("scripts.evidence_pack", "scripts.html_report", "scripts.top10_failures")


class ThereIsOneSource(unittest.TestCase):
    def test_the_loader_found_something(self):
        """A loader returning {} would make every assertion below vacuous."""
        self.assertEqual(len(OWASP_AGENTIC_CATEGORIES), 10)

    def test_the_source_matches_the_published_standard(self):
        self.assertEqual(
            OWASP_AGENTIC_CATEGORIES, PUBLISHED_2026,
            "the canonical YAML no longer matches the published OWASP Top 10 "
            "for Agentic Applications (2026)",
        )

    def test_every_renderer_uses_the_shared_object(self):
        """Identity, not equality -- equality would pass on a synced copy."""
        import importlib

        for name in RENDERERS:
            with self.subTest(module=name):
                mod = importlib.import_module(name)
                self.assertIs(
                    getattr(mod, "OWASP_AGENTIC_CATEGORIES"),
                    OWASP_AGENTIC_CATEGORIES,
                    f"{name} has its own copy of the ASI titles; a copy that "
                    f"must be kept in sync is a copy that will drift",
                )

    def test_no_renderer_restates_a_title_as_a_literal(self):
        """Catches a copy reintroduced beside the import."""
        root = Path(__file__).resolve().parents[1]
        for name in RENDERERS:
            with self.subTest(module=name):
                src = (root / (name.replace(".", "/") + ".py")).read_text()
                for asi_id, title in PUBLISHED_2026.items():
                    self.assertNotIn(
                        f'"{asi_id}": "', src,
                        f"{name} restates {asi_id} as a literal",
                    )

    def test_the_loader_refuses_rather_than_guesses(self):
        """A missing source must raise, never fall back to a literal.

        A wrong title rendered confidently into an evidence pack misinforms an
        auditor; a pack that fails to build stops and says so.
        """
        import protocol_tests.owasp_taxonomy as tax

        real = tax._candidates
        tax._candidates = lambda: [Path("/nonexistent/owasp.yaml")]
        try:
            with self.assertRaises(FileNotFoundError):
                load_owasp_categories()
        finally:
            tax._candidates = real


if __name__ == "__main__":
    unittest.main()
