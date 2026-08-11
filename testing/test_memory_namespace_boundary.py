"""MEM-011/MEM-012 must FAIL against a store that crosses namespace boundaries.

CVE-2026-71433 / GHSA-47pj-3jcm-6whg: LangGraph's Postgres and SQLite stores
flattened a hierarchical namespace to a dot-joined string and matched scoped
reads with ``LIKE '<path>%'``. ``LIKE`` has no notion of the ``.`` separator, so
a read scoped to ``("foo",)`` also returned items under ``("foobar",)``, and
because ``_`` and ``%`` are legal namespace labels but unescaped ``LIKE``
metacharacters, ``("user_1",)`` also matched ``("userX1",)``.

Across the whole catalog this harness asserted no such property. The four
tenant-isolation tests it does have (MS-003, IN-001, WXO-005, CP-008) all drive
a deployed endpoint; none constructs an adversarial namespace pair and then
checks the persisted read boundary. The vulnerable predicate can execute beneath
the endpoint while those cases never provoke it.

CONTRIBUTION_REVIEW_CHECKLIST requires a new test be shown to PASS against
compliant behaviour and FAIL against known-vulnerable behaviour. A test only ever
seen to pass is indistinguishable from one that cannot fail - see #357, where six
identity tests could not fail for any input. Both directions are asserted here,
against a segment-aware store and against a LIKE-semantics store.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.memory_harness import MemoryTests  # noqa: E402

_NS_RE = re.compile(r"namespace '([^']+)'")
_MARKER_RE = re.compile(r"(canary_token_[0-9a-f]+)")


class _FakeStore:
    """Minimal store standing in for the target's memory backend.

    ``mode="segment_aware"`` is the fixed behaviour: a scoped read returns the
    namespace itself and its descendants, and nothing else.

    ``mode="like_prefix"`` reproduces the CVE: the queried label is used as a
    ``LIKE`` pattern against the flattened namespace, so leading-substring
    siblings match and ``_``/``%`` act as wildcards.
    """

    def __init__(self, mode: str):
        self.mode = mode
        self.items: dict[str, str] = {}

    def _matches(self, stored: str, queried: str) -> bool:
        if self.mode == "segment_aware":
            return stored == queried or stored.startswith(queried + ".")
        if self.mode == "like_prefix":
            # LIKE '<queried>%' with _ = any single char, % = any run.
            pattern = "".join(
                "." if c == "_" else ".*" if c == "%" else re.escape(c)
                for c in queried
            )
            return re.match(pattern + ".*", stored) is not None
        raise ValueError(f"unknown mode {self.mode!r}")

    def send(self, text: str) -> dict:
        ns_match = _NS_RE.search(text)
        ns = ns_match.group(1) if ns_match else ""
        marker_match = _MARKER_RE.search(text)

        if marker_match:                      # a write
            self.items[ns] = marker_match.group(1)
            body = "stored"
        else:                                 # a scoped read
            hits = [m for stored, m in self.items.items()
                    if self._matches(stored, ns)]
            body = " ".join(hits) if hits else "no notes found"

        # Shaped as a serviced response so the #348 guard in _record does not
        # convert these into INCONCLUSIVE. See testing/test_serviced_guard.py.
        return {"_status": 200,
                "response": {"jsonrpc": "2.0", "id": 1,
                             "result": {"parts": [{"text": body}]}}}


def _run(test_name: str, mode: str):
    suite = MemoryTests("http://stub.invalid")
    store = _FakeStore(mode)
    suite._send = store.send  # type: ignore[method-assign]
    getattr(suite, test_name)()
    assert len(suite.results) == 1, f"expected one result, got {len(suite.results)}"
    return suite.results[0]


class NamespaceBoundaryTests(unittest.TestCase):

    CASES = [
        ("test_mem_011_namespace_prefix_boundary", "MEM-011"),
        ("test_mem_012_namespace_wildcard_metacharacter", "MEM-012"),
    ]

    def test_passes_against_segment_aware_store(self):
        """The control holding must produce a PASS, or the test is unusable."""
        for method, test_id in self.CASES:
            with self.subTest(test_id=test_id):
                r = _run(method, "segment_aware")
                self.assertEqual(r.test_id, test_id)
                self.assertTrue(
                    r.passed,
                    f"{test_id} did not pass against a segment-aware store: {r.details}",
                )

    def test_fails_against_like_prefix_store(self):
        """The CVE behaviour must produce a FAIL. This is the direction that matters."""
        for method, test_id in self.CASES:
            with self.subTest(test_id=test_id):
                r = _run(method, "like_prefix")
                self.assertEqual(r.test_id, test_id)
                self.assertFalse(
                    r.passed,
                    f"{test_id} reported PASS against a store reproducing "
                    f"CVE-2026-71433 - it cannot detect what it was written for",
                )

    def test_failure_detail_names_the_leaked_marker(self):
        """A FAIL has to say which marker crossed, or it is not actionable."""
        for method, test_id in self.CASES:
            with self.subTest(test_id=test_id):
                r = _run(method, "like_prefix")
                self.assertIn("canary_token_", r.details)


if __name__ == "__main__":
    unittest.main()
