"""Wire JCS byte-match into pytest discovery.

Runs run_bytematch.main() and asserts a clean exit. The byte-match itself
fetches three published fixture sources at runtime; this test will skip
gracefully if `rfc8785` is not installed (install with
`pip install -r tests/jcs/requirements.txt`).

Tracks A2A WG: a2aproject/A2A#1672, a2aproject/A2A#1786.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))


def test_jcs_bytematch_passes():
    """All 19 published JCS canonicalization vectors must reproduce.

    Skips if `rfc8785` is not installed. Requires network access to fetch
    fixtures from agentgraph.co, raw.githubusercontent.com, and aeoess.com
    on first run; results cache under tests/jcs/.fixtures/.
    """
    pytest.importorskip("rfc8785")
    import run_bytematch

    assert run_bytematch.main() == 0, "JCS byte-match failed; see stdout for divergence detail"
