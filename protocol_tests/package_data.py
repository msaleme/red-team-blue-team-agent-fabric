"""One resolver for every data file the package reads at run time.

Five places resolved these paths their own way -- attestation, owasp_taxonomy,
compliance_crosswalk, and three raw `os.path.join(REPO_ROOT, "configs", ...)`
joins in the report consumers. The three consumers resolved a checkout-only
path: in an installed wheel `html_report` silently dropped both coverage
tables, `top10_failures` returned `{}`, and `evidence_pack` raised naming a
root-level `configs/` that does not exist there. #526 tested ZIP membership
and attestation validation; it never called these three. Found by an external
review importing the extracted wheel from outside the checkout (2026-09-07).

Resolution order: the package-local copy (`protocol_tests/<dir>/...`, correct
in a wheel and in a symlinked checkout), then the canonical repo-root location
(a checkout where the symlink did not materialise). A missing file resolves to
the package-local path so the error names where it was expected.
"""
from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).resolve().parent

#: Package-local directory -> canonical repo-root location.
_CANONICAL = {
    "schemas": ("schemas",),
    "configs": ("configs",),
    "coverage": ("docs", "coverage"),
}


def data_path(*parts: str) -> Path:
    """`data_path("configs", "aiuc1_mapping.yaml")` -> an existing Path, or the
    package-local expectation if nothing exists (so the caller's error is
    specific)."""
    if not parts or parts[0] not in _CANONICAL:
        raise ValueError(f"unknown data directory {parts[:1]!r}; "
                         f"known: {sorted(_CANONICAL)}")
    local = _HERE.joinpath(*parts)
    if local.is_file():
        return local
    root = _HERE.parent.joinpath(*_CANONICAL[parts[0]], *parts[1:])
    if root.is_file():
        return root
    return local


def data_dir(name: str) -> Path:
    """The directory form, for callers that list or join themselves."""
    if name not in _CANONICAL:
        raise ValueError(f"unknown data directory {name!r}")
    local = _HERE / name
    if local.is_dir():
        return local
    root = _HERE.parent.joinpath(*_CANONICAL[name])
    return root if root.is_dir() else local
