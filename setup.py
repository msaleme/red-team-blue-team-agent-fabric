"""Build-time copy of the canonical data directories into the package.

`protocol_tests/{schemas,configs,coverage}` are symlinks to the canonical
`schemas/`, `configs/` and `docs/coverage/`. On Linux the wheel builder follows
them and the data ships. On a Windows clone without developer mode, git writes
each symlink as a regular FILE containing its target path; `package-data`
globs beneath a file match nothing, the build SUCCEEDS, and the wheel lacks
every runtime data file. An external review reproduced exactly that
(2026-09-07) by flattening the links on Linux.

This copies from the canonical roots into the build staging directory, so the
distribution is independent of how the links materialised. It is a copy into
`build/`, not a second maintained source: the repo still has one of each file.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py

ROOT = Path(__file__).resolve().parent

#: package-local dir -> canonical source dir -> glob
_DATA = (
    ("schemas", ROOT / "schemas", "*.json"),
    ("configs", ROOT / "configs", "*.yaml"),
    ("coverage", ROOT / "docs" / "coverage", "*.yaml"),
)


class build_py(_build_py):
    def run(self) -> None:
        super().run()
        pkg_dir = Path(self.build_lib) / "protocol_tests"
        for local, source, pattern in _DATA:
            files = sorted(source.glob(pattern))
            if not files:
                raise SystemExit(
                    f"setup.py: no {pattern} under canonical {source}; refusing to "
                    f"build a wheel that would ship without runtime data")
            dest = pkg_dir / local
            # Whatever the symlink became -- a link, a dir, or a placeholder
            # file -- is replaced by real files from the canonical root.
            if dest.is_symlink() or dest.is_file():
                dest.unlink()
            dest.mkdir(parents=True, exist_ok=True)
            for f in files:
                shutil.copy2(f, dest / f.name)


setup(cmdclass={"build_py": build_py})
