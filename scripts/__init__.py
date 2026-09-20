"""Command-line and reporting utilities that ship with the distribution.

This file exists to make `scripts` a REGULAR package rather than a namespace
portion, and removing it reintroduces a real import failure.

`pyproject.toml` declares `include = ["scripts*"]`, and setuptools' pyproject
finder has `namespaces = true` by default, so without an `__init__.py` this
directory still ships -- as a namespace portion. The two are not equivalent at
import time:

    a namespace portion loses to a regular package of the same name found
    ANYWHERE on sys.path, whatever the order

    a regular package loses only to one found EARLIER

`scripts` is a generic top-level name, and `protocol_tests/cli.py` imports
`scripts.html_report` at run time on an installed copy. As a namespace portion,
any unrelated installed distribution shipping a regular top-level `scripts`
silently defeated that import, no matter where it sat on the path.

`TheWheelShipsWhatItReads.test_top_level_packages_are_regular_packages` holds
this, deriving the package list from the wheel's own `top_level.txt` rather
than naming `scripts`, so a future top-level package is covered too.
"""
