"""Shared result type and recording base for test harnesses.

## Why this exists

This package had 45 result dataclasses in 31 distinct field signatures, and 43
separate ``_record`` implementations of one concept: *record a verdict about a
response*. That is the direct cause of #348, #350 and #351 rather than a matter
of taste. When a defect was found in the verdict logic it had 43 possible homes,
and each repair reached only the ones someone thought to open, so the same bug
was fixed in v4.13.1, again in #348, again in #350 and again in #351.

The package already knows the right shape. ``ExtAdapter``,
``EnterprisePlatformAdapter``, ``CloudAgentAdapter`` and ``FrameworkAdapter``
each give one ``_record`` to 5-11 subclasses, which is exactly why guarding
those modules was a one-line change while guarding the five standalone harnesses
in #348 took five separate edits. The pattern is right where it is applied and
absent everywhere else.

## What this does NOT do

It does not migrate the 43. Collapsing them in one change would be a large edit
to a package with roughly 705 downloads a month, and the #351 sweep is evidence
against that approach: a careful bulk application of a *one-line* guard turned 25
correct passes into failures and had to be reverted across fourteen of them.

So this is additive. New harnesses inherit it; existing ones are grandfathered in
``testing/test_harness_base_adoption.py`` and migrate when they are touched for
other reasons. The grandfather list may shrink and must never grow.

## Field selection

Not invented. Measured across all 45 existing result classes:

    test_id   44/45     elapsed_s          42/45      category  32/45
    name      43/45     request_sent       35/45      stride    16/45
    owasp_asi 43/45     response_received  35/45      protocol  14/45
    severity  43/45     timestamp          34/45
    passed    43/45
    details   43/45

The six universal fields are required. Everything a majority declares is
optional with a default, so a subclass can add its own fields without fighting
the base.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from protocol_tests.http_helpers import inconclusive_detail


@dataclass
class HarnessResult:
    """The result shape 43 of 45 existing result classes already converge on.

    Subclass it to add harness-specific fields rather than starting a 46th
    parallel definition::

        @dataclass
        class MyHarnessResult(HarnessResult):
            mcp_method: str = ""
    """

    test_id: str
    name: str
    owasp_asi: str
    severity: str
    passed: bool
    details: str

    category: str = ""
    stride: str = ""
    protocol: str = ""
    endpoint: str = ""
    request_sent: dict | None = None
    response_received: dict | None = None
    elapsed_s: float = 0.0
    timestamp: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


class RecordingHarness:
    """Base for any harness that records a verdict about a target response.

    Supplies the one behaviour that had to be retrofitted four times: a result
    whose target never serviced the request is INCONCLUSIVE, never a pass. A
    subclass cannot forget a guard it never has to call.

    Subclasses that need their own ``_record`` behaviour should call
    ``super()._record(result)`` rather than reimplementing it. Overriding it
    without that call reintroduces exactly the defect this class exists to
    prevent, and ``testing/test_harness_base_adoption.py`` checks for it.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if not hasattr(self, "results"):
            self.results: list[Any] = []

    def _record(self, result: Any) -> Any:
        """Append a result, downgrading it to INCONCLUSIVE if unserviced."""
        self.results.append(result)
        detail = inconclusive_detail(
            getattr(result, "response_received", None),
            getattr(result, "details", None),
        )
        if detail is not None:
            result.passed = False
            result.details = detail
        return result
