#!/usr/bin/env python3
"""Multi-hop delegated-authority attenuation harness (DCA-001..DCA-011).

## The property

When an agent hands work to a sub-agent, and that sub-agent hands work on
again, each hop carries a **pass**: a statement of what the holder may do. The
property this module tests is that a child's authority is provably no broader
than its parent's, and that the check happens **at the tool boundary** — the
place that actually performs the effect — rather than in the calling agent's
reasoning about what it ought to ask for.

An agent's reasoning is not an enforcement point. It is an input the attacker
may control. If the only thing standing between a staging-scoped sub-agent and
the production database is that the orchestrator "wouldn't ask for that", the
system has a plan, not a control.

## Why this generalises FB-013

FB-013 (this repository, `x402_fireblocks_harness`) is the concrete instance.
An approval quorum checked that approvers were *distinct* and never that they
were *authorized*, so two arbitrary strings formed a quorum. The class of defect
is: **a structural property was checked in place of an authority property.**
Cardinality was checked in place of entitlement.

Delegation chains fail the same way, and more often, because the structural
property looks so much more convincing:

  * checking that a child pass is *well-formed* instead of *narrower*;
  * checking the leaf against the **root** instead of against **every hop**,
    which lets an intermediate re-widen what its own parent narrowed;
  * checking the pass **presented** instead of the authority actually **used**,
    which is how a tool ends up acting under its own ambient credentials;
  * checking that a pass **verifies** instead of that it verifies *here*, which
    is audience confusion.

Each of those is a real check that passes on a real attack.

## What this module is, and is not

It is a **conformance suite against a reference model** defined in this file:
`Authority`, `DelegationPass`, and `ToolBoundary`. In ``--simulate`` mode the
verdicts are statements about that reference model — a self-test, not a finding
about anybody's deployment — and every result says so in `verdict_scope`.

There is no interoperable wire format for delegation passes across MCP, A2A and
the agent-payment stack, so ``--url`` mode cannot be a spec conformance probe.
What it does is narrower and honestly labelled: it POSTs each attack chain to
the target and records whether the target *accepted* it. An unreachable or
erroring target is INCONCLUSIVE (never a pass) via the shared
`RecordingHarness._record` guard. A target that answers and accepts a
privilege-escalating chain is evidence of an absent control; a target that
answers and rejects it is consistent with the control being present and is not
proof that it is, because the target may be rejecting the request shape rather
than the authority claim. That limit is stated in the details string.

## Positive controls are load-bearing

Every deny case in this suite is paired, inside the same test, with the
legitimate variant it must ALLOW. A verifier that denies everything is not a
verifier, and a suite of nothing but deny cases cannot tell the difference. Two
tests (DCA-009, DCA-010) exist only to carry positive controls.

OWASP Mappings: ASI02 (Improper Access Controls), ASI03 (Identity/Privilege
                Abuse), ASI07 (Insecure Inter-Agent Communication)
STRIDE: Elevation of Privilege, Spoofing, Repudiation

Usage:
    python -m protocol_tests.delegation_chain_harness --simulate
    python -m protocol_tests.delegation_chain_harness --url https://agent.example.com/act
    python -m protocol_tests.delegation_chain_harness --simulate --report dca.json

Requires: Python 3.10+, no external dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from protocol_tests._utils import Severity, http_post_json, json_stdout_only
from protocol_tests.harness_base import HarnessResult, RecordingHarness
from protocol_tests.run_provenance import (
    run_provenance,
    subject_http,
    subject_none,
)
from protocol_tests.http_helpers import (
    INCONCLUSIVE_PREFIX,
    is_inconclusive,
    run_summary,
    summary_lines,
)

# ---------------------------------------------------------------------------
# Policy references
# ---------------------------------------------------------------------------

#: Named clauses of the reference delegation policy. A denial that cannot name
#: the clause it enforced is not auditable: the operator gets "no" and no way to
#: tell a revoked pass from a malformed one, which are different incidents with
#: different responses. Expiry and revocation in particular MUST carry one --
#: they are the two denials an operator is most likely to have to explain.
POLICY = {
    "capability_subset": "DAP-1: a child's capability set is a subset of its parent's",
    "resource_within": "DAP-2: every child resource lies within a parent resource",
    "constraint_preserved": "DAP-3: every parent constraint appears in the child at a bound no looser",
    "audience_bound": "DAP-4: a pass is valid only at the audience it names",
    "chain_linked": "DAP-5: each hop is issued by the subject of the hop above it",
    "expiry": "DAP-6: a pass is invalid at or after its expiry, and no child outlives its parent",
    "revocation": "DAP-7: a pass whose epoch precedes the issuer's revocation epoch is void",
    "no_ambient": "DAP-8: the tool acts only under authority carried in the request",
    "presenter_bound": "DAP-9: the presenter of a chain is the subject of its leaf",
    "within_effective": "DAP-10: the effect lies within the intersection of the whole chain",
    "replay": "DAP-11: a repeated request identifier yields the first receipt, not a second effect",
}


# ---------------------------------------------------------------------------
# Reference authority model
# ---------------------------------------------------------------------------

def resource_within(child: str, parent: str) -> bool:
    """True when ``child`` names a resource inside ``parent``'s scope.

    Scopes are ``/``-separated segment paths, e.g. ``env:staging/db:orders``.
    A parent scope contains a child scope when the parent's segments are a
    prefix of the child's. Prefix is taken **per segment**, not per character,
    so ``env:stag`` does not contain ``env:staging`` — a string-prefix
    implementation is the classic way this check is written and the classic way
    it is bypassed.
    """
    if not parent or not child:
        return False
    p = parent.split("/")
    c = child.split("/")
    return len(p) <= len(c) and c[:len(p)] == p


@dataclass(frozen=True)
class Authority:
    """What a principal may do — the unit a grant and a request are both measured in.

    ``constraints`` are **upper bounds**: a smaller number is narrower. They are
    held as a sorted tuple of pairs rather than a dict so the whole dataclass is
    hashable and comparisons are structural, the same reason ``ActionRef`` in
    `x402_fireblocks_harness` is frozen.
    """

    capabilities: frozenset = frozenset()
    resources: frozenset = frozenset()
    constraints: tuple = ()          # ((name, upper_bound), ...) sorted by name
    audiences: frozenset = frozenset()

    @staticmethod
    def of(capabilities=(), resources=(), constraints=None, audiences=()) -> "Authority":
        """Build one from friendlier inputs (constraints as a dict)."""
        items = tuple(sorted((constraints or {}).items()))
        return Authority(frozenset(capabilities), frozenset(resources),
                         items, frozenset(audiences))

    @property
    def bounds(self) -> dict:
        return dict(self.constraints)

    def as_json(self) -> dict:
        return {
            "capabilities": sorted(self.capabilities),
            "resources": sorted(self.resources),
            "constraints": {k: v for k, v in self.constraints},
            "audiences": sorted(self.audiences),
        }


def caps_subset(child: Authority, parent: Authority) -> tuple[bool, str, str]:
    """No capability the parent does not hold."""
    extra = child.capabilities - parent.capabilities
    if extra:
        return (False,
                f"child holds capabilities absent from its parent: {sorted(extra)}",
                POLICY["capability_subset"])
    return (True, "", "")


def resources_within(child: Authority, parent: Authority) -> tuple[bool, str, str]:
    """No resource outside every parent resource."""
    for r in sorted(child.resources):
        if not any(resource_within(r, p) for p in parent.resources):
            return (False,
                    f"child resource {r!r} is not within the parent scope "
                    f"{sorted(parent.resources)}",
                    POLICY["resource_within"])
    return (True, "", "")


def constraints_preserved(child: Authority, parent: Authority) -> tuple[bool, str, str]:
    """Every parent bound present in the child, at a value no looser.

    Iterating the PARENT's constraints is the whole check. A loop over the
    child's own constraints compares only what the child chose to mention, so a
    child that drops the spend cap entirely presents nothing to compare and the
    loop finds nothing to complain about. A dropped bound is not an oversight to
    be tolerated; it is a request for an unbounded one.
    """
    child_bounds = child.bounds
    for name, limit in sorted(parent.bounds.items()):
        if name not in child_bounds:
            return (False,
                    f"child dropped the parent constraint {name!r} "
                    f"(a dropped bound is an unbounded one)",
                    POLICY["constraint_preserved"])
        if child_bounds[name] > limit:
            return (False,
                    f"child loosened {name!r} from {limit} to {child_bounds[name]}",
                    POLICY["constraint_preserved"])
    return (True, "", "")


def audiences_subset(child: Authority, parent: Authority) -> tuple[bool, str, str]:
    """No audience the parent may not speak to."""
    extra = child.audiences - parent.audiences
    if extra:
        return (False,
                f"child names audiences its parent cannot speak to: {sorted(extra)}",
                POLICY["audience_bound"])
    return (True, "", "")


#: The four independent ways to be broader than your parent. Named separately,
#: and composed here, so each one can be neutered on its own — which is what
#: `testing/test_delegation_chain_attenuation.py` does to show that each is
#: load-bearing rather than decorative.
ATTENUATION_CHECKS = (caps_subset, resources_within, constraints_preserved,
                      audiences_subset)


def narrows(child: Authority, parent: Authority) -> tuple[bool, str, str]:
    """Is ``child`` no broader than ``parent``? Returns (ok, reason, policy_ref)."""
    for check in ATTENUATION_CHECKS:
        ok, reason, ref = check(child, parent)
        if not ok:
            return (False, reason, ref)
    return (True, "child is no broader than its parent", "")


def intersect(a: Authority, b: Authority) -> Authority:
    """The authority held by both — computed, not asserted.

    This exists so the *effective* authority of a chain can be derived
    independently of the per-hop check. The two are different questions and a
    verifier wants both: per-hop rejects a structurally invalid chain outright,
    while the intersection bounds what a structurally valid chain may actually
    do. A verifier with only the intersection accepts a chain containing an
    illegitimate hop as long as the request happens to fall inside the
    narrowest link.
    """
    resources = frozenset(
        [r for r in a.resources if any(resource_within(r, p) for p in b.resources)] +
        [r for r in b.resources if any(resource_within(r, p) for p in a.resources)])
    names = set(a.bounds) | set(b.bounds)
    bounds = {}
    for n in names:
        vals = [d[n] for d in (a.bounds, b.bounds) if n in d]
        bounds[n] = min(vals)
    return Authority.of(
        capabilities=a.capabilities & b.capabilities,
        resources=resources,
        constraints=bounds,
        audiences=a.audiences & b.audiences,
    )


@dataclass(frozen=True)
class DelegationPass:
    """One hop. ``issuer`` delegated ``authority`` to ``subject`` until ``expires_at``.

    ``epoch`` is the issuer's revocation generation at issue time. Bumping an
    issuer's epoch voids every pass it has issued without needing to know their
    identifiers — the revocation primitive that works when the passes are
    bearer-shaped and already in flight.
    """

    pass_id: str
    issuer: str
    subject: str
    authority: Authority
    expires_at: int
    epoch: int = 0

    def as_json(self) -> dict:
        return {
            "pass_id": self.pass_id, "issuer": self.issuer, "subject": self.subject,
            "authority": self.authority.as_json(),
            "expires_at": self.expires_at, "epoch": self.epoch,
        }


@dataclass(frozen=True)
class EffectRequest:
    """A request to actually do something, presented at a tool boundary."""

    request_id: str
    presenter: str
    capability: str
    resource: str
    audience: str
    amounts: tuple = ()   # ((constraint_name, value), ...)

    @staticmethod
    def of(request_id, presenter, capability, resource, audience,
           amounts=None) -> "EffectRequest":
        return EffectRequest(request_id, presenter, capability, resource, audience,
                             tuple(sorted((amounts or {}).items())))

    def as_json(self) -> dict:
        return {
            "request_id": self.request_id, "presenter": self.presenter,
            "capability": self.capability, "resource": self.resource,
            "audience": self.audience, "amounts": {k: v for k, v in self.amounts},
        }


@dataclass
class Decision:
    """The tool boundary's answer. A denial names the clause it enforced."""

    allowed: bool
    reason: str
    policy_ref: str = ""
    receipt: str | None = None
    replayed: bool = False


# ---------------------------------------------------------------------------
# The enforcement point
# ---------------------------------------------------------------------------

class ToolBoundary:
    """A tool that performs effects, and decides authority before it does.

    Deliberately holds ``ambient_authority``: a credential of its own that would
    authorize far more than any pass does — a service account, an instance role,
    a long-lived API key. Real tools have one. The confused-deputy property is
    that it is never consulted, so the only way to show the property holds is to
    give the boundary something to be confused by.
    """

    def __init__(self, audience: str, trusted_roots: dict,
                 revocation_epochs: dict | None = None,
                 ambient_authority: Authority | None = None):
        self.audience = audience
        self.trusted_roots = dict(trusted_roots)
        self.revocation_epochs = dict(revocation_epochs or {})
        self.ambient_authority = ambient_authority
        self.effects_applied = 0
        self._ledger: dict = {}

    # -- authority checks -------------------------------------------------

    # Each check is a separate method returning (ok, reason, policy_ref). They
    # are separate so a subclass can neuter exactly one of them and the suite can
    # show that the corresponding attack then succeeds. A single 60-line
    # `_check_chain` is checkable only in aggregate, and a guard that cannot be
    # made to fail on its own has not been shown to be doing anything.

    def _check_root(self, chain: tuple) -> tuple[bool, str, str]:
        """The chain begins at a root this boundary trusts, at no more authority."""
        root = chain[0]
        if root.issuer not in self.trusted_roots:
            return (False, f"chain root issuer {root.issuer!r} is not a trusted root",
                    POLICY["chain_linked"])
        ok, why, ref = narrows(root.authority, self.trusted_roots[root.issuer])
        if not ok:
            return (False, f"hop 0 ({root.issuer} -> {root.subject}): {why}", ref)
        return (True, "", "")

    def _check_links(self, chain: tuple) -> tuple[bool, str, str]:
        """Each hop is issued by the subject above it, and does not outlive it."""
        for i in range(1, len(chain)):
            parent, child = chain[i - 1], chain[i]
            if child.issuer != parent.subject:
                return (False,
                        f"hop {i}: issuer {child.issuer!r} is not the subject of "
                        f"the hop above ({parent.subject!r})",
                        POLICY["chain_linked"])
            if child.expires_at > parent.expires_at:
                return (False,
                        f"hop {i}: child outlives its parent "
                        f"({child.expires_at} > {parent.expires_at})",
                        POLICY["expiry"])
        return (True, "", "")

    def _check_attenuation(self, chain: tuple) -> tuple[bool, str, str]:
        """EVERY hop narrows the one above it.

        Per hop, not leaf-versus-root. A leaf may be a strict subset of the
        origin and still an escalation, because an intermediate gave authority
        up and nothing below it can take that back. Checking against the origin
        is the cheaper check and it accepts exactly that chain.
        """
        for i in range(1, len(chain)):
            parent, child = chain[i - 1], chain[i]
            ok, why, ref = narrows(child.authority, parent.authority)
            if not ok:
                # Named per hop, so a three-hop chain says WHERE it widened.
                return (False, f"hop {i} ({child.issuer} -> {child.subject}): {why}", ref)
        return (True, "", "")

    def _check_lifetime(self, chain: tuple, now: int) -> tuple[bool, str, str]:
        """No hop is expired — checked at every position, not only the leaf."""
        for i, p in enumerate(chain):
            if p.expires_at <= now:
                return (False,
                        f"hop {i}: pass {p.pass_id!r} expired at {p.expires_at} "
                        f"(now {now})",
                        POLICY["expiry"])
        return (True, "", "")

    def _check_revocation(self, chain: tuple) -> tuple[bool, str, str]:
        """No hop precedes its issuer's revocation epoch.

        Separate from expiry because they are separate incidents. A pass can sit
        well inside its validity window and still be void, and an operator
        reading a denial needs to know which of the two happened.
        """
        for i, p in enumerate(chain):
            floor = self.revocation_epochs.get(p.issuer, 0)
            if p.epoch < floor:
                return (False,
                        f"hop {i}: pass {p.pass_id!r} carries epoch {p.epoch}, "
                        f"below issuer {p.issuer!r} revocation epoch {floor}",
                        POLICY["revocation"])
        return (True, "", "")

    def _check_audience(self, chain: tuple,
                        request: EffectRequest) -> tuple[bool, str, str]:
        """The pass is valid HERE, at the boundary that is actually running."""
        if self.audience not in chain[-1].authority.audiences:
            return (False,
                    f"pass names audiences {sorted(chain[-1].authority.audiences)}; "
                    f"presented at {self.audience!r}",
                    POLICY["audience_bound"])
        if request.audience != self.audience:
            return (False,
                    f"request addressed to {request.audience!r} but presented at "
                    f"{self.audience!r}",
                    POLICY["audience_bound"])
        return (True, "", "")

    def _check_effective(self, chain: tuple,
                         request: EffectRequest) -> tuple[bool, str, str]:
        """The effect lies inside the intersection of the whole chain."""
        eff = self.effective_authority(chain)
        if request.capability not in eff.capabilities:
            return (False,
                    f"capability {request.capability!r} is outside the chain's "
                    f"effective authority {sorted(eff.capabilities)}",
                    POLICY["within_effective"])
        if not any(resource_within(request.resource, r) for r in eff.resources):
            return (False,
                    f"resource {request.resource!r} is outside the chain's "
                    f"effective scope {sorted(eff.resources)}",
                    POLICY["within_effective"])
        bounds = eff.bounds
        for name, value in request.amounts:
            if name not in bounds:
                return (False,
                        f"request declares {name}={value} against no bound in the "
                        f"chain's effective authority",
                        POLICY["within_effective"])
            if value > bounds[name]:
                return (False,
                        f"{name}={value} exceeds the chain's effective bound "
                        f"{bounds[name]}",
                        POLICY["within_effective"])
        return (True, "", "")

    def _check_chain(self, chain: tuple, now: int) -> tuple[bool, str, str]:
        """Structural validity of the chain itself, independent of any request."""
        for check in (self._check_root, self._check_links,
                      self._check_attenuation, self._check_revocation):
            ok, why, ref = check(chain)
            if not ok:
                return (False, why, ref)
        ok, why, ref = self._check_lifetime(chain, now)
        if not ok:
            return (False, why, ref)
        return (True, "chain is linked, attenuating, unexpired and unrevoked", "")

    def effective_authority(self, chain: tuple) -> Authority:
        """The intersection across the whole chain, folded left."""
        eff = chain[0].authority
        for p in chain[1:]:
            eff = intersect(eff, p.authority)
        return eff

    def _check_replay(self, request: EffectRequest) -> Decision | None:
        """The first receipt for a repeated identifier, or None if it is new."""
        prior = self._ledger.get(request.request_id)
        if prior is None:
            return None
        return Decision(allowed=prior.allowed, reason=prior.reason,
                        policy_ref=POLICY["replay"], receipt=prior.receipt,
                        replayed=True)

    def authorize(self, chain, request: EffectRequest, now: int) -> Decision:
        """Decide, then (only if allowed) apply the effect exactly once."""
        # Replay is answered before anything else, so a replayed request cannot
        # be re-adjudicated against changed state and get a different answer.
        replayed = self._check_replay(request)
        if replayed is not None:
            return replayed

        if not chain:
            # The confused deputy. There IS an ambient credential that would
            # authorize this; it is not consulted, because it was not presented.
            return Decision(False,
                            "no delegation chain in the request context; the tool's "
                            "own ambient credential is not authority for a caller's "
                            "request",
                            POLICY["no_ambient"])

        chain = tuple(chain)
        if request.presenter != chain[-1].subject:
            return Decision(False,
                            f"presenter {request.presenter!r} is not the subject of the "
                            f"leaf pass ({chain[-1].subject!r})",
                            POLICY["presenter_bound"])

        ok, why, ref = self._check_chain(chain, now)
        if not ok:
            return Decision(False, why, ref)

        ok, why, ref = self._check_audience(chain, request)
        if not ok:
            return Decision(False, why, ref)

        ok, why, ref = self._check_effective(chain, request)
        if not ok:
            return Decision(False, why, ref)

        self.effects_applied += 1
        receipt = hashlib.sha256(
            json.dumps({"request": request.as_json(),
                        "chain": [p.pass_id for p in chain]},
                       sort_keys=True).encode()).hexdigest()[:32]
        decision = Decision(True, "within the chain's effective authority", "", receipt)
        self._ledger[request.request_id] = decision
        return decision


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class DelegationResult(HarnessResult):
    """A harness result plus the two things a reader of this suite needs.

    ``verdict_scope`` says what the row is about. In ``--simulate`` mode every
    row is about the reference model in this file, and a reader who takes a
    passing CRITICAL row as a statement about their deployment has been
    misled — the failure mode `testing/test_local_verdicts_are_labelled.py`
    was written for.

    ``positive_control`` records that the legitimate variant was also exercised
    and allowed. A deny-case row without it is a row a deny-everything verifier
    would also produce.
    """

    verdict_scope: str = "reference-model self-test (no target)"
    positive_control: str = ""
    policy_ref: str = ""

    #: INCONCLUSIVE as a field rather than only as a prefix on ``details``.
    #: ``asdict()`` carries a field; it does not carry the meaning of English.
    not_evaluated: bool = False

    def __post_init__(self) -> None:
        super().__post_init__()
        # A prefix written into `details` is the state too, not only a guard's
        # decision, so both paths end up structural. The guard in
        # `RecordingHarness._record` rewrites `details` after construction, so
        # `_emit` re-derives this once the guard has run.
        if is_inconclusive(self.details):
            self.not_evaluated = True


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

class DelegationChainTests(RecordingHarness):
    """Multi-hop delegated-authority attenuation suite (DCA-001..DCA-011)."""

    #: Fixed epoch in simulate mode so fixtures and receipts are reproducible.
    SIM_NOW = 1_750_000_000

    def __init__(self, url: str | None = None, headers: dict | None = None,
                 simulate: bool = False):
        super().__init__()
        self.url = url.rstrip("/") if url else None
        self.headers = headers or {}
        self.simulate = simulate or not url
        self.results: list = []

    # -- fixtures ---------------------------------------------------------

    def _now(self) -> int:
        return self.SIM_NOW if self.simulate else int(time.time())

    def _root_authority(self) -> Authority:
        """The orchestrator's own authority — the widest thing in the system."""
        return Authority.of(
            capabilities={"read", "write", "refund"},
            resources={"env:staging", "env:production"},
            constraints={"spend_cents": 100_000, "calls_per_minute": 600},
            audiences={"tool:ledger", "tool:mailer"},
        )

    def _boundary(self, audience: str = "tool:ledger",
                  revocation_epochs: dict | None = None) -> ToolBoundary:
        return ToolBoundary(
            audience=audience,
            trusted_roots={"orchestrator": self._root_authority()},
            revocation_epochs=revocation_epochs,
            # Wide enough to authorize anything in this suite. Never consulted.
            ambient_authority=Authority.of(
                capabilities={"read", "write", "refund", "admin"},
                resources={"env:staging", "env:production"},
                constraints={"spend_cents": 10_000_000, "calls_per_minute": 100_000},
                audiences={"tool:ledger", "tool:mailer"}),
        )

    def _root_pass(self, now: int | None = None, ttl: int = 3600,
                   epoch: int = 0) -> DelegationPass:
        now = self._now() if now is None else now
        return DelegationPass(
            pass_id="p-root", issuer="orchestrator", subject="planner",
            authority=self._root_authority(), expires_at=now + ttl, epoch=epoch)

    def _child_pass(self, parent: DelegationPass, subject: str,
                    authority: Authority, ttl_delta: int = 0,
                    epoch: int = 0, pass_id: str | None = None) -> DelegationPass:
        return DelegationPass(
            pass_id=pass_id or f"p-{subject}", issuer=parent.subject, subject=subject,
            authority=authority, expires_at=parent.expires_at + ttl_delta, epoch=epoch)

    def _legit_child_authority(self) -> Authority:
        """A correctly attenuated child: fewer caps, narrower scope, tighter caps."""
        return Authority.of(
            capabilities={"read"},
            resources={"env:staging/db:orders"},
            constraints={"spend_cents": 500, "calls_per_minute": 60},
            audiences={"tool:ledger"},
        )

    def _legit_chain(self, now: int | None = None) -> tuple:
        root = self._root_pass(now)
        child = self._child_pass(root, "worker", self._legit_child_authority())
        return (root, child)

    def _legit_request(self, presenter: str = "worker",
                       request_id: str = "req-legit") -> EffectRequest:
        return EffectRequest.of(
            request_id=request_id, presenter=presenter, capability="read",
            resource="env:staging/db:orders/row:1", audience="tool:ledger",
            amounts={"spend_cents": 100, "calls_per_minute": 1})

    # -- recording --------------------------------------------------------

    def _probe_live(self, chain, request: EffectRequest) -> tuple[dict, bool]:
        """POST one chain to a live target. Returns (response, target_allowed).

        The response is handed to ``RecordingHarness._record`` as
        ``response_received``, which downgrades an unserviced result to
        INCONCLUSIVE. A pass is never manufactured from silence here.
        """
        payload = {
            "delegation_chain": [p.as_json() for p in (chain or ())],
            "request": request.as_json(),
        }
        resp = http_post_json(self.url, payload, self.headers, timeout=8)
        return resp, self._target_decision(resp) == "allow"

    #: The live response contract this harness grades. A conforming target
    #: answers a chain-plus-request with a JSON object carrying a boolean
    #: decision under one of these keys, and optionally a `receipt` string.
    #: Anything else is undecided, never a pass and never a finding.
    _DECISION_KEYS = ("allowed", "granted")

    @classmethod
    def _target_decision(cls, resp: dict) -> str:
        """'allow' | 'deny' | 'undecided'. Three states, because two conflate.

        THE parser. Every live verdict path reads the decision through this
        function and no other. There used to be two: this one, read by the
        DCA-005 replay hook, and `_target_allowed`, read by `_probe_live` for
        every other row. They agreed on well-formed responses and disagreed on
        `{"allowed": false, "granted": true}`: this one stopped at the first
        key and said deny; the other accepted ANY true alias and said allow.
        So DCA-009/010 graded PASS on a response DCA-005 called a refusal.
        Found by the third external review, 2026-09-07.

        Precedence, stated: there is none. Every decision key present must
        carry a boolean, and every boolean present must agree. One key is a
        decision; two keys that agree are the same decision; two keys that
        disagree are a contradiction and establish nothing. A decision key
        carrying a non-boolean (`"true"`, `1`, an object) is a malformed
        decision, and a malformed decision next to a well-formed one is not
        upgraded to the well-formed one. `null` is read as not stated.

        History: `_target_allowed` returned False for an explicit
        `{"allowed": false}` AND for `{}`, `{"allowed": "true"}`, a JSON-RPC
        error, or a transport error; `_live_replay` read that False as "the
        replay was refused" and graded PASS (second review). 'deny' requires
        a boolean False; anything that is not a boolean is undecided.
        """
        return cls._decide(resp)[0]

    @classmethod
    def _decide(cls, resp: dict) -> tuple[str, str]:
        """(state, reason). The reason is empty for allow/deny and names the
        cause for undecided, so an INCONCLUSIVE row can say WHY on the row."""
        if not isinstance(resp, dict) or resp.get("_error") or "error" in resp:
            return "undecided", ""
        seen: dict[str, bool] = {}
        for k in cls._DECISION_KEYS:
            v = resp.get(k)
            if v is None:
                continue
            if not isinstance(v, bool):
                return "undecided", f"decision key {k!r} is not a boolean"
            seen[k] = v
        if not seen:
            return "undecided", ""
        if len(set(seen.values())) > 1:
            stated = ", ".join(f"{k}={str(v).lower()}" for k, v in seen.items())
            return "undecided", f"decision keys contradict each other ({stated})"
        return ("allow" if next(iter(seen.values())) else "deny"), ""

    @classmethod
    def _target_allowed(cls, resp: dict) -> bool:
        """`_target_decision(resp) == "allow"`, and nothing else. Kept as a
        name so a reader who knew the old one finds the definition."""
        return cls._target_decision(resp) == "allow"

    #: Why a live refusal is not a live pass. There is no interoperable wire
    #: format for a delegation pass, so a target that answers without reporting
    #: a decision may be refusing the authority claim or may simply not parse the
    #: payload. Reading the second as the first is the "no surface is not a pass"
    #: defect (`testing/test_no_surface_is_not_a_pass.py`) with an extra step, so
    #: live mode grades only the two unambiguous answers: it *allowed* an
    #: escalation (a finding), or it *allowed* the legitimate chain (a pass).
    _LIVE_UNDECIDED = (
        "the target answered but reported no allow decision in the reference "
        "shape. It may be refusing the authority claim or may not parse a "
        "delegation chain at all, and nothing here separates those. Run "
        "--simulate for the reference-model verdict.")

    def _emit(self, *, test_id, name, category, severity, owasp, stride,
              denied: bool, deny_reason: str, policy_ref: str,
              positive_control: str, attack_chain, attack_request, t0: float,
              live_expect: str = "reject", live_verdict=None):
        """Fold the reference-model verdict with optional live evidence.

        ``denied`` is the whole verdict in simulate mode: the reference verifier
        refused the attack AND allowed the paired legitimate variant. Both halves
        are computed by the caller; ``positive_control`` is the sentence that
        records the second half, and an empty one is a programming error rather
        than a passing test.

        ``live_expect`` says which way a live target's *allow* should be read.
        ``"reject"`` rows send an attack: an allow is a finding. ``"accept"``
        rows send the legitimate chain: an allow is the pass. Everything else is
        INCONCLUSIVE — see ``_LIVE_UNDECIDED``.
        """
        if not positive_control:
            raise AssertionError(
                f"{test_id} recorded no positive control. A deny case without "
                "evidence that the legitimate variant is allowed is satisfied by "
                "a verifier that denies everything.")
        passed = denied
        details = deny_reason
        response = None
        request_sent = None
        scope = "reference-model self-test (no target)"
        if not self.simulate and live_verdict is not None:
            # A row whose live semantics are not "one request, read the allow".
            # DCA-005 is the case: its first allow is the PRECONDITION for the
            # replay check, not the finding. Routing it through the generic
            # reject path graded a target that correctly allowed a legitimate
            # request as "control absent" -- a false FAIL, latent behind the
            # parser defect above until that was fixed. The hook returns the
            # whole verdict and owns its own requests.
            passed, details, response, request_sent = live_verdict()
            scope = f"live target {self.url}"
        elif not self.simulate and attack_request is not None:
            # Recorded only in live mode. In simulate mode nothing was sent, and
            # a `request_sent` on a row that made no request is the kind of
            # evidence that reads as a probe and was not one.
            request_sent = {
                "delegation_chain": [p.as_json() for p in (attack_chain or ())],
                "request": attack_request.as_json(),
            }
            response, target_allowed = self._probe_live(attack_chain, attack_request)
            scope = f"live target {self.url}"
            if live_expect == "reject" and target_allowed:
                passed = False
                details = (f"LIVE TARGET ALLOWED the chain — control absent. "
                           f"Reference-model verdict for comparison: {deny_reason}")
            elif live_expect == "accept" and target_allowed:
                passed = True
                details = ("live target allowed the legitimate chain, so it is not "
                           f"refusing everything. {deny_reason}")
            else:
                passed = False
                details = f"{INCONCLUSIVE_PREFIX}{self._LIVE_UNDECIDED}"
                _state, why = self._decide(response)
                if why:
                    details = f"{INCONCLUSIVE_PREFIX}{why}; no decision is read from " \
                              f"this response. {self._LIVE_UNDECIDED}"
        r = DelegationResult(
            test_id=test_id, name=name, owasp_asi=owasp, severity=severity,
            passed=passed, details=details, category=category, stride=stride,
            protocol="delegation-chain", endpoint=self.url or "",
            request_sent=request_sent, response_received=response,
            elapsed_s=round(time.monotonic() - t0, 3),
            verdict_scope=scope, positive_control=positive_control,
            policy_ref=policy_ref)
        self._record(r)
        # The shared guard may have rewritten `details` to INCONCLUSIVE. Re-derive
        # the field so a serialised record carries the state, not only the English.
        r.not_evaluated = is_inconclusive(r.details)
        status = "INCONCLUSIVE" if r.not_evaluated else ("PASS" if r.passed else "FAIL")
        print(f"  {status}  {r.test_id}: {r.name}")
        return r

    # -- DCA-001: capability escalation -----------------------------------

    def test_dca_001_capability_escalation(self) -> None:
        """DCA-001: a child may not hold a capability its parent lacks (CRITICAL).

        The child pass is otherwise perfect — right issuer, right subject,
        unexpired, right audience, narrower resources, tighter caps. The one
        thing wrong with it is ``write``, a capability its parent gave up.

        The capability is chosen so the root still holds it. Escalation is
        measured against the immediate parent, not against the origin, and a
        capability the root holds is exactly the case a leaf-versus-root
        verifier waves through.
        """
        t0 = time.monotonic()
        now = self._now()
        boundary = self._boundary()
        root = self._root_pass(now)
        parent = self._child_pass(root, "planner2", Authority.of(
            capabilities={"read"}, resources={"env:staging"},
            constraints={"spend_cents": 1000, "calls_per_minute": 60},
            audiences={"tool:ledger"}))
        # root holds "write"; parent does not. The child takes it back.
        escalated = self._child_pass(parent, "worker", Authority.of(
            capabilities={"read", "write"}, resources={"env:staging/db:orders"},
            constraints={"spend_cents": 500, "calls_per_minute": 30},
            audiences={"tool:ledger"}))
        bad_chain = (root, parent, escalated)
        bad_req = EffectRequest.of("req-esc", "worker", "write",
                                   "env:staging/db:orders/row:1", "tool:ledger",
                                   {"spend_cents": 10, "calls_per_minute": 1})
        d_bad = boundary.authorize(bad_chain, bad_req, now)

        # POSITIVE CONTROL: same shape, capability set kept within the parent.
        attenuated = self._child_pass(parent, "worker", Authority.of(
            capabilities={"read"}, resources={"env:staging/db:orders"},
            constraints={"spend_cents": 500, "calls_per_minute": 30},
            audiences={"tool:ledger"}))
        good_req = EffectRequest.of("req-esc-ok", "worker", "read",
                                    "env:staging/db:orders/row:1", "tool:ledger",
                                    {"spend_cents": 10, "calls_per_minute": 1})
        d_good = self._boundary().authorize((root, parent, attenuated), good_req, now)

        # The clause matters, not only the answer. The intersection check
        # (DAP-10) would also refuse this request, because the parent's
        # capability set bounds it -- so a chain-attenuation guard that had been
        # deleted entirely would still produce a denial here. Requiring DAP-1 by
        # name is what makes this row about the per-hop check.
        clause_ok = d_bad.policy_ref == POLICY["capability_subset"]
        denied = (not d_bad.allowed) and clause_ok and d_good.allowed
        if d_bad.allowed:
            reason = ("PRIVILEGE ESCALATION — a child capability absent from its "
                      "parent was authorized")
        elif not clause_ok:
            reason = ("PRIVILEGE ESCALATION was refused, but not by the "
                      f"attenuation check: denied under {d_bad.policy_ref!r} "
                      f"({d_bad.reason}). Something downstream happened to bound "
                      "the request; the per-hop capability check is not shown to "
                      "be doing anything.")
        else:
            reason = f"escalation denied ({d_bad.reason}) [{d_bad.policy_ref}]"
        self._emit(
            test_id="DCA-001", name="Child Adds a Capability Absent From Its Parent",
            category="attenuation", severity=Severity.CRITICAL.value,
            owasp="ASI03", stride="Elevation of Privilege",
            denied=denied, deny_reason=reason,
            policy_ref=d_bad.policy_ref,
            positive_control=(
                f"the same chain with the capability kept within the parent was "
                f"ALLOWED (receipt {d_good.receipt})" if d_good.allowed else
                "POSITIVE CONTROL FAILED — the correctly attenuated variant was "
                f"also denied ({d_good.reason}); this verifier may deny everything"),
            attack_chain=bad_chain, attack_request=bad_req, t0=t0)

    # -- DCA-002: resource scope widening ---------------------------------

    def test_dca_002_resource_widening(self) -> None:
        """DCA-002: a child may not reach a resource outside its parent's scope (CRITICAL).

        staging -> production. The literal case the property exists for, and the
        one a per-character prefix check gets wrong in the other direction
        (``env:stag`` "containing" ``env:staging``), which is why
        ``resource_within`` compares segments.
        """
        t0 = time.monotonic()
        now = self._now()
        root = self._root_pass(now)
        parent = self._child_pass(root, "planner2", Authority.of(
            capabilities={"read"}, resources={"env:staging"},
            constraints={"spend_cents": 1000, "calls_per_minute": 60},
            audiences={"tool:ledger"}))
        widened = self._child_pass(parent, "worker", Authority.of(
            capabilities={"read"}, resources={"env:production/db:orders"},
            constraints={"spend_cents": 500, "calls_per_minute": 30},
            audiences={"tool:ledger"}))
        bad_chain = (root, parent, widened)
        bad_req = EffectRequest.of("req-widen", "worker", "read",
                                   "env:production/db:orders/row:1", "tool:ledger",
                                   {"spend_cents": 10, "calls_per_minute": 1})
        d_bad = self._boundary().authorize(bad_chain, bad_req, now)

        # POSITIVE CONTROL: the same reach, inside the parent's environment.
        narrowed = self._child_pass(parent, "worker", Authority.of(
            capabilities={"read"}, resources={"env:staging/db:orders"},
            constraints={"spend_cents": 500, "calls_per_minute": 30},
            audiences={"tool:ledger"}))
        good_req = EffectRequest.of("req-widen-ok", "worker", "read",
                                    "env:staging/db:orders/row:1", "tool:ledger",
                                    {"spend_cents": 10, "calls_per_minute": 1})
        d_good = self._boundary().authorize((root, parent, narrowed), good_req, now)

        # Second control, on the primitive rather than the chain: a segment
        # prefix must not be confused with a string prefix in either direction.
        seg_ok = (resource_within("env:staging/db:orders", "env:staging")
                  and not resource_within("env:staging", "env:stag")
                  and not resource_within("env:staging", "env:production"))

        clause_ok = d_bad.policy_ref == POLICY["resource_within"]
        denied = (not d_bad.allowed) and clause_ok and d_good.allowed and seg_ok
        if d_bad.allowed:
            reason = "SCOPE WIDENING — a staging-scoped delegate reached production"
        elif not clause_ok:
            reason = ("SCOPE WIDENING was refused, but not by the attenuation "
                      f"check: denied under {d_bad.policy_ref!r} ({d_bad.reason}). "
                      "The per-hop containment check is not shown to be doing "
                      "anything.")
        elif not seg_ok:
            reason = ("containment is not segment-wise: a string prefix was read as "
                      "a scope prefix, which is the bypass this check exists for")
        else:
            reason = f"scope widening denied ({d_bad.reason}) [{d_bad.policy_ref}]"
        self._emit(
            test_id="DCA-002", name="Child Widens Resource Scope (staging -> production)",
            category="attenuation", severity=Severity.CRITICAL.value,
            owasp="ASI02", stride="Elevation of Privilege",
            denied=denied, deny_reason=reason,
            policy_ref=d_bad.policy_ref,
            positive_control=(
                f"the same delegate scoped inside the parent's environment was "
                f"ALLOWED (receipt {d_good.receipt}); segment-wise containment holds "
                f"in both directions: {seg_ok}" if d_good.allowed else
                f"POSITIVE CONTROL FAILED — the within-scope variant was denied "
                f"({d_good.reason})"),
            attack_chain=bad_chain, attack_request=bad_req, t0=t0)

    # -- DCA-003: constraint drop -----------------------------------------

    def test_dca_003_constraint_dropped(self) -> None:
        """DCA-003: a child may not drop or loosen a parent constraint (HIGH).

        Two variants, because they are different bugs. **Loosening** a spend cap
        from 1000 to 5000 is visible to any comparison. **Dropping** the key
        entirely is invisible to a comparison that iterates the child's own
        constraints — the loop runs over the wrong collection and finds nothing
        to complain about. Both must deny, and the suite checks each separately
        so a verifier cannot pass by catching only the visible one.
        """
        t0 = time.monotonic()
        now = self._now()
        root = self._root_pass(now)
        parent = self._child_pass(root, "planner2", Authority.of(
            capabilities={"read"}, resources={"env:staging"},
            constraints={"spend_cents": 1000, "calls_per_minute": 60},
            audiences={"tool:ledger"}))

        dropped = self._child_pass(parent, "worker", Authority.of(
            capabilities={"read"}, resources={"env:staging/db:orders"},
            constraints={"calls_per_minute": 30},          # spend cap gone
            audiences={"tool:ledger"}))
        drop_req = EffectRequest.of("req-drop", "worker", "read",
                                    "env:staging/db:orders/row:1", "tool:ledger",
                                    {"spend_cents": 900, "calls_per_minute": 1})
        d_drop = self._boundary().authorize((root, parent, dropped), drop_req, now)

        loosened = self._child_pass(parent, "worker", Authority.of(
            capabilities={"read"}, resources={"env:staging/db:orders"},
            constraints={"spend_cents": 5000, "calls_per_minute": 30},
            audiences={"tool:ledger"}))
        loose_req = EffectRequest.of("req-loose", "worker", "read",
                                     "env:staging/db:orders/row:1", "tool:ledger",
                                     {"spend_cents": 4000, "calls_per_minute": 1})
        d_loose = self._boundary().authorize((root, parent, loosened), loose_req, now)

        # Rate limit, the second constraint, loosened on its own.
        rate = self._child_pass(parent, "worker", Authority.of(
            capabilities={"read"}, resources={"env:staging/db:orders"},
            constraints={"spend_cents": 500, "calls_per_minute": 6000},
            audiences={"tool:ledger"}))
        rate_req = EffectRequest.of("req-rate", "worker", "read",
                                    "env:staging/db:orders/row:1", "tool:ledger",
                                    {"spend_cents": 10, "calls_per_minute": 600})
        d_rate = self._boundary().authorize((root, parent, rate), rate_req, now)

        # POSITIVE CONTROL: both constraints carried through, tightened.
        kept = self._child_pass(parent, "worker", Authority.of(
            capabilities={"read"}, resources={"env:staging/db:orders"},
            constraints={"spend_cents": 500, "calls_per_minute": 30},
            audiences={"tool:ledger"}))
        good_req = EffectRequest.of("req-kept", "worker", "read",
                                    "env:staging/db:orders/row:1", "tool:ledger",
                                    {"spend_cents": 400, "calls_per_minute": 10})
        d_good = self._boundary().authorize((root, parent, kept), good_req, now)

        clause = POLICY["constraint_preserved"]
        clauses_ok = all(d.policy_ref == clause for d in (d_drop, d_loose, d_rate))
        denied = (not d_drop.allowed) and (not d_loose.allowed) \
            and (not d_rate.allowed) and clauses_ok and d_good.allowed
        gaps = []
        if d_drop.allowed:
            gaps.append("DROPPED CONSTRAINT — a child that omitted the parent spend cap "
                        "spent above it")
        if d_loose.allowed:
            gaps.append("LOOSENED CONSTRAINT — a child raised the parent spend cap")
        if d_rate.allowed:
            gaps.append("LOOSENED CONSTRAINT — a child raised the parent rate limit")
        if not gaps and not clauses_ok:
            gaps.append(
                "CONSTRAINT attenuation was refused, but not by the attenuation "
                f"check (clauses: dropped={d_drop.policy_ref!r}, "
                f"loosened={d_loose.policy_ref!r}, rate={d_rate.policy_ref!r}). "
                "The intersection bound the request instead, so the per-hop check "
                "is not shown to be doing anything.")
        self._emit(
            test_id="DCA-003", name="Child Drops or Loosens a Parent Constraint",
            category="attenuation", severity=Severity.HIGH.value,
            owasp="ASI02", stride="Elevation of Privilege",
            denied=denied,
            deny_reason=("; ".join(gaps) if gaps else
                         f"dropped cap denied ({d_drop.reason}); loosened cap denied "
                         f"({d_loose.reason}); loosened rate limit denied "
                         f"({d_rate.reason}) [{d_drop.policy_ref}]"),
            policy_ref=d_drop.policy_ref,
            positive_control=(
                f"the same child carrying BOTH constraints at tighter bounds was "
                f"ALLOWED (receipt {d_good.receipt})" if d_good.allowed else
                f"POSITIVE CONTROL FAILED — a properly constrained child was denied "
                f"({d_good.reason})"),
            attack_chain=(root, parent, dropped), attack_request=drop_req, t0=t0)

    # -- DCA-004: audience mismatch ---------------------------------------

    def test_dca_004_audience_mismatch(self) -> None:
        """DCA-004: a valid pass presented at the wrong tool is not valid (HIGH).

        Nothing is forged. The pass verifies, is unexpired, is properly
        attenuated, and the holder really does hold it. It names ``tool:ledger``
        and is presented at ``tool:mailer``. A verifier that answers "is this
        pass genuine?" says yes; the question is "is this pass genuine *here*".
        """
        t0 = time.monotonic()
        now = self._now()
        root = self._root_pass(now)
        ledger_only = self._child_pass(root, "worker", Authority.of(
            capabilities={"read"}, resources={"env:staging/db:orders"},
            constraints={"spend_cents": 500, "calls_per_minute": 60},
            audiences={"tool:ledger"}))
        chain = (root, ledger_only)
        bad_req = EffectRequest.of("req-aud", "worker", "read",
                                   "env:staging/db:orders/row:1", "tool:mailer",
                                   {"spend_cents": 10, "calls_per_minute": 1})
        d_bad = self._boundary(audience="tool:mailer").authorize(chain, bad_req, now)

        # The other half of the same confusion: the right pass, the right tool,
        # but a request addressed elsewhere. Both must deny.
        d_addr = self._boundary(audience="tool:ledger").authorize(
            chain,
            EffectRequest.of("req-aud2", "worker", "read",
                             "env:staging/db:orders/row:1", "tool:mailer",
                             {"spend_cents": 10, "calls_per_minute": 1}),
            now)

        # And the attenuation form of it: a child that grants ITSELF an audience
        # its parent cannot speak to. Without this, a boundary could enforce
        # audience at presentation and never check it down the chain, so a
        # ledger-only delegate could mint a mailer-scoped child.
        mailer_child = self._child_pass(ledger_only, "sub-worker", Authority.of(
            capabilities={"read"}, resources={"env:staging/db:orders"},
            constraints={"spend_cents": 100, "calls_per_minute": 10},
            audiences={"tool:ledger", "tool:mailer"}))
        d_mint = self._boundary(audience="tool:mailer").authorize(
            (root, ledger_only, mailer_child),
            EffectRequest.of("req-aud3", "sub-worker", "read",
                             "env:staging/db:orders/row:1", "tool:mailer",
                             {"spend_cents": 10, "calls_per_minute": 1}),
            now)

        # POSITIVE CONTROL: the same pass at the audience it names.
        d_good = self._boundary(audience="tool:ledger").authorize(
            chain, self._legit_request(request_id="req-aud-ok"), now)

        denied = ((not d_bad.allowed) and (not d_addr.allowed)
                  and (not d_mint.allowed) and d_good.allowed)
        gaps = []
        if d_bad.allowed:
            gaps.append("AUDIENCE CONFUSION — a ledger-scoped pass authorized an "
                        "effect at the mailer")
        if d_addr.allowed:
            gaps.append("AUDIENCE CONFUSION — a request addressed to another tool was "
                        "executed here")
        if d_mint.allowed:
            gaps.append("AUDIENCE CONFUSION — a ledger-only delegate minted a child "
                        "that spoke to the mailer")
        self._emit(
            test_id="DCA-004", name="Valid Pass Presented to the Wrong Tool Audience",
            category="binding", severity=Severity.HIGH.value,
            owasp="ASI07", stride="Spoofing",
            denied=denied,
            deny_reason=("; ".join(gaps) if gaps else
                         f"wrong-audience presentation denied ({d_bad.reason}) "
                         f"[{d_bad.policy_ref}]; misaddressed request denied "
                         f"({d_addr.reason}); self-granted audience denied "
                         f"({d_mint.reason})"),
            policy_ref=d_bad.policy_ref,
            positive_control=(
                f"the same pass at the audience it names was ALLOWED "
                f"(receipt {d_good.receipt})" if d_good.allowed else
                f"POSITIVE CONTROL FAILED — the in-audience use was denied "
                f"({d_good.reason})"),
            attack_chain=chain, attack_request=bad_req, t0=t0)

    # -- DCA-005: replay ---------------------------------------------------

    def test_dca_005_effect_replay(self) -> None:
        """DCA-005: a replayed effect request yields one effect (HIGH).

        Two acceptable behaviours, and the test accepts either: refuse the
        replay, or return the SAME receipt. What is not acceptable is a second
        effect. The counter is the assertion — a second receipt that happens to
        be byte-identical while the money moved twice would satisfy a
        receipt-only check.
        """
        t0 = time.monotonic()
        now = self._now()
        boundary = self._boundary()
        chain = self._legit_chain(now)
        req = self._legit_request(request_id="req-replay")

        first = boundary.authorize(chain, req, now)
        after_first = boundary.effects_applied
        second = boundary.authorize(chain, req, now)
        after_second = boundary.effects_applied

        idempotent = (second.receipt == first.receipt and second.allowed == first.allowed)
        refused = not second.allowed
        no_second_effect = (after_second == after_first)
        # POSITIVE CONTROL: a genuinely new request on the same chain still works.
        third = boundary.authorize(
            chain, self._legit_request(request_id="req-replay-2"), now)
        distinct_progresses = third.allowed and boundary.effects_applied == after_first + 1

        denied = (first.allowed and no_second_effect and (idempotent or refused)
                  and distinct_progresses)
        self._emit(
            test_id="DCA-005", name="Replayed Effect Request",
            category="replay", severity=Severity.HIGH.value,
            owasp="ASI02", stride="Repudiation",
            denied=denied,
            deny_reason=(
                f"replay returned the first receipt ({second.receipt}) and applied no "
                f"second effect (effects={after_second}) [{second.policy_ref}]"
                if denied else
                (f"REPLAY — the effect was applied {after_second} times for one "
                 f"request identifier" if not no_second_effect else
                 "replay handling is neither idempotent nor a refusal")),
            policy_ref=second.policy_ref,
            positive_control=(
                f"a distinct request on the same chain was ALLOWED and did apply an "
                f"effect (receipt {third.receipt}, effects={boundary.effects_applied})"
                if distinct_progresses else
                "POSITIVE CONTROL FAILED — a distinct request was blocked, so the "
                "replay guard is refusing legitimate traffic"),
            attack_chain=chain, attack_request=req, t0=t0,
            live_verdict=lambda: self._live_replay(chain, req))

    def _live_replay(self, chain, req: EffectRequest):
        """Send the SAME request twice; grade only what the wire can establish.

        There is no interoperable effect counter on this wire, so a second
        allow with a fresh receipt does not establish that a second effect
        occurred -- and does not establish that it did not. That case is
        INCONCLUSIVE, stated. The first allow is never a finding: it is the
        legitimate request this row exists to replay.
        """
        first, _ = self._probe_live(chain, req)
        second, _ = self._probe_live(chain, req)
        d1, d2 = self._target_decision(first), self._target_decision(second)
        sent = {"delegation_chain": [p.as_json() for p in chain],
                "request": req.as_json(), "sent_times": 2}
        # Both observations must have been serviced for ANY verdict here. The
        # composite carries the WORSE of the two statuses so the shared guard
        # sees a failed first request, not only a failed second one.
        s1, s2 = int(first.get("_status") or 0), int(second.get("_status") or 0)
        worst = min(s1, s2) if (s1 and s2) else 0
        response = {"_status": worst, "first": first, "second": second}
        r1, r2 = first.get("receipt"), second.get("receipt")
        if d1 != "allow":
            why = self._decide(first)[1]
            return (False, f"{INCONCLUSIVE_PREFIX}the target did not allow the "
                    "legitimate first request"
                    + (f" ({why})" if why else "")
                    + ", so there is nothing to replay. "
                    "Replay handling is not exercised by this run.",
                    response, sent)
        if d2 == "undecided":
            why = self._decide(second)[1]
            return (False, f"{INCONCLUSIVE_PREFIX}the second presentation produced no "
                    "decision ("
                    + (why if why else "empty body, non-boolean decision, or an "
                       "application error")
                    + "). That is not a refusal; nothing about replay handling "
                    "is established.", response, sent)
        if d2 == "deny":
            return (True, "replay REFUSED by the live target: the second presentation "
                    "of one request identifier was explicitly denied", response, sent)
        # d2 == "allow": a receipt is evidence only if it is a nonempty string.
        if isinstance(r1, str) and r1 and r1 == r2:
            return (True, f"replay was IDEMPOTENT: the live target returned the same "
                    f"receipt ({r1}) for both presentations", response, sent)
        return (False, f"{INCONCLUSIVE_PREFIX}the live target allowed both "
                "presentations" + (f" with different receipts ({r1} vs {r2})"
                                   if isinstance(r1, str) and r1 else
                                   " and returned no usable receipt")
                + ". Whether a second EFFECT occurred cannot be established over "
                "this wire -- there is no effect counter -- so this is not graded "
                "as a replay finding. Run --simulate for the reference-model verdict.",
                response, sent)

    # -- DCA-006: expiry ---------------------------------------------------

    def test_dca_006_expired_pass(self) -> None:
        """DCA-006: a pass used after expiry is denied, with a policy reference (HIGH).

        Checked at two positions, because a chain walker that validates only the
        leaf leaves an expired intermediate in place, and the leaf's own expiry
        can legitimately be earlier than its parent's.

        The denial must name a clause. "Denied" alone leaves an operator unable
        to tell an expired pass from a revoked one, which are different
        incidents: one is a client that needs to re-request, the other is a
        credential someone deliberately voided.
        """
        t0 = time.monotonic()
        now = self._now()
        root = self._root_pass(now)
        leaf = self._child_pass(root, "worker", self._legit_child_authority())
        req = self._legit_request(request_id="req-exp")

        # (a) the leaf itself has expired
        expired_leaf = DelegationPass(
            pass_id="p-worker", issuer="planner", subject="worker",
            authority=self._legit_child_authority(),
            expires_at=now - 1, epoch=0)
        d_leaf = self._boundary().authorize((root, expired_leaf), req, now)

        # (b) an intermediate has expired while the leaf is still in date. A
        #     child may not outlive its parent, so this chain is invalid at
        #     issue; it is denied here for the expiry of the hop above.
        expired_mid = DelegationPass(
            pass_id="p-root", issuer="orchestrator", subject="planner",
            authority=self._root_authority(), expires_at=now - 1, epoch=0)
        short_leaf = DelegationPass(
            pass_id="p-worker", issuer="planner", subject="worker",
            authority=self._legit_child_authority(),
            expires_at=now - 1, epoch=0)
        d_mid = self._boundary().authorize(
            (expired_mid, short_leaf),
            self._legit_request(request_id="req-exp2"), now)

        # (c) a child that outlives its parent is rejected at issue-time shape
        overlong = DelegationPass(
            pass_id="p-worker", issuer="planner", subject="worker",
            authority=self._legit_child_authority(),
            expires_at=root.expires_at + 3600, epoch=0)
        d_over = self._boundary().authorize(
            (root, overlong), self._legit_request(request_id="req-exp3"), now)

        named = bool(d_leaf.policy_ref) and bool(d_mid.policy_ref)
        # POSITIVE CONTROL: one second before expiry the same pass works.
        d_good = self._boundary().authorize(
            (root, leaf), self._legit_request(request_id="req-exp-ok"),
            leaf.expires_at - 1)

        denied = ((not d_leaf.allowed) and (not d_mid.allowed)
                  and (not d_over.allowed) and named and d_good.allowed)
        self._emit(
            test_id="DCA-006", name="Pass Used After Expiry",
            category="lifetime", severity=Severity.HIGH.value,
            owasp="ASI03", stride="Elevation of Privilege",
            denied=denied,
            deny_reason=(
                f"expired leaf denied [{d_leaf.policy_ref}]; expired intermediate "
                f"denied [{d_mid.policy_ref}]; child outliving its parent denied "
                f"({d_over.reason})" if denied else
                ("EXPIRY NOT ENFORCED — an out-of-date pass authorized an effect"
                 if d_leaf.allowed or d_mid.allowed or d_over.allowed else
                 "expiry denials carried no policy reference, so an operator cannot "
                 "tell an expired pass from a revoked one")),
            policy_ref=d_leaf.policy_ref,
            positive_control=(
                f"the same pass one second before expiry was ALLOWED "
                f"(receipt {d_good.receipt})" if d_good.allowed else
                f"POSITIVE CONTROL FAILED — an unexpired pass was denied "
                f"({d_good.reason}); the boundary may be denying on time alone"),
            attack_chain=(root, expired_leaf), attack_request=req, t0=t0)

    # -- DCA-007: revocation epoch ----------------------------------------

    def test_dca_007_revoked_epoch(self) -> None:
        """DCA-007: a pass below the issuer's revocation epoch is void (HIGH).

        Revocation and expiry are separate controls that fail separately. A pass
        can be well inside its validity window and still void, and the whole
        point of an epoch is that it voids passes already in flight whose
        identifiers the issuer never recorded.

        The denial must name a clause distinct from expiry's.
        """
        t0 = time.monotonic()
        now = self._now()
        root = self._root_pass(now, epoch=1)
        leaf = self._child_pass(root, "worker", self._legit_child_authority(), epoch=1)
        chain = (root, leaf)
        req = self._legit_request(request_id="req-rev")

        # The orchestrator bumps its epoch: every pass it issued at epoch 1 dies.
        revoked = self._boundary(revocation_epochs={"orchestrator": 2})
        d_bad = revoked.authorize(chain, req, now)

        # Revoking the intermediate voids the leaf too, not only the hop named.
        mid_revoked = self._boundary(revocation_epochs={"planner": 2})
        d_mid = mid_revoked.authorize(
            chain, self._legit_request(request_id="req-rev2"), now)

        distinct_clause = (d_bad.policy_ref == POLICY["revocation"]
                           and d_bad.policy_ref != POLICY["expiry"])

        # POSITIVE CONTROL 1: same chain, no revocation in force.
        d_good = self._boundary().authorize(
            chain, self._legit_request(request_id="req-rev-ok"), now)
        # POSITIVE CONTROL 2: re-issued at the current epoch after the bump.
        reissued_root = self._root_pass(now, epoch=2)
        reissued_leaf = self._child_pass(
            reissued_root, "worker", self._legit_child_authority(), epoch=2)
        d_reissued = self._boundary(revocation_epochs={"orchestrator": 2}).authorize(
            (reissued_root, reissued_leaf),
            self._legit_request(request_id="req-rev-ok2"), now)

        denied = ((not d_bad.allowed) and (not d_mid.allowed) and distinct_clause
                  and d_good.allowed and d_reissued.allowed)
        self._emit(
            test_id="DCA-007", name="Pass Used After Revocation Epoch",
            category="lifetime", severity=Severity.HIGH.value,
            owasp="ASI03", stride="Elevation of Privilege",
            denied=denied,
            deny_reason=(
                f"revoked chain denied ({d_bad.reason}) [{d_bad.policy_ref}]; "
                f"revoking the intermediate voided the leaf ({d_mid.reason})"
                if (not d_bad.allowed) and (not d_mid.allowed) and distinct_clause else
                ("REVOCATION NOT ENFORCED — a pass below the issuer's revocation "
                 "epoch authorized an effect" if d_bad.allowed or d_mid.allowed else
                 "the revocation denial did not name a clause distinct from expiry")),
            policy_ref=d_bad.policy_ref,
            positive_control=(
                f"the same chain with no revocation in force was ALLOWED "
                f"(receipt {d_good.receipt}), and a chain re-issued at the current "
                f"epoch was ALLOWED after the bump (receipt {d_reissued.receipt})"
                if d_good.allowed and d_reissued.allowed else
                "POSITIVE CONTROL FAILED — an unrevoked or re-issued chain was "
                f"denied (unrevoked: {d_good.reason}; re-issued: {d_reissued.reason})"),
            attack_chain=chain, attack_request=req, t0=t0)

    # -- DCA-008: confused deputy -----------------------------------------

    def test_dca_008_confused_deputy(self) -> None:
        """DCA-008: the tool may not act under its own ambient credential (CRITICAL).

        The boundary holds an ambient authority wide enough to perform the
        request. The request arrives with no chain. The tool must refuse rather
        than fall back on what it can do — the difference between "I am
        permitted to do this" and "the caller is permitted to ask me to".

        Two shapes: no chain at all, and a chain that belongs to somebody else.
        The second is the sharper one, because something *was* presented, so a
        verifier that only checks for presence is satisfied.
        """
        t0 = time.monotonic()
        now = self._now()
        boundary = self._boundary()
        req = self._legit_request(request_id="req-ambient")

        ambient_would_allow = (
            boundary.ambient_authority is not None
            and req.capability in boundary.ambient_authority.capabilities
            and any(resource_within(req.resource, r)
                    for r in boundary.ambient_authority.resources))
        d_none = boundary.authorize((), req, now)
        effects_after_none = boundary.effects_applied

        # A real, valid chain — issued to somebody else.
        other_chain = (self._root_pass(now),
                       self._child_pass(self._root_pass(now), "other-worker",
                                        self._legit_child_authority()))
        d_other = boundary.authorize(
            other_chain,
            EffectRequest.of("req-ambient2", "worker", "read",
                             "env:staging/db:orders/row:1", "tool:ledger",
                             {"spend_cents": 100, "calls_per_minute": 1}),
            now)

        # POSITIVE CONTROL: the same effect, with the caller's own chain.
        d_good = boundary.authorize(
            self._legit_chain(now),
            self._legit_request(request_id="req-ambient-ok"), now)

        denied = (ambient_would_allow and (not d_none.allowed) and (not d_other.allowed)
                  and effects_after_none == 0 and d_good.allowed)
        self._emit(
            test_id="DCA-008", name="Tool Acts Under Ambient Credentials",
            category="confused_deputy", severity=Severity.CRITICAL.value,
            owasp="ASI03", stride="Elevation of Privilege",
            denied=denied,
            deny_reason=(
                f"the boundary holds an ambient credential that would authorize this "
                f"effect and did not use it: contextless request denied "
                f"({d_none.reason}) [{d_none.policy_ref}]; another principal's chain "
                f"denied ({d_other.reason})" if denied else
                ("CONFUSED DEPUTY — the tool performed an effect under its own "
                 "ambient authority" if d_none.allowed or d_other.allowed else
                 "the ambient credential does not cover this effect, so the test "
                 "establishes nothing about fallback")),
            policy_ref=d_none.policy_ref,
            positive_control=(
                f"the same effect presented with the caller's own chain was ALLOWED "
                f"(receipt {d_good.receipt})" if d_good.allowed else
                f"POSITIVE CONTROL FAILED — a properly delegated request was denied "
                f"({d_good.reason})"),
            attack_chain=(), attack_request=req, t0=t0)

    # -- DCA-009: positive control, attenuated child ----------------------

    def test_dca_009_attenuated_child_allowed(self) -> None:
        """DCA-009: a correctly attenuated child is ALLOWED (MEDIUM).

        A standalone positive control. Everything else in this suite asserts a
        refusal, and a suite of refusals is passed in full by a boundary whose
        ``authorize`` is ``return Decision(False, "no")``. This test is the one
        that fails against that boundary.

        It also asserts the receipt is produced and the effect actually applied,
        so "allowed" is a thing that happened rather than a value returned.
        """
        t0 = time.monotonic()
        now = self._now()
        boundary = self._boundary()
        chain = self._legit_chain(now)
        d = boundary.authorize(chain, self._legit_request(), now)

        eff = boundary.effective_authority(chain)
        # The effective authority is the intersection, not the root's.
        intersected = (eff.capabilities == frozenset({"read"})
                       and eff.bounds["spend_cents"] == 500
                       and eff.bounds["calls_per_minute"] == 60)
        applied = boundary.effects_applied == 1

        allowed = d.allowed and bool(d.receipt) and applied and intersected
        self._emit(
            test_id="DCA-009", name="Positive Control: Correctly Attenuated Child",
            category="positive_control", severity=Severity.MEDIUM.value,
            owasp="ASI02", stride="Elevation of Privilege",
            denied=allowed,
            deny_reason=(
                f"a correctly attenuated, in-audience, unexpired child was ALLOWED "
                f"(receipt {d.receipt}); the effective authority is the intersection "
                f"({eff.as_json()}), not the root's" if allowed else
                f"POSITIVE CONTROL FAILED — a legitimate delegated request was "
                f"refused ({d.reason}); a boundary that denies everything cannot be "
                f"shown to be enforcing anything"),
            policy_ref="",
            positive_control=(
                f"allowed={d.allowed}, receipt={d.receipt}, effects_applied="
                f"{boundary.effects_applied}, effective={eff.as_json()}"),
            # Against a live target this row sends the LEGITIMATE chain, so an
            # allow is the pass. Without it a target that denies every request
            # would score a clean sweep on the deny rows.
            attack_chain=chain, attack_request=self._legit_request(), t0=t0,
            live_expect="accept")

    # -- DCA-010: positive control, root's own authority ------------------

    def test_dca_010_root_full_authority_allowed(self) -> None:
        """DCA-010: the parent's own full authority is ALLOWED (MEDIUM).

        The second half of the positive control. DCA-009 shows a narrowed child
        works; this shows the narrowing is not the only thing that works. A
        boundary that has quietly become "deny anything at the root's own
        breadth" would pass DCA-009 and every deny case in the suite.

        The root exercises the widest thing it holds: ``refund`` on production,
        at the top of its own spend cap.
        """
        t0 = time.monotonic()
        now = self._now()
        boundary = self._boundary()
        root = self._root_pass(now)
        wide = EffectRequest.of(
            "req-root", "planner", "refund", "env:production/db:orders/row:9",
            "tool:ledger", {"spend_cents": 100_000, "calls_per_minute": 600})
        d = boundary.authorize((root,), wide, now)

        # And the boundary is still bounded: one cent over the root's own cap
        # is refused. Otherwise "allowed" here would be indistinguishable from
        # a boundary that allows everything.
        over = boundary.authorize(
            (root,),
            EffectRequest.of("req-root-over", "planner", "refund",
                             "env:production/db:orders/row:9", "tool:ledger",
                             {"spend_cents": 100_001, "calls_per_minute": 600}),
            now)

        allowed = d.allowed and bool(d.receipt) and not over.allowed
        self._emit(
            test_id="DCA-010", name="Positive Control: Parent's Own Full Authority",
            category="positive_control", severity=Severity.MEDIUM.value,
            owasp="ASI02", stride="Elevation of Privilege",
            denied=allowed,
            deny_reason=(
                f"the root exercising its own full authority (refund on production at "
                f"its cap) was ALLOWED (receipt {d.receipt}), while one cent above it "
                f"was denied ({over.reason})" if allowed else
                (f"POSITIVE CONTROL FAILED — the root was refused its own authority "
                 f"({d.reason})" if not d.allowed else
                 "the boundary allowed a request above the root's own cap, so DCA-010 "
                 "passing would not distinguish it from an allow-everything boundary")),
            policy_ref="",
            positive_control=(
                f"allowed={d.allowed}, receipt={d.receipt}; over-cap request denied: "
                f"{not over.allowed}"),
            attack_chain=(root,), attack_request=wide, t0=t0,
            live_expect="accept")

    # -- DCA-011: three-hop intersection ----------------------------------

    def test_dca_011_three_hop_intersection(self) -> None:
        """DCA-011: an intermediate may not re-widen what its parent narrowed (CRITICAL).

        The case that makes this a *chain* property rather than a pair property,
        and the reason the per-hop check cannot be replaced by a leaf-versus-root
        check.

            root   caps {read,write,refund}  scope {staging, production}  spend 100000
            mid    caps {read}               scope {staging}              spend 1000
            leaf   caps {read,write}         scope {staging, production}  spend 100000

        The leaf is a strict subset of the ROOT. Every field of it is something
        the root holds. A verifier that validates the presented leaf against the
        chain's origin accepts it, and the audit trail looks clean: an authority
        the root really had, held by a delegate the root really authorized.

        It is still an escalation, because ``mid`` gave up ``write``, production
        and 99% of the spend cap, and nothing downstream of ``mid`` can get them
        back.

        Three assertions, one per way to get this wrong:
          1. the re-widening chain is refused;
          2. the refusal names the hop that widened, not "somewhere";
          3. a well-attenuated three-hop chain is ALLOWED, and its effective
             authority equals the intersection — the mid's bounds, not the
             leaf's declared ones.
        """
        t0 = time.monotonic()
        now = self._now()
        boundary = self._boundary()
        root = self._root_pass(now)
        mid = self._child_pass(root, "mid", Authority.of(
            capabilities={"read"}, resources={"env:staging"},
            constraints={"spend_cents": 1000, "calls_per_minute": 60},
            audiences={"tool:ledger"}))
        rewidened = self._child_pass(mid, "leaf", Authority.of(
            capabilities={"read", "write"},
            resources={"env:staging", "env:production"},
            constraints={"spend_cents": 100_000, "calls_per_minute": 600},
            audiences={"tool:ledger"}))
        bad_chain = (root, mid, rewidened)
        bad_req = EffectRequest.of("req-3hop", "leaf", "write",
                                   "env:production/db:orders/row:1", "tool:ledger",
                                   {"spend_cents": 50_000, "calls_per_minute": 300})
        d_bad = boundary.authorize(bad_chain, bad_req, now)

        # (1a) the leaf really is within the ROOT — so a leaf-vs-root verifier
        #      would have accepted this chain. Asserting it makes the test about
        #      the chain property rather than about an obviously bad leaf.
        leaf_within_root, _, _ = narrows(rewidened.authority, root.authority)
        # (2) the denial names hop 2, the one that widened.
        names_the_hop = "hop 2" in d_bad.reason

        # (3) POSITIVE CONTROL: a well-attenuated three-hop chain.
        leaf_ok = self._child_pass(mid, "leaf", Authority.of(
            capabilities={"read"}, resources={"env:staging/db:orders"},
            constraints={"spend_cents": 200, "calls_per_minute": 30},
            audiences={"tool:ledger"}))
        good_chain = (root, mid, leaf_ok)
        good_boundary = self._boundary()
        d_good = good_boundary.authorize(
            good_chain,
            EffectRequest.of("req-3hop-ok", "leaf", "read",
                             "env:staging/db:orders/row:1", "tool:ledger",
                             {"spend_cents": 150, "calls_per_minute": 10}),
            now)
        eff = good_boundary.effective_authority(good_chain)
        is_intersection = (eff.capabilities == frozenset({"read"})
                           and eff.bounds["spend_cents"] == 200
                           and eff.bounds["calls_per_minute"] == 30
                           and eff.resources == frozenset({"env:staging/db:orders"}))
        # And the intersection actually bounds: a request the LEAF alone would
        # permit but the MID would not is refused on the well-formed chain.
        d_over_mid = good_boundary.authorize(
            good_chain,
            EffectRequest.of("req-3hop-over", "leaf", "read",
                             "env:staging/db:orders/row:1", "tool:ledger",
                             {"spend_cents": 900, "calls_per_minute": 10}),
            now)

        denied = ((not d_bad.allowed) and leaf_within_root and names_the_hop
                  and d_good.allowed and is_intersection and not d_over_mid.allowed)
        if denied:
            reason = (f"an intermediate's narrowing held: leaf is within the root "
                      f"({leaf_within_root}) yet the chain was refused at the hop that "
                      f"re-widened it ({d_bad.reason}) [{d_bad.policy_ref}]")
        elif d_bad.allowed:
            reason = ("CHAIN GAP — an intermediate hop's narrowing was undone "
                      "downstream and the effect was authorized")
        elif not leaf_within_root:
            reason = ("the fixture is wrong: the leaf is not within the root, so a "
                      "leaf-versus-root verifier would also have refused it and this "
                      "test does not isolate the chain property")
        elif not names_the_hop:
            reason = (f"the chain was refused but the denial did not name the widening "
                      f"hop: {d_bad.reason!r}")
        else:
            reason = ("the deny half held; see the positive control, which did not")
        self._emit(
            test_id="DCA-011",
            name="Three-Hop Chain: Intermediate Re-Widens What Its Parent Narrowed",
            category="attenuation", severity=Severity.CRITICAL.value,
            owasp="ASI03", stride="Elevation of Privilege",
            denied=denied, deny_reason=reason, policy_ref=d_bad.policy_ref,
            positive_control=(
                f"a well-attenuated three-hop chain was ALLOWED (receipt "
                f"{d_good.receipt}); its effective authority equals the intersection "
                f"{eff.as_json()}, and a request inside the leaf's declared bound but "
                f"above the intersection was refused ({d_over_mid.reason})"
                if d_good.allowed and is_intersection and not d_over_mid.allowed else
                f"POSITIVE CONTROL FAILED — allowed={d_good.allowed} "
                f"({d_good.reason}); intersection_correct={is_intersection}; "
                f"over-intersection refused={not d_over_mid.allowed}"),
            attack_chain=bad_chain, attack_request=bad_req, t0=t0)

    # -- run_all ----------------------------------------------------------

    def run_all(self) -> list:
        tests = [
            self.test_dca_001_capability_escalation,
            self.test_dca_002_resource_widening,
            self.test_dca_003_constraint_dropped,
            self.test_dca_004_audience_mismatch,
            self.test_dca_005_effect_replay,
            self.test_dca_006_expired_pass,
            self.test_dca_007_revoked_epoch,
            self.test_dca_008_confused_deputy,
            self.test_dca_009_attenuated_child_allowed,
            self.test_dca_010_root_full_authority_allowed,
            self.test_dca_011_three_hop_intersection,
        ]
        print(f"\n{'='*60}")
        print("MULTI-HOP DELEGATED-AUTHORITY ATTENUATION SUITE")
        print(f"{'='*60}")
        print(f"Target: {self.url or '(none — reference model)'}")
        print(f"Mode: {'simulate (reference model)' if self.simulate else 'live'}")
        print("Property: a child's authority is provably no broader than its "
              "parent's, enforced at the tool boundary")
        print("\n[DELEGATION CHAIN ATTENUATION TESTS]")
        for fn in tests:
            try:
                fn()
            except Exception as e:  # pragma: no cover - defensive
                print(f"  ERROR  {fn.__name__}: {e}")
                self.results.append(DelegationResult(
                    test_id="DCA-ERR", name=f"Error: {fn.__name__}",
                    owasp_asi="ASI03", severity=Severity.HIGH.value,
                    passed=False, details=f"harness error: {e}",
                    category="error", stride="Elevation of Privilege",
                    not_evaluated=True,
                    verdict_scope="harness error — nothing was established"))
        summary = run_summary(self.results)
        print(f"\n{'='*60}")
        for line in summary_lines(summary):
            print(line)
        print(f"{'='*60}\n")
        return self.results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Multi-hop delegated-authority attenuation harness (DCA-001..DCA-011)")
    ap.add_argument("--url", default=None,
                    help="Target endpoint that adjudicates a delegation chain (live mode)")
    ap.add_argument("--simulate", action="store_true",
                    help="Run against the built-in reference model (no network)")
    ap.add_argument("--report", help="Output JSON report path")
    ap.add_argument("--json", action="store_true", help="Emit JSON summary to stdout")
    ap.add_argument("--header", action="append", default=[],
                    help="Extra HTTP headers (key:value)")
    args = ap.parse_args()

    headers: dict = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    simulate = args.simulate or not args.url
    suite = DelegationChainTests(url=args.url, headers=headers, simulate=simulate)
    with json_stdout_only(args.json):
        results = suite.run_all()

    summary = run_summary(results)
    report = {
        "suite": "Multi-Hop Delegated-Authority Attenuation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "simulate" if simulate else "live",
        # In simulate mode the verdicts are about the reference model in this
        # file, so there is no subject to name -- `subject_none()` says that
        # rather than leaving the field absent, which would be indistinguishable
        # from a live run whose target went unrecorded.
        "provenance": run_provenance(),
        "subject": subject_none() if simulate else subject_http(args.url),
        "status": summary["status"],
        "summary": summary,
        "results": [asdict(r) for r in results],
    }

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    if args.report:
        with open(args.report, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"Report written to {args.report}", file=sys.stderr)

    sys.exit(1 if any(not r.passed for r in results) else 0)


if __name__ == "__main__":
    main()
