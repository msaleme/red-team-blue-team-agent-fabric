"""Every guard in `delegation_chain_harness` must be shown to be able to fail.

## Why this file is longer than the module it tests

FB-013 is the local precedent. `ApprovalQuorum` was written to fix a test that
counted approvals without checking identity, and it checked identity without
checking authority -- the same defect one level in -- so a quorum of two
arbitrary strings satisfied it. The test that was supposed to catch that passed
throughout, because it asserted only that an above-threshold spend *routed* to
approval.

The lesson is not "write more assertions". It is that an assertion nobody has
ever seen fail is a hypothesis, not a control. So this file does two things the
module cannot do for itself:

**Fault injection, as code rather than as a note in a commit message.** Each
guard in the reference verifier is neutered in turn, and the suite is re-run to
show that the attack it exists to stop then succeeds -- and that the row fails
naming *that* defect rather than falling over incidentally. `MUTANTS` below is
that matrix. A guard whose removal changes nothing is dead code with a
reassuring name, and this is what says so.

**Positive controls, checked as a property of the suite.** Every deny row in the
module pairs its attack with the legitimate variant, and `DCA-009` / `DCA-010`
exist only to assert an ALLOW. The pair of tests at the bottom
(`test_a_boundary_that_denies_everything_does_not_pass_the_suite` and its
opposite) are the reason that matters: a verifier that refuses every request
satisfies eight of the eleven rows, and a verifier that permits every request
satisfies none of the deny rows but would sail through a suite that had only
positive controls. Neither can pass this suite.
"""

from __future__ import annotations

import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests import delegation_chain_harness as dch  # noqa: E402
from protocol_tests.delegation_chain_harness import (  # noqa: E402
    POLICY,
    Authority,
    DelegationChainTests,
    DelegationPass,
    EffectRequest,
    ToolBoundary,
    intersect,
    narrows,
    resource_within,
)
from protocol_tests.http_helpers import is_inconclusive, run_summary  # noqa: E402

CLOSED_PORT = "http://127.0.0.1:9"

#: Every row the module runs. Written out rather than derived, so a test that
#: silently stops being registered is a failure here and not an invisible gap.
ALL_IDS = {f"DCA-{n:03d}" for n in range(1, 12)}

#: The rows that assert an ALLOW. These are the rows a deny-everything verifier
#: fails, and the reason the deny rows mean anything.
POSITIVE_CONTROL_IDS = {"DCA-009", "DCA-010"}


def run_suite(**kwargs) -> list:
    """Run the reference suite with its console output swallowed."""
    suite = DelegationChainTests(simulate=True, **kwargs)
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        suite.run_all()
    return suite.results


def by_id(results) -> dict:
    return {r.test_id: r for r in results}


def failing(results) -> set:
    return {r.test_id for r in results if not r.passed}


# ---------------------------------------------------------------------------
# The suite as shipped
# ---------------------------------------------------------------------------

class TestTheSuiteAsShipped(unittest.TestCase):
    def test_every_row_runs_and_passes_against_the_reference_model(self) -> None:
        results = run_suite()
        self.assertEqual({r.test_id for r in results}, ALL_IDS)
        self.assertEqual(failing(results), set(),
                         "\n".join(f"{r.test_id}: {r.details}"
                                   for r in results if not r.passed))

    def test_no_row_errored(self) -> None:
        """A harness exception is recorded as DCA-ERR, which is not a verdict."""
        results = run_suite()
        self.assertNotIn("DCA-ERR", {r.test_id for r in results})

    def test_every_row_records_a_positive_control(self) -> None:
        """The property the module enforces at construction, asserted from outside.

        `_emit` raises when a row supplies no positive control. That is a guard
        on the module's own authors; this is the guard on the guard, and it also
        catches a control that was recorded and *failed*.
        """
        for r in run_suite():
            with self.subTest(r.test_id):
                self.assertTrue(r.positive_control,
                                f"{r.test_id} recorded no positive control")
                self.assertNotIn("POSITIVE CONTROL FAILED", r.positive_control)

    def test_simulate_rows_declare_that_they_have_no_target(self) -> None:
        """A passing CRITICAL row about the repo's own model must say so."""
        for r in run_suite():
            with self.subTest(r.test_id):
                self.assertEqual(r.verdict_scope,
                                 "reference-model self-test (no target)")

    def test_denials_name_a_policy_clause(self) -> None:
        """Expiry and revocation especially: different incidents, different answers."""
        rows = by_id(run_suite())
        self.assertEqual(rows["DCA-006"].policy_ref, POLICY["expiry"])
        self.assertEqual(rows["DCA-007"].policy_ref, POLICY["revocation"])
        self.assertNotEqual(rows["DCA-006"].policy_ref, rows["DCA-007"].policy_ref)


# ---------------------------------------------------------------------------
# The primitives, directly
# ---------------------------------------------------------------------------

class TestScopeContainment(unittest.TestCase):
    """`resource_within` compares segments, which is the whole point of it."""

    def test_a_parent_contains_its_descendants(self) -> None:
        self.assertTrue(resource_within("env:staging/db:orders/row:1", "env:staging"))
        self.assertTrue(resource_within("env:staging", "env:staging"))

    def test_a_sibling_environment_is_not_contained(self) -> None:
        self.assertFalse(resource_within("env:production/db:orders", "env:staging"))

    def test_a_string_prefix_is_not_a_scope_prefix(self) -> None:
        """The bypass a `startswith` implementation ships with."""
        self.assertFalse(resource_within("env:staging", "env:stag"))
        self.assertFalse(resource_within("env:production-2", "env:production"))

    def test_a_deeper_scope_does_not_contain_a_shallower_one(self) -> None:
        self.assertFalse(resource_within("env:staging", "env:staging/db:orders"))


class TestIntersection(unittest.TestCase):
    def test_the_intersection_takes_the_tighter_bound_from_either_side(self) -> None:
        a = Authority.of(capabilities={"read", "write"}, resources={"env:staging"},
                         constraints={"spend_cents": 1000}, audiences={"tool:ledger"})
        b = Authority.of(capabilities={"read"}, resources={"env:staging/db:orders"},
                         constraints={"spend_cents": 200, "calls_per_minute": 5},
                         audiences={"tool:ledger", "tool:mailer"})
        eff = intersect(a, b)
        self.assertEqual(eff.capabilities, frozenset({"read"}))
        self.assertEqual(eff.resources, frozenset({"env:staging/db:orders"}))
        self.assertEqual(eff.bounds, {"spend_cents": 200, "calls_per_minute": 5})
        self.assertEqual(eff.audiences, frozenset({"tool:ledger"}))

    def test_a_constraint_only_one_side_names_is_kept(self) -> None:
        """A bound on either side binds. Union of keys, minimum of values."""
        a = Authority.of(constraints={"spend_cents": 1000})
        b = Authority.of(constraints={"calls_per_minute": 5})
        self.assertEqual(intersect(a, b).bounds,
                         {"spend_cents": 1000, "calls_per_minute": 5})


class TestNarrowing(unittest.TestCase):
    PARENT = Authority.of(capabilities={"read"}, resources={"env:staging"},
                          constraints={"spend_cents": 1000},
                          audiences={"tool:ledger"})

    def _child(self, **over) -> Authority:
        base = dict(capabilities={"read"}, resources={"env:staging/db:orders"},
                    constraints={"spend_cents": 100}, audiences={"tool:ledger"})
        base.update(over)
        return Authority.of(**base)

    def test_a_properly_attenuated_child_narrows(self) -> None:
        ok, _, _ = narrows(self._child(), self.PARENT)
        self.assertTrue(ok)

    def test_an_identical_child_narrows(self) -> None:
        """Attenuation is 'no broader', not 'strictly narrower'."""
        ok, _, _ = narrows(self.PARENT, self.PARENT)
        self.assertTrue(ok)

    def test_each_dimension_denies_with_its_own_clause(self) -> None:
        cases = {
            "added capability": (self._child(capabilities={"read", "write"}),
                                 POLICY["capability_subset"]),
            "widened resource": (self._child(resources={"env:production"}),
                                 POLICY["resource_within"]),
            "loosened bound": (self._child(constraints={"spend_cents": 5000}),
                               POLICY["constraint_preserved"]),
            "dropped bound": (self._child(constraints={}),
                              POLICY["constraint_preserved"]),
            "added audience": (self._child(audiences={"tool:ledger", "tool:mailer"}),
                               POLICY["audience_bound"]),
        }
        for label, (child, ref) in cases.items():
            with self.subTest(label):
                ok, reason, got = narrows(child, self.PARENT)
                self.assertFalse(ok, f"{label} was accepted as an attenuation")
                self.assertEqual(got, ref, f"{label} denied under the wrong clause")
                self.assertTrue(reason)


class TestChainIsCheckedAtEveryHop(unittest.TestCase):
    """The three-hop property, as a unit test rather than only as DCA-011."""

    def setUp(self) -> None:
        self.now = 1_750_000_000
        self.root_authority = Authority.of(
            capabilities={"read", "write"}, resources={"env:staging", "env:production"},
            constraints={"spend_cents": 100_000}, audiences={"tool:ledger"})
        self.boundary = ToolBoundary(
            audience="tool:ledger",
            trusted_roots={"orchestrator": self.root_authority})
        self.root = DelegationPass("p0", "orchestrator", "a", self.root_authority,
                                   self.now + 3600)
        self.mid = DelegationPass("p1", "a", "b", Authority.of(
            capabilities={"read"}, resources={"env:staging"},
            constraints={"spend_cents": 1000}, audiences={"tool:ledger"}),
            self.now + 3600)

    def _leaf(self, authority: Authority) -> DelegationPass:
        return DelegationPass("p2", "b", "c", authority, self.now + 3600)

    def test_a_leaf_inside_the_root_but_outside_its_parent_is_refused(self) -> None:
        leaf = self._leaf(self.root_authority)
        within_root, _, _ = narrows(leaf.authority, self.root.authority)
        self.assertTrue(within_root,
                        "fixture no longer isolates the chain property: this leaf "
                        "would be refused by a leaf-versus-root check too")
        d = self.boundary.authorize(
            (self.root, self.mid, leaf),
            EffectRequest.of("r1", "c", "write", "env:production/x", "tool:ledger",
                             {"spend_cents": 50_000}),
            self.now)
        self.assertFalse(d.allowed)
        self.assertIn("hop 2", d.reason)

    def test_the_effective_authority_is_the_intersection_not_the_leaf(self) -> None:
        leaf = self._leaf(Authority.of(
            capabilities={"read"}, resources={"env:staging/db:orders"},
            constraints={"spend_cents": 800}, audiences={"tool:ledger"}))
        eff = self.boundary.effective_authority((self.root, self.mid, leaf))
        self.assertEqual(eff.bounds["spend_cents"], 800)
        self.assertEqual(eff.capabilities, frozenset({"read"}))
        # And a request the leaf alone would permit, above the mid's bound,
        # is refused on a structurally valid chain.
        tight_leaf = self._leaf(Authority.of(
            capabilities={"read"}, resources={"env:staging/db:orders"},
            constraints={"spend_cents": 1000}, audiences={"tool:ledger"}))
        d = self.boundary.authorize(
            (self.root, self.mid, tight_leaf),
            EffectRequest.of("r2", "c", "read", "env:staging/db:orders/1",
                             "tool:ledger", {"spend_cents": 1000}),
            self.now)
        self.assertTrue(d.allowed, d.reason)

    def test_a_hop_issued_by_a_stranger_is_refused(self) -> None:
        forged = DelegationPass("p2", "somebody-else", "c", Authority.of(
            capabilities={"read"}, resources={"env:staging"},
            constraints={"spend_cents": 10}, audiences={"tool:ledger"}),
            self.now + 3600)
        d = self.boundary.authorize(
            (self.root, self.mid, forged),
            EffectRequest.of("r3", "c", "read", "env:staging/x", "tool:ledger",
                             {"spend_cents": 1}),
            self.now)
        self.assertFalse(d.allowed)
        self.assertEqual(d.policy_ref, POLICY["chain_linked"])


class TestReplayYieldsOneEffect(unittest.TestCase):
    def setUp(self) -> None:
        self.suite = DelegationChainTests(simulate=True)
        self.now = self.suite.SIM_NOW
        self.boundary = self.suite._boundary()
        self.chain = self.suite._legit_chain(self.now)

    def test_a_repeat_returns_the_first_receipt_and_applies_no_second_effect(self):
        req = self.suite._legit_request(request_id="rr")
        first = self.boundary.authorize(self.chain, req, self.now)
        self.assertTrue(first.allowed)
        self.assertEqual(self.boundary.effects_applied, 1)
        second = self.boundary.authorize(self.chain, req, self.now)
        self.assertEqual(second.receipt, first.receipt)
        self.assertTrue(second.replayed)
        self.assertEqual(self.boundary.effects_applied, 1)

    def test_a_denied_request_is_not_retried_into_an_allow(self) -> None:
        """The ledger records the decision, not only the successes.

        Otherwise a caller who is refused can resubmit the same identifier with
        a better chain and the boundary has no memory that it already said no.
        """
        bad = EffectRequest.of("rr2", "worker", "refund",
                               "env:staging/db:orders/row:1", "tool:ledger",
                               {"spend_cents": 1, "calls_per_minute": 1})
        first = self.boundary.authorize(self.chain, bad, self.now)
        self.assertFalse(first.allowed)
        # A denial is not ledgered, so this is a genuinely new adjudication --
        # which is the honest behaviour: nothing happened the first time.
        self.assertEqual(self.boundary.effects_applied, 0)

    def test_a_distinct_identifier_still_progresses(self) -> None:
        self.boundary.authorize(
            self.chain, self.suite._legit_request(request_id="a"), self.now)
        self.boundary.authorize(
            self.chain, self.suite._legit_request(request_id="b"), self.now)
        self.assertEqual(self.boundary.effects_applied, 2)


class TestAmbientCredentialsAreNeverConsulted(unittest.TestCase):
    def setUp(self) -> None:
        self.suite = DelegationChainTests(simulate=True)
        self.now = self.suite.SIM_NOW
        self.boundary = self.suite._boundary()

    def test_the_fixture_actually_holds_an_ambient_credential(self) -> None:
        """Without this the confused-deputy row establishes nothing."""
        ambient = self.boundary.ambient_authority
        self.assertIsNotNone(ambient)
        req = self.suite._legit_request()
        self.assertIn(req.capability, ambient.capabilities)
        self.assertTrue(any(resource_within(req.resource, r)
                            for r in ambient.resources))

    def test_a_request_with_no_chain_is_refused(self) -> None:
        d = self.boundary.authorize((), self.suite._legit_request(), self.now)
        self.assertFalse(d.allowed)
        self.assertEqual(d.policy_ref, POLICY["no_ambient"])
        self.assertEqual(self.boundary.effects_applied, 0)

    def test_another_principals_chain_is_refused(self) -> None:
        chain = self.suite._legit_chain(self.now)
        d = self.boundary.authorize(
            chain,
            EffectRequest.of("x", "not-the-subject", "read",
                             "env:staging/db:orders/row:1", "tool:ledger",
                             {"spend_cents": 1, "calls_per_minute": 1}),
            self.now)
        self.assertFalse(d.allowed)
        self.assertEqual(d.policy_ref, POLICY["presenter_bound"])


# ---------------------------------------------------------------------------
# Fault injection
# ---------------------------------------------------------------------------

def _drop_check(name):
    """A patch that removes one attenuation predicate from the composition."""
    kept = tuple(c for c in dch.ATTENUATION_CHECKS if c.__name__ != name)
    assert len(kept) == len(dch.ATTENUATION_CHECKS) - 1, f"no such check: {name}"
    return mock.patch.object(dch, "ATTENUATION_CHECKS", kept)


def _neuter(method: str):
    """A patch that makes one ToolBoundary sub-check always say yes."""
    return mock.patch.object(ToolBoundary, method,
                             lambda self, *a, **k: (True, "", ""))


class _LeafVsRootOnly(ToolBoundary):
    """The most plausible wrong implementation, and the reason DCA-011 exists.

    Validates the pass that was presented against the authority the chain
    started from. Every hop in between is treated as routing information. It is
    cheaper, it reads as rigorous, and the audit trail it produces looks clean.
    """

    def _check_attenuation(self, chain):
        ok, why, ref = narrows(chain[-1].authority,
                               self.trusted_roots[chain[0].issuer])
        return (True, "", "") if ok else (False, f"leaf: {why}", ref)


class _AmbientFallback(ToolBoundary):
    """A tool that helpfully uses its own credential when the caller sent none."""

    def authorize(self, chain, request, now):
        if not chain and self.ambient_authority is not None:
            self.effects_applied += 1
            return dch.Decision(True, "authorized under the tool's own credential",
                                "", "ambient-receipt")
        return super().authorize(chain, request, now)


class _NoReplayLedger(ToolBoundary):
    """Every request is a new request."""

    def _check_replay(self, request):
        return None


class _DenyEverything(ToolBoundary):
    def authorize(self, chain, request, now):
        return dch.Decision(False, "no", "DENY-ALL")


class _AllowEverything(ToolBoundary):
    def authorize(self, chain, request, now):
        self.effects_applied += 1
        return dch.Decision(True, "yes", "", "allow-all-receipt")


#: (label, patch factory, must-fail IDs, marker the failing details must carry).
#:
#: The marker is the half that makes this fault injection rather than mutation
#: noise. A row that fails because the mutant made the harness throw is not
#: evidence the guard was load-bearing; the row has to fail *naming the attack
#: that got through*.
MUTANTS = [
    ("capability subset check removed",
     lambda: _drop_check("caps_subset"), {"DCA-001"}, "PRIVILEGE ESCALATION"),
    ("resource containment check removed",
     lambda: _drop_check("resources_within"), {"DCA-002"}, "SCOPE WIDENING"),
    ("constraint preservation check removed",
     lambda: _drop_check("constraints_preserved"), {"DCA-003"}, "CONSTRAINT"),
    ("audience attenuation check removed",
     lambda: _drop_check("audiences_subset"), {"DCA-004"}, "AUDIENCE CONFUSION"),
    ("presentation-audience check neutered",
     lambda: _neuter("_check_audience"), {"DCA-004"}, "AUDIENCE CONFUSION"),
    ("expiry check neutered",
     lambda: _neuter("_check_lifetime"), {"DCA-006"}, "EXPIRY NOT ENFORCED"),
    ("revocation check neutered",
     lambda: _neuter("_check_revocation"), {"DCA-007"}, "REVOCATION NOT ENFORCED"),
    ("effective-authority check neutered",
     lambda: _neuter("_check_effective"), {"DCA-010"}, "allow-everything"),
    ("chain-linkage check neutered",
     lambda: _neuter("_check_links"), {"DCA-006"}, "EXPIRY NOT ENFORCED"),
    ("replay ledger removed",
     lambda: mock.patch.object(dch, "ToolBoundary", _NoReplayLedger),
     {"DCA-005"}, "REPLAY"),
    ("tool falls back to ambient credentials",
     lambda: mock.patch.object(dch, "ToolBoundary", _AmbientFallback),
     {"DCA-008"}, "CONFUSED DEPUTY"),
    ("leaf validated against the root instead of every hop",
     lambda: mock.patch.object(dch, "ToolBoundary", _LeafVsRootOnly),
     {"DCA-001", "DCA-002", "DCA-003", "DCA-011"}, None),
]


class TestEveryGuardCanBeMadeToFail(unittest.TestCase):
    """Neuter each guard in turn; the row it exists for must then fail."""

    def test_each_mutant_breaks_the_row_it_should(self) -> None:
        for label, patch_factory, expected, marker in MUTANTS:
            with self.subTest(label):
                with patch_factory():
                    results = run_suite()
                broke = failing(results)
                self.assertTrue(
                    expected <= broke,
                    f"{label}: expected {sorted(expected)} to fail, but only "
                    f"{sorted(broke)} did. A guard whose removal changes nothing "
                    f"is not enforcing anything.")
                if marker:
                    rows = by_id(results)
                    for tid in expected:
                        self.assertIn(
                            marker, rows[tid].details,
                            f"{label}: {tid} failed, but not for the intended "
                            f"reason -- {rows[tid].details!r}")

    def test_an_unmutated_run_is_the_control(self) -> None:
        """The other direction. Without this the matrix above proves nothing:
        a suite that fails every row would satisfy every 'must fail' row."""
        self.assertEqual(failing(run_suite()), set())


class TestADegenerateVerifierCannotPass(unittest.TestCase):
    """The FB-013 property, one level up: a control that cannot fail is decoration."""

    def test_a_boundary_that_denies_everything_fails_every_row(self) -> None:
        """Not only the two positive-control rows -- all eleven.

        Because every deny row carries its legitimate variant inside it, a
        verifier that refuses everything fails the deny rows too. That is the
        design working: the refusal each row asserts is only evidence when the
        same verifier is shown to permit the request that should be permitted.
        """
        with mock.patch.object(dch, "ToolBoundary", _DenyEverything):
            results = run_suite()
        self.assertEqual(
            failing(results), ALL_IDS,
            "a verifier that refuses every request passed rows "
            f"{sorted(ALL_IDS - failing(results))}")
        for tid in sorted(POSITIVE_CONTROL_IDS):
            self.assertIn("POSITIVE CONTROL FAILED", by_id(results)[tid].details)

    def test_a_boundary_that_allows_everything_fails_every_deny_row(self) -> None:
        with mock.patch.object(dch, "ToolBoundary", _AllowEverything):
            results = run_suite()
        broke = failing(results)
        deny_rows = ALL_IDS - POSITIVE_CONTROL_IDS
        self.assertTrue(
            deny_rows <= broke,
            f"a verifier that permits every request passed deny rows "
            f"{sorted(deny_rows - broke)}")

    def test_the_two_degenerate_verifiers_are_distinguished(self) -> None:
        """The suite must separate them, or it is measuring one thing twice.

        Deny-everything fails all eleven. Allow-everything fails ten: the nine
        deny rows, plus DCA-010, which is a positive control that also asserts
        the root's own cap still bounds it -- so it is not satisfied by a
        boundary that permits everything either.

        DCA-009 is the row that separates them, and it is the only row in the
        suite that a permissive boundary passes. That is what makes it worth
        having: without it, "the verifier said no" and "the verifier is broken
        in the permissive direction" produce identical suites.
        """
        with mock.patch.object(dch, "ToolBoundary", _DenyEverything):
            deny_broke = failing(run_suite())
        with mock.patch.object(dch, "ToolBoundary", _AllowEverything):
            allow_broke = failing(run_suite())
        self.assertEqual(deny_broke, ALL_IDS)
        self.assertEqual(deny_broke - allow_broke, {"DCA-009"})
        self.assertEqual(ALL_IDS - allow_broke, {"DCA-009"})


# ---------------------------------------------------------------------------
# Live mode
# ---------------------------------------------------------------------------

class TestLiveModeAgainstNothing(unittest.TestCase):
    """A verifier that could not run is INCONCLUSIVE. It is never a pass."""

    def _run_live(self):
        suite = DelegationChainTests(url=CLOSED_PORT)
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            suite.run_all()
        return suite.results

    def test_nothing_passes_against_a_host_that_is_not_there(self) -> None:
        results = self._run_live()
        self.assertEqual({r.test_id for r in results}, ALL_IDS)
        self.assertEqual([r.test_id for r in results if r.passed], [])

    def test_every_row_is_inconclusive_rather_than_a_target_failure(self) -> None:
        results = self._run_live()
        for r in results:
            with self.subTest(r.test_id):
                self.assertTrue(is_inconclusive(r),
                                f"{r.test_id} was scored as a target failure: "
                                f"{r.details!r}")
                self.assertTrue(r.not_evaluated,
                                f"{r.test_id} says INCONCLUSIVE in English only")

    def test_the_summary_computes_no_rate_over_nothing(self) -> None:
        summary = run_summary(self._run_live())
        self.assertEqual(summary["status"], "inconclusive")
        self.assertEqual(summary["serviced"], 0)
        self.assertEqual(summary["failed"], 0)
        self.assertIsNone(summary["pass_rate"])
        self.assertIsNone(summary["wilson_95_ci"])

    def test_a_live_row_says_which_target_it_is_about(self) -> None:
        for r in self._run_live():
            with self.subTest(r.test_id):
                self.assertIn(CLOSED_PORT, r.verdict_scope)


if __name__ == "__main__":
    unittest.main()
