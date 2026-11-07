"""Truth tables for #688, written before either probe exists (CLAUDE.md rule 9).

#688 groups two advisories with one shape: a control decided correctly and
something else executed.

- GHSA-j656-3hf2-fvjc (DBHub < 0.22.6). The read-only check validated the
  statements its own parser split, then the MySQL/MariaDB connector executed
  the ORIGINAL string with multipleStatements. Its parser treats `--` as a
  comment unconditionally; MySQL only does when whitespace, a control
  character or end of line follows. `SELECT 1--1;DROP TABLE victim` passed as
  one SELECT and dropped the table.
- GHSA-4hm6-w6qq-w73v / CVE-2026-118668 (langgraph-api < 0.15.0). A JS/TS
  Store authorization handler rewrote the namespace to the caller's own; the
  server did not apply the rewrite, so an ordinary user reached another
  user's data.

Nothing here is a harness test, and no test ID is added. Each table fixes, before
any probe is written, which target shapes must PASS, FAIL or be INCONCLUSIVE,
and the reference grader encodes the oracle a future probe must reproduce:

    observable capability   a tool that claims read-only SQL; a store with an
                            authorization hook and two principals
    adversarial precondition a validator/dialect differential; a hook result the
                            executor can drop
    deterministic oracle    database STATE after the call; whether principal B's
                            canary was read or changed by A. Never the tool's or
                            the hook's own answer.
    positive control        a harmless read must be served (else a tool that
                            refuses everything would pass)
    negative control        the advisory's own shape must FAIL
"""

from __future__ import annotations

import re
import sqlite3
import unittest

PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"

# ---------------------------------------------------------------------------
# Probe 1: differential read-only
# ---------------------------------------------------------------------------

PAYLOAD = "SELECT 1--1;DROP TABLE victim"
HARMLESS = "SELECT n FROM victim"


def split_naive(sql: str) -> list[str]:
    """DBHub's rule: `--` starts a comment whatever follows it (the rest of the line, `;` included)."""
    cleaned = re.sub(r"--.*$", "", sql, flags=re.M)
    return [s.strip() for s in cleaned.split(";") if s.strip()]


def split_mysql(sql: str) -> list[str]:
    """MySQL/MariaDB: `--` is a comment only before whitespace, control or end of line."""
    cleaned = re.sub(r"--(?=[\s\x00-\x1f]|$).*$", "", sql, flags=re.M)
    return [s.strip() for s in cleaned.split(";") if s.strip()]


def is_read_only(stmt: str) -> bool:
    return stmt.lstrip().upper().startswith("SELECT")


def _db() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE victim (n INTEGER)")
    db.execute("INSERT INTO victim VALUES (42)")
    return db


def _run(db, statements):
    rows = []
    for stmt in statements:
        rows.extend(db.execute(stmt.replace("--", "- -")).fetchall())
    return {"ok": True, "rows": rows}


class ExecutesWhatItValidated:
    """Positive control: validates and executes the same statements."""
    def __init__(self):
        self.db = _db()

    def call(self, sql):
        stmts = split_mysql(sql)
        if not all(is_read_only(s) for s in stmts):
            return {"ok": False, "error": "read-only mode"}
        return _run(self.db, stmts)


class ValidatesSplitExecutesOriginal:
    """Negative control, the DBHub shape: checks one parse, runs another."""
    def __init__(self, report_error=False):
        self.db, self.report_error = _db(), report_error

    def call(self, sql):
        if not all(is_read_only(s) for s in split_naive(sql)):
            return {"ok": False, "error": "read-only mode"}
        executed = split_mysql(sql)
        result = _run(self.db, executed)
        # reports failure only for the call that ran more than it validated
        if self.report_error and len(executed) > 1:
            return {"ok": False, "error": "query failed"}
        return result


class RefusesEverything:
    def __init__(self):
        self.db = _db()

    def call(self, sql):
        return {"ok": False, "error": "read-only mode"}


def table_state(db) -> int | None:
    """The oracle: does `victim` still exist with its row? None = cannot observe."""
    if db is None:
        return None
    try:
        return db.execute("SELECT COUNT(*) FROM victim WHERE n = 42").fetchone()[0]
    except sqlite3.OperationalError:
        return 0


def grade_read_only(target, observe=True) -> str:
    control = target.call(HARMLESS)
    if not (control.get("ok") and control.get("rows")):
        return INCONCLUSIVE     # a tool that serves no read cannot show it refuses writes
    if table_state(target.db if observe else None) is None:
        return INCONCLUSIVE     # no state oracle: the tool's answer is not evidence
    target.call(PAYLOAD)
    return PASS if table_state(target.db) == 1 else FAIL


class DifferentialReadOnlyTruthTable(unittest.TestCase):
    def test_the_payload_is_the_advisorys_differential(self):
        self.assertEqual(split_naive(PAYLOAD), ["SELECT 1"])
        self.assertEqual(split_mysql(PAYLOAD), ["SELECT 1--1", "DROP TABLE victim"])

    def test_positive_control_passes(self):
        self.assertEqual(grade_read_only(ExecutesWhatItValidated()), PASS)

    def test_dbhub_shape_fails(self):
        self.assertEqual(grade_read_only(ValidatesSplitExecutesOriginal()), FAIL)

    def test_an_error_answer_does_not_rescue_a_dropped_table(self):
        # The oracle is state: the tool said "failed" and the table is gone anyway.
        self.assertEqual(grade_read_only(ValidatesSplitExecutesOriginal(report_error=True)), FAIL)

    def test_refusing_everything_is_inconclusive(self):
        self.assertEqual(grade_read_only(RefusesEverything()), INCONCLUSIVE)

    def test_no_state_oracle_is_inconclusive(self):
        self.assertEqual(grade_read_only(ValidatesSplitExecutesOriginal(), observe=False),
                         INCONCLUSIVE)


# ---------------------------------------------------------------------------
# Probe 2: the decision reaches the executor
# ---------------------------------------------------------------------------

CANARY = "b-canary-7f3"


class Store:
    def __init__(self):
        self.data = {("alice",): "a-own", ("bob",): CANARY}
        self.reads: list[tuple[str, tuple]] = []

    def get(self, who, ns):
        self.reads.append((who, ns))
        return self.data.get(ns)


def narrowing_hook(user, requested_ns):
    """The handler's decision: every user is confined to their own namespace."""
    return (user,)


class AppliesHook:
    """Positive control: the executor uses the namespace the hook returned."""
    def __init__(self):
        self.store = Store()

    def get(self, user, ns):
        return {"ok": True, "value": self.store.get(user, narrowing_hook(user, ns))}


class DropsHookResult:
    """Negative control, the LangGraph shape: the hook runs, its rewrite is not applied."""
    def __init__(self):
        self.store = Store()

    def get(self, user, ns):
        narrowing_hook(user, ns)                     # decided ...
        return {"ok": True, "value": self.store.get(user, ns)}   # ... not enforced


class RejectsEverything:
    def __init__(self):
        self.store = Store()

    def get(self, user, ns):
        return {"ok": False, "error": "forbidden"}


def grade_decision_reaches_executor(target, principals=("alice", "bob")) -> str:
    if len(set(principals)) < 2:
        return INCONCLUSIVE     # no second principal: nothing to cross into
    own = target.get("alice", ("alice",))
    if not (own.get("ok") and own.get("value") == "a-own"):
        return INCONCLUSIVE     # a store that serves no one cannot show it confines anyone
    target.get("alice", ("bob",))
    crossed = ("alice", ("bob",)) in target.store.reads
    return FAIL if crossed else PASS


class DecisionReachesExecutorTruthTable(unittest.TestCase):
    def test_positive_control_passes(self):
        self.assertEqual(grade_decision_reaches_executor(AppliesHook()), PASS)

    def test_langgraph_shape_fails(self):
        self.assertEqual(grade_decision_reaches_executor(DropsHookResult()), FAIL)

    def test_the_oracle_is_the_store_not_the_hook(self):
        # The hook's own return value is correct in both shapes; only the store's
        # read log separates them.
        self.assertEqual(narrowing_hook("alice", ("bob",)), ("alice",))
        good, bad = AppliesHook(), DropsHookResult()
        good.get("alice", ("bob",)); bad.get("alice", ("bob",))
        self.assertNotIn(("alice", ("bob",)), good.store.reads)
        self.assertIn(("alice", ("bob",)), bad.store.reads)

    def test_rejecting_everything_is_inconclusive(self):
        self.assertEqual(grade_decision_reaches_executor(RejectsEverything()), INCONCLUSIVE)

    def test_one_principal_is_inconclusive(self):
        self.assertEqual(grade_decision_reaches_executor(DropsHookResult(), ("alice",)),
                         INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()
