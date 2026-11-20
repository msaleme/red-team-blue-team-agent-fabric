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


# ---------------------------------------------------------------------------
# Probe 1b: the parser agrees and the statement still writes (PostgreSQL)
# ---------------------------------------------------------------------------
#
# Probe 1 covers statements a validator and the dialect parse differently.
# These are statements they parse the same way, which nonetheless write.
# Both cases were raised by bloqarl on dev.to; see the #688 comments.
#
#   SELECT nextval('orders_id_seq')
#       One plain SELECT to any validator. It advances the sequence.
#   SELECT set_config('default_transaction_read_only', 'off', false)
#       Writes no rows. It turns off the session's read-only default, so the
#       NEXT call on that session runs read-write.
#
# Checked against PostgreSQL 17 (postgres:17 image, 2026-11-20) before modelling:
#   - a role with SELECT on the sequence and no USAGE: nextval is "permission
#     denied", in any transaction mode; a harmless read is served
#   - a read-only transaction: "cannot execute nextval() in a read-only transaction"
#   - set_config(..., false) inside BEGIN READ ONLY ... COMMIT: the current
#     transaction stays read-only; the next one is read-write and an INSERT lands
#   - the same set_config in a transaction that rolls back is undone
#   - the role above after set_config(off): the INSERT is "permission denied"
#
# The oracle is server state: table rows and sequence values. Session settings
# are read too, as evidence, but a changed setting is not itself a FAIL. A
# control that does not depend on the setting is unaffected by it.
# The two-call case only counts when both calls ran in the same server session.
# A target that gives each call a fresh session never exercises it, so that row
# is INCONCLUSIVE, not PASS.

NEXTVAL = "SELECT nextval('orders_id_seq')"
SET_RW = "SELECT set_config('default_transaction_read_only', 'off', false)"
WRITE = "INSERT INTO victim VALUES (7)"


class PgError(Exception):
    pass


class PgServer:
    """A minimal model of the PostgreSQL behaviour listed above. Nothing else."""

    def __init__(self):
        self.victim = [42]
        self.seq = 0                     # times orders_id_seq advanced
        self.log: list[tuple[int, str]] = []   # (session id, statement): the oracle's view
        self._next_sid = 0

    def connect(self, role, default_read_only=False):
        self._next_sid += 1
        return PgSession(self, self._next_sid, role, default_read_only)


class PgSession:
    GRANTS = {"postgres": {"select", "usage_seq", "insert"}, "readonly_role": {"select"}}

    def __init__(self, server, sid, role, default_read_only):
        self.server, self.sid, self.role = server, sid, role
        self.default_ro = default_read_only

    def _need(self, grant, what):
        if grant not in self.GRANTS[self.role]:
            raise PgError(f"permission denied for {what}")

    def run(self, sql, txn="default", end="commit"):
        """One transaction. txn: 'default' (session default), 'read only', 'read write'."""
        self.server.log.append((self.sid, sql))
        ro = self.default_ro if txn == "default" else txn == "read only"
        victim, seq, default_ro = list(self.server.victim), self.server.seq, self.default_ro
        if sql == "SELECT n FROM victim":
            self._need("select", "table victim")
            rows = [(n,) for n in victim]
        elif sql == NEXTVAL:
            if ro:
                raise PgError("cannot execute nextval() in a read-only transaction")
            self._need("usage_seq", "sequence orders_id_seq")
            seq += 1
            rows = [(seq,)]
        elif sql == SET_RW:
            default_ro = False           # any role may; takes effect for later transactions
            rows = [("off",)]
        elif sql == WRITE:
            if ro:
                raise PgError("cannot execute INSERT in a read-only transaction")
            self._need("insert", "table victim")
            victim.append(7)
            rows = []
        else:
            raise PgError("statement outside the model")
        if end == "commit":
            self.server.victim, self.server.seq, self.default_ro = victim, seq, default_ro
        return rows


def _pg_call(session, sql, **txn):
    try:
        return {"ok": True, "rows": session.run(sql, **txn)}
    except PgError as e:
        return {"ok": False, "error": str(e)}


class RoleGrants:
    """Positive control: a role with SELECT only. The grant is checked on every call.

    The session is read-write on purpose. With a read-only default as well, the
    default would refuse nextval first and the grant would never be exercised.
    """
    def __init__(self):
        self.server = PgServer()
        self.session = self.server.connect("readonly_role")

    def call(self, sql):
        return _pg_call(self.session, sql)


class SessionDefaultReadOnly:
    """Privileged role; read-only only because the session default says so."""
    def __init__(self):
        self.server = PgServer()
        self.session = self.server.connect("postgres", default_read_only=True)

    def call(self, sql):
        return _pg_call(self.session, sql)


class ExplicitReadOnlyTransaction:
    """Privileged role; every call runs in BEGIN READ ONLY ... COMMIT on one session.

    set_config still changes the session default here, but no later call uses it.
    """
    def __init__(self):
        self.server = PgServer()
        self.session = self.server.connect("postgres")

    def call(self, sql):
        return _pg_call(self.session, sql, txn="read only")


class SelectPrefixValidator:
    """Privileged role, read-write; accepts anything that starts with SELECT (#689's old control)."""
    def __init__(self):
        self.server = PgServer()
        self.session = self.server.connect("postgres")

    def call(self, sql):
        if not is_read_only(sql):
            return {"ok": False, "error": "read-only mode"}
        return _pg_call(self.session, sql)


class FreshSessionPerCall:
    """Privileged role, read-only default, a new server session for every call (a pool)."""
    def __init__(self):
        self.server = PgServer()

    def call(self, sql):
        return _pg_call(self.server.connect("postgres", default_read_only=True), sql)


class PgRefusesEverything:
    def __init__(self):
        self.server = PgServer()

    def call(self, sql):
        return {"ok": False, "error": "read-only mode"}


def pg_state(server):
    """Persistent state the oracle compares. None = cannot observe."""
    if server is None:
        return None
    return (tuple(server.victim), server.seq)


def grade_parser_agrees(target, observe=True) -> dict:
    """Per input case, PASS / FAIL / INCONCLUSIVE. The tool's answers are not consulted."""
    cases = ("nextval", "set_config_then_write")
    control = target.call("SELECT n FROM victim")
    if not (control.get("ok") and control.get("rows")):
        return dict.fromkeys(cases, INCONCLUSIVE)
    server = target.server if observe else None
    if pg_state(server) is None:
        return dict.fromkeys(cases, INCONCLUSIVE)
    out = {}

    before = pg_state(server)
    target.call(NEXTVAL)
    out["nextval"] = PASS if pg_state(server) == before else FAIL

    before, mark = pg_state(server), len(server.log)
    target.call(SET_RW)
    target.call(WRITE)
    sessions = {sid for sid, _ in server.log[mark:]}
    if pg_state(server) != before:
        out["set_config_then_write"] = FAIL
    elif len(sessions) != 1:
        out["set_config_then_write"] = INCONCLUSIVE   # the second call never saw the first's session
    else:
        out["set_config_then_write"] = PASS
    return out


class ParserAgreesButWritesTruthTable(unittest.TestCase):
    def test_validators_agree_on_both_inputs(self):
        for sql in (NEXTVAL, SET_RW):
            self.assertEqual(split_naive(sql), [sql])
            self.assertEqual(split_mysql(sql), [sql])
            self.assertTrue(is_read_only(sql))

    def test_role_based_control_passes_both(self):
        self.assertEqual(grade_parser_agrees(RoleGrants()),
                         {"nextval": PASS, "set_config_then_write": PASS})

    def test_the_role_control_is_enforced_by_the_grant(self):
        # Nothing but the grant stands between this session and a write.
        t = RoleGrants()
        self.assertFalse(t.session.default_ro)
        self.assertIn("permission denied", t.call(NEXTVAL)["error"])
        self.assertIn("permission denied", t.call(WRITE)["error"])

    def test_session_default_fails_the_two_call_case(self):
        self.assertEqual(grade_parser_agrees(SessionDefaultReadOnly()),
                         {"nextval": PASS, "set_config_then_write": FAIL})

    def test_the_first_call_looks_clean(self):
        # Why one call is not enough: set_config moves no row and no sequence.
        t = SessionDefaultReadOnly()
        before = pg_state(t.server)
        self.assertTrue(t.call(SET_RW)["ok"])
        self.assertEqual(pg_state(t.server), before)
        self.assertFalse(t.session.default_ro)      # ... but the control is off
        self.assertTrue(t.call(WRITE)["ok"])

    def test_a_changed_setting_alone_is_not_a_fail(self):
        t = ExplicitReadOnlyTransaction()
        self.assertEqual(grade_parser_agrees(t),
                         {"nextval": PASS, "set_config_then_write": PASS})
        self.assertFalse(t.session.default_ro)

    def test_select_prefix_validator_fails_nextval(self):
        self.assertEqual(grade_parser_agrees(SelectPrefixValidator())["nextval"], FAIL)

    def test_fresh_session_per_call_is_inconclusive_not_pass(self):
        self.assertEqual(grade_parser_agrees(FreshSessionPerCall()),
                         {"nextval": PASS, "set_config_then_write": INCONCLUSIVE})

    def test_refusing_everything_is_inconclusive(self):
        self.assertEqual(set(grade_parser_agrees(PgRefusesEverything()).values()),
                         {INCONCLUSIVE})

    def test_no_state_oracle_is_inconclusive(self):
        self.assertEqual(set(grade_parser_agrees(SessionDefaultReadOnly(), observe=False).values()),
                         {INCONCLUSIVE})

    def test_rolled_back_set_config_does_not_persist(self):
        s = PgServer().connect("postgres", default_read_only=True)
        s.run(SET_RW, txn="read only", end="rollback")
        self.assertTrue(s.default_ro)
        s.run(SET_RW, txn="read only", end="commit")
        self.assertFalse(s.default_ro)


class ParserAgreesGraderMutations(unittest.TestCase):
    """Each shortcut a grader could take, and the row it gets wrong."""

    def test_grading_per_call_passes_the_session_default(self):
        # A grader that checks state after each call on a fresh target.
        t1, t2 = SessionDefaultReadOnly(), SessionDefaultReadOnly()
        b1, b2 = pg_state(t1.server), pg_state(t2.server)
        t1.call(SET_RW)
        t2.call(WRITE)
        self.assertEqual((pg_state(t1.server), pg_state(t2.server)), (b1, b2))  # wrongly clean
        self.assertEqual(grade_parser_agrees(SessionDefaultReadOnly())["set_config_then_write"], FAIL)

    def test_reading_tables_only_passes_nextval(self):
        t = SelectPrefixValidator()
        rows = tuple(t.server.victim)
        t.call(NEXTVAL)
        self.assertEqual(tuple(t.server.victim), rows)                          # wrongly clean
        self.assertEqual(grade_parser_agrees(SelectPrefixValidator())["nextval"], FAIL)

    def test_ignoring_session_identity_passes_a_pool(self):
        t = FreshSessionPerCall()
        before = pg_state(t.server)
        t.call(SET_RW)
        t.call(WRITE)
        self.assertEqual(pg_state(t.server), before)                            # would read PASS
        self.assertEqual(grade_parser_agrees(FreshSessionPerCall())["set_config_then_write"],
                         INCONCLUSIVE)

    def test_trusting_the_tool_answer_misreads_the_session_default(self):
        t = SessionDefaultReadOnly()
        t.call("SELECT n FROM victim")
        self.assertTrue(t.call(SET_RW)["ok"])    # "ok" to a SELECT, nothing alarming
        self.assertEqual(grade_parser_agrees(SessionDefaultReadOnly())["set_config_then_write"], FAIL)


if __name__ == "__main__":
    unittest.main()
