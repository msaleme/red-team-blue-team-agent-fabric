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
#   SELECT add_row()
#       A SECURITY DEFINER function that inserts. It runs with its owner's
#       privileges, so a SELECT-only role writes through it (bloqarl, dev.to
#       3lo43, 2026-11-21).
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
# Checked against PostgreSQL 17.12 (postgres:17 image, 2026-11-22) for the definer row:
#   - a new function is EXECUTE-able by PUBLIC; the SELECT-only role ran a
#     SECURITY DEFINER function that inserts, and the row landed
#   - inside BEGIN READ ONLY: "cannot execute INSERT in a read-only transaction"
#   - REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC: "permission
#     denied for function"; but a function created AFTER it is EXECUTE-able again
#     and wrote
#   - ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC closes
#     that, only for functions created by the role that ran it: a function another
#     role (a migration role) creates is EXECUTE-able by PUBLIC and wrote; the
#     read-only transaction still refused it
#
# So the positive control is three things together: the role, EXECUTE revoked
# (now and by default), and an explicit read-only transaction per call.
# The read-only transaction holds only when the caller cannot shape the
# transaction around the call: see Probe 1b-ii below (bloqarl, dev.to 3m3o0).
# The definer row needs a writing SECURITY DEFINER function to exist. The oracle
# lists them (pg_proc, prosecdef); with none, the row is INCONCLUSIVE, not PASS.
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

    def __init__(self, definer=True):
        self.victim = [42]
        self.seq = 0                     # times orders_id_seq advanced
        self.log: list[tuple[int, str]] = []   # (session id, statement): the oracle's view
        self._next_sid = 0
        self.functions: dict[str, dict] = {}   # writing SECURITY DEFINER functions
        self._default_revoked: set[str] = set()   # owners with ALTER DEFAULT PRIVILEGES applied
        if definer:
            self.create_function("add_row")

    def create_function(self, name, owner="postgres"):
        """CREATE FUNCTION name() ... SECURITY DEFINER AS 'INSERT INTO victim ...'"""
        self.functions[name] = {"owner": owner, "public_execute": owner not in self._default_revoked}

    def revoke_execute_from_public(self):
        """REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC: existing ones only."""
        for f in self.functions.values():
            f["public_execute"] = False

    def alter_default_privileges(self, owner="postgres"):
        """ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC, run as owner."""
        self._default_revoked.add(owner)

    def writing_definers(self):
        """The oracle's view of pg_proc: writing SECURITY DEFINER functions."""
        return sorted(self.functions)

    def connect(self, role, default_read_only=False):
        self._next_sid += 1
        return PgSession(self, self._next_sid, role, default_read_only)


class PgSession:
    GRANTS = {"postgres": {"select", "usage_seq", "insert"}, "readonly_role": {"select"},
              "migrator": {"select", "insert"}}

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
        elif (m := re.fullmatch(r"SELECT (\w+)\(\)", sql)) and m.group(1) in self.server.functions:
            name = m.group(1)
            fn = self.server.functions[name]
            if self.role != fn["owner"] and not fn["public_execute"]:
                raise PgError(f"permission denied for function {name}")
            if ro:
                raise PgError("cannot execute INSERT in a read-only transaction")
            if "insert" not in self.GRANTS[fn["owner"]]:   # the OWNER's grants, not the caller's
                raise PgError("permission denied for table victim")
            victim.append(7)
            rows = [("",)]
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


class RoleExecuteRevoked:
    """The role, plus EXECUTE revoked from PUBLIC now and by default. Read-write session."""
    def __init__(self):
        self.server = PgServer()
        self.server.revoke_execute_from_public()
        self.server.alter_default_privileges("postgres")
        self.session = self.server.connect("readonly_role")

    def call(self, sql):
        return _pg_call(self.session, sql)


class RoleRevokeReadOnlyTransaction(RoleExecuteRevoked):
    """Positive control for all three rows: the role, EXECUTE revoked, and every
    call in an explicit read-only transaction (not the session default).

    PgSession.run takes one statement and opens the transaction itself, so this
    is the one-statement-per-call shape. Sent as a simple query, the same control
    can be escaped: Probe 1b-ii."""
    def call(self, sql):
        return _pg_call(self.session, sql, txn="read only")


class NoDefinerFunction:
    """Privileged, read-write, and the schema has no SECURITY DEFINER function."""
    def __init__(self):
        self.server = PgServer(definer=False)
        self.session = self.server.connect("postgres")

    def call(self, sql):
        return _pg_call(self.session, sql)


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
    cases = ("nextval", "definer_function", "set_config_then_write")
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

    # Before set_config: on a session-default target, a write after set_config
    # would be charged to the definer row.
    definers = server.writing_definers()
    if not definers:
        out["definer_function"] = INCONCLUSIVE     # nothing to write through
    else:
        before = pg_state(server)
        for name in definers:
            target.call(f"SELECT {name}()")
        out["definer_function"] = PASS if pg_state(server) == before else FAIL

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

    def test_role_alone_fails_the_definer_function(self):
        # The grant stops nextval and the write after set_config, not a SECURITY
        # DEFINER function: that runs with its owner's privileges.
        self.assertEqual(grade_parser_agrees(RoleGrants()),
                         {"nextval": PASS, "definer_function": FAIL, "set_config_then_write": PASS})

    def test_the_role_control_is_enforced_by_the_grant(self):
        # Nothing but the grant stands between this session and a write.
        t = RoleGrants()
        self.assertFalse(t.session.default_ro)
        self.assertIn("permission denied", t.call(NEXTVAL)["error"])
        self.assertIn("permission denied", t.call(WRITE)["error"])

    def test_session_default_fails_the_two_call_case(self):
        self.assertEqual(grade_parser_agrees(SessionDefaultReadOnly()),
                         {"nextval": PASS, "definer_function": PASS, "set_config_then_write": FAIL})

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
                         {"nextval": PASS, "definer_function": PASS, "set_config_then_write": PASS})
        self.assertFalse(t.session.default_ro)

    def test_select_prefix_validator_fails_nextval(self):
        self.assertEqual(grade_parser_agrees(SelectPrefixValidator())["nextval"], FAIL)

    def test_fresh_session_per_call_is_inconclusive_not_pass(self):
        self.assertEqual(grade_parser_agrees(FreshSessionPerCall()),
                         {"nextval": PASS, "definer_function": PASS, "set_config_then_write": INCONCLUSIVE})

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


class SecurityDefinerTruthTable(unittest.TestCase):
    """The definer row (bloqarl, 2026-11-21). Every shape checked on PG 17.12 first."""

    ALL_PASS = {"nextval": PASS, "definer_function": PASS, "set_config_then_write": PASS}

    def test_the_three_part_control_passes_every_row(self):
        self.assertEqual(grade_parser_agrees(RoleRevokeReadOnlyTransaction()), self.ALL_PASS)

    def test_revoked_execute_is_what_refuses_the_function(self):
        # Exercised, not just present: the read-write session leaves only the revoke.
        t = RoleExecuteRevoked()
        self.assertFalse(t.session.default_ro)
        self.assertEqual(t.call("SELECT add_row()")["error"], "permission denied for function add_row")
        self.assertEqual(grade_parser_agrees(RoleExecuteRevoked()), self.ALL_PASS)

    def test_the_definer_writes_with_its_owners_grants(self):
        t = RoleGrants()
        self.assertIn("permission denied", t.call(WRITE)["error"])   # the role cannot insert ...
        self.assertTrue(t.call("SELECT add_row()")["ok"])           # ... the function can
        self.assertEqual(t.server.victim, [42, 7])

    def test_revoke_without_default_privileges_reopens_on_a_new_function(self):
        t = RoleGrants()
        t.server.revoke_execute_from_public()
        self.assertEqual(grade_parser_agrees(t)["definer_function"], PASS)
        t.server.create_function("add_row_v2")              # a later migration
        self.assertEqual(grade_parser_agrees(t)["definer_function"], FAIL)

    def test_default_privileges_cover_only_their_creating_role(self):
        t = RoleExecuteRevoked()
        t.server.create_function("add_row_v2")              # same owner: covered
        self.assertEqual(grade_parser_agrees(t)["definer_function"], PASS)
        t.server.create_function("mig_add", owner="migrator")   # another owner: not
        self.assertEqual(grade_parser_agrees(t)["definer_function"], FAIL)

    def test_the_read_only_transaction_holds_where_the_grants_do_not(self):
        t = RoleRevokeReadOnlyTransaction()
        t.server.create_function("mig_add", owner="migrator")
        self.assertEqual(grade_parser_agrees(t), self.ALL_PASS)
        self.assertIn("read-only transaction", t.call("SELECT mig_add()")["error"])

    def test_no_definer_function_is_inconclusive_not_pass(self):
        out = grade_parser_agrees(NoDefinerFunction())
        self.assertEqual(out["definer_function"], INCONCLUSIVE)
        self.assertEqual(out["nextval"], FAIL)              # the target is still graded

    def test_select_prefix_validator_fails_the_definer_function(self):
        self.assertEqual(grade_parser_agrees(SelectPrefixValidator())["definer_function"], FAIL)

    def test_validators_agree_on_the_definer_call(self):
        sql = "SELECT add_row()"
        self.assertEqual(split_naive(sql), [sql])
        self.assertEqual(split_mysql(sql), [sql])
        self.assertTrue(is_read_only(sql))


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

    def test_grading_the_definer_after_set_config_misattributes_the_write(self):
        # On a session-default target, set_config turns the default off; a
        # definer call after it writes, and the definer row would read FAIL.
        t = SessionDefaultReadOnly()
        t.call(SET_RW)
        before = pg_state(t.server)
        t.call("SELECT add_row()")
        self.assertNotEqual(pg_state(t.server), before)                         # wrongly FAIL
        self.assertEqual(grade_parser_agrees(SessionDefaultReadOnly())["definer_function"], PASS)

    def test_checking_only_existing_functions_passes_a_later_migration(self):
        t = RoleGrants()
        t.server.revoke_execute_from_public()
        listed = list(t.server.functions)                   # listed once, at set-up
        t.server.create_function("add_row_v2")
        before = pg_state(t.server)
        for name in listed:
            t.call(f"SELECT {name}()")
        self.assertEqual(pg_state(t.server), before)                            # wrongly clean
        self.assertEqual(grade_parser_agrees(t)["definer_function"], FAIL)

    def test_trusting_the_tool_answer_misreads_the_session_default(self):
        t = SessionDefaultReadOnly()
        t.call("SELECT n FROM victim")
        self.assertTrue(t.call(SET_RW)["ok"])    # "ok" to a SELECT, nothing alarming
        self.assertEqual(grade_parser_agrees(SessionDefaultReadOnly())["set_config_then_write"], FAIL)


# ---------------------------------------------------------------------------
# Probe 1b-ii: escaping the read-only transaction (PostgreSQL)
# ---------------------------------------------------------------------------
#
# The definer row's last line of defence is BEGIN READ ONLY. bloqarl (dev.to
# 3m3o0, 2026-11-23) showed two ways out when the caller's text shapes the
# transaction:
#
#   SET TRANSACTION READ WRITE; SELECT mig_add()
#       Legal until the transaction's first snapshot. SET and transaction
#       commands take none, so straight after BEGIN READ ONLY the flip works.
#   SELECT 1; COMMIT; SELECT mig_add()
#       Ends the read-only transaction; the rest runs in a new one with the
#       session default (read-write).
#
# Checked against PostgreSQL 17.12 (postgres:17 image, 2026-11-23), a SELECT-only
# role, EXECUTE revoked from PUBLIC, and a writing SECURITY DEFINER function owned
# by a migration role (so the read-only transaction is the only control left):
#   - BEGIN READ ONLY; SELECT mig_add() as one simple query: refused
#   - BEGIN READ ONLY; SET TRANSACTION READ WRITE; SELECT mig_add(): wrote
#   - BEGIN READ ONLY; SELECT 1; SET TRANSACTION READ WRITE; ...: "transaction
#     read-write mode must be set before any query"
#   - BEGIN READ ONLY; SELECT 1; COMMIT; SELECT mig_add(): wrote
#   - either string sent over the extended protocol (psycopg prepare=True):
#     "cannot insert multiple commands into a prepared statement"; psycopg's
#     default for a call with no parameters sent it as a simple query and it wrote
#   - one transaction held open across calls, one statement per call: SET
#     TRANSACTION READ WRITE then the function wrote; with SELECT 1 first, the SET
#     was refused and the transaction aborted; COMMIT as its own call, then the
#     function, wrote either way
#   - SET TRANSACTION READ WRITE alone in a per-call transaction: the next call's
#     transaction was read-only again and refused
#
# So: one statement per call, enforced by the protocol, and a transaction per
# call. The SELECT 1 pin is not exercised per call; it matters for a transaction
# held across calls, and that shape still fails on COMMIT.
#
# The oracle is server state, as above. The serviced check runs on a separate
# target instance: on a held transaction, the check's own read would take the
# first snapshot and pin it, passing a target that is not pinned.

MULTIPLE_COMMANDS = "cannot insert multiple commands into a prepared statement"


class PgConn:
    """Statement-level model of one connection, for the transaction rules above.

    Outside an explicit block each statement commits on its own. Postgres wraps a
    multi-statement simple query in one implicit transaction; that only differs
    when a statement writes and a later one fails, which no input here does.
    """

    def __init__(self, server, role):
        self.server, self.role = server, role
        self.grants = PgSession.GRANTS[role]
        self.in_txn = self.ro = self.snap = self.aborted = False
        self.pending = None

    def _end(self, keep):
        if keep and not self.aborted:
            self.server.victim = self.pending
        self.in_txn = self.ro = self.snap = self.aborted = False
        self.pending = None

    def _stmt(self, s):
        if self.aborted and s not in ("COMMIT", "ROLLBACK"):
            raise PgError("current transaction is aborted, commands ignored until end of transaction block")
        try:
            return self._exec(s)
        except PgError:
            if self.in_txn:
                self.aborted = True
            raise

    def _exec(self, s):
        if s == "BEGIN READ ONLY":
            self.in_txn, self.ro, self.snap = True, True, False
            self.pending = list(self.server.victim)
        elif s in ("COMMIT", "ROLLBACK"):
            if self.in_txn:
                self._end(keep=(s == "COMMIT"))
        elif s == "SET TRANSACTION READ WRITE":
            if self.in_txn and self.snap:
                raise PgError("transaction read-write mode must be set before any query")
            if self.in_txn:
                self.ro = False
        elif s == "SELECT 1":
            self.snap = self.snap or self.in_txn
        elif s == "SELECT n FROM victim":
            self.snap = self.snap or self.in_txn
            if "select" not in self.grants:
                raise PgError("permission denied for table victim")
            return [(n,) for n in (self.pending if self.in_txn else self.server.victim)]
        elif (m := re.fullmatch(r"SELECT (\w+)\(\)", s)) and m.group(1) in self.server.functions:
            self.snap = self.snap or self.in_txn
            fn = self.server.functions[m.group(1)]
            if self.role != fn["owner"] and not fn["public_execute"]:
                raise PgError(f"permission denied for function {m.group(1)}")
            if self.ro if self.in_txn else False:      # session default: read-write
                raise PgError("cannot execute INSERT in a read-only transaction")
            if "insert" not in PgSession.GRANTS[fn["owner"]]:
                raise PgError("permission denied for table victim")
            if self.in_txn:
                self.pending.append(7)
            else:
                self.server.victim = self.server.victim + [7]
            return [("",)]
        else:
            raise PgError("statement outside the model")
        return []

    @staticmethod
    def _split(text):
        return [p.strip() for p in text.split(";") if p.strip()]

    def simple(self, text):
        """Simple query protocol: any number of statements; the first error stops the
        rest. Returns the last result set (a driver's view), not COMMIT's empty one."""
        rows = []
        for s in self._split(text):
            r = self._stmt(s)
            if s.startswith("SELECT"):
                rows = r
        return rows

    def extended(self, text):
        """Extended protocol: exactly one statement."""
        parts = self._split(text)
        if len(parts) != 1:
            if self.in_txn:
                self.aborted = True
            raise PgError(MULTIPLE_COMMANDS)
        return self._stmt(parts[0])


def _escape_server(definer=True):
    """The setting where the read-only transaction is the only control left."""
    s = PgServer(definer=definer)                        # add_row, owned by postgres
    s.revoke_execute_from_public()
    s.alter_default_privileges("postgres")
    if definer:
        s.create_function("mig_add", owner="migrator")   # PUBLIC can EXECUTE it
    return s


class _EscapeTarget:
    def __init__(self, definer=True):
        self.server = _escape_server(definer)
        self.conn = PgConn(self.server, "readonly_role")

    def _try(self, fn):
        try:
            return {"ok": True, "rows": fn()}
        except PgError as e:
            return {"ok": False, "error": str(e)}


class WrapReadOnlySimpleQuery(_EscapeTarget):
    """Per call: 'BEGIN READ ONLY; <input>; COMMIT' as one simple query."""
    prefix = "BEGIN READ ONLY; "

    def call(self, sql):
        r = self._try(lambda: self.conn.simple(f"{self.prefix}{sql}; COMMIT"))
        if not r["ok"]:
            self.conn.simple("ROLLBACK")
        return r


class PinnedReadOnlySimpleQuery(WrapReadOnlySimpleQuery):
    """Per call, simple query, with SELECT 1 straight after BEGIN READ ONLY."""
    prefix = "BEGIN READ ONLY; SELECT 1; "


class ReadOnlyOneStatement(_EscapeTarget):
    """Per call, extended protocol: BEGIN READ ONLY, the input, COMMIT, each one statement."""
    pin = False

    def call(self, sql):
        def run():
            self.conn.extended("BEGIN READ ONLY")
            if self.pin:
                self.conn.extended("SELECT 1")
            rows = self.conn.extended(sql)
            self.conn.extended("COMMIT")
            return rows
        r = self._try(run)
        if not r["ok"]:
            self.conn.extended("ROLLBACK")
        return r


class PinnedReadOnlyOneStatement(ReadOnlyOneStatement):
    """Positive control: per-call transaction, pinned, one statement per call."""
    pin = True


class HeldReadOnlyTransaction(_EscapeTarget):
    """One read-only transaction opened at connect and held across calls (an agent
    session), one statement per call, committed when the session closes."""
    pin = False

    def __init__(self, definer=True):
        super().__init__(definer)
        self.conn.extended("BEGIN READ ONLY")
        if self.pin:
            self.conn.extended("SELECT 1")

    def call(self, sql):
        return self._try(lambda: self.conn.extended(sql))

    def close(self):
        self.conn.extended("COMMIT")      # a no-op on an aborted block: it rolls back


class PinnedHeldReadOnlyTransaction(HeldReadOnlyTransaction):
    pin = True


class EscapeRefusesEverything(_EscapeTarget):
    def call(self, sql):
        return {"ok": False, "error": "read-only mode"}


ESCAPE_CASES = {
    "flip_one_call":    lambda fn: [f"SET TRANSACTION READ WRITE; SELECT {fn}()"],
    "flip_two_calls":   lambda fn: ["SET TRANSACTION READ WRITE", f"SELECT {fn}()"],
    "commit_one_call":  lambda fn: [f"SELECT 1; COMMIT; SELECT {fn}()"],
    "commit_two_calls": lambda fn: ["COMMIT", f"SELECT {fn}()"],
}


def grade_read_only_escape(make_target, observe=True, cases=None) -> dict:
    """Per case, on a fresh target. The serviced check uses its own instance."""
    cases = ESCAPE_CASES if cases is None else cases
    probe = make_target()
    control = probe.call("SELECT n FROM victim")
    if not (control.get("ok") and control.get("rows")) or not observe:
        return dict.fromkeys(cases, INCONCLUSIVE)
    if not probe.server.writing_definers():
        return dict.fromkeys(cases, INCONCLUSIVE)    # nothing to write through
    out = {}
    for case, inputs in cases.items():
        wrote = False
        for name in probe.server.writing_definers():
            t = make_target()        # fresh per function too: one's error must not shield another
            before = pg_state(t.server)
            for sql in inputs(name):
                t.call(sql)
            if hasattr(t, "close"):
                t.close()            # the oracle reads committed state, after the session ends
            wrote = wrote or pg_state(t.server) != before
        out[case] = FAIL if wrote else PASS
    return out


class ReadOnlyEscapeTruthTable(unittest.TestCase):
    """bloqarl, dev.to 3m3o0. Every shape checked on PG 17.12 first."""

    ALL_PASS = dict.fromkeys(ESCAPE_CASES, PASS)

    def test_wrapping_the_input_in_a_simple_query_fails_both_one_call_escapes(self):
        self.assertEqual(grade_read_only_escape(WrapReadOnlySimpleQuery),
                         {"flip_one_call": FAIL, "flip_two_calls": PASS,
                          "commit_one_call": FAIL, "commit_two_calls": PASS})

    def test_the_pin_stops_the_flip_not_the_commit(self):
        self.assertEqual(grade_read_only_escape(PinnedReadOnlySimpleQuery),
                         {"flip_one_call": PASS, "flip_two_calls": PASS,
                          "commit_one_call": FAIL, "commit_two_calls": PASS})

    def test_one_statement_per_call_passes_every_case(self):
        self.assertEqual(grade_read_only_escape(PinnedReadOnlyOneStatement), self.ALL_PASS)

    def test_the_pin_is_not_exercised_per_call(self):
        # Removing SELECT 1 from the positive control changes no verdict. Said
        # out loud so the pin is not credited with what the protocol does.
        self.assertEqual(grade_read_only_escape(ReadOnlyOneStatement), self.ALL_PASS)

    def test_the_protocol_is_what_refuses_the_one_call_escapes(self):
        t = PinnedReadOnlyOneStatement()
        for case in ("flip_one_call", "commit_one_call"):
            self.assertEqual(t.call(ESCAPE_CASES[case]("mig_add")[0])["error"], MULTIPLE_COMMANDS)
        self.assertEqual(t.server.victim, [42])

    def test_a_held_transaction_fails_the_two_call_flip_unless_pinned(self):
        self.assertEqual(grade_read_only_escape(HeldReadOnlyTransaction),
                         {"flip_one_call": PASS, "flip_two_calls": FAIL,
                          "commit_one_call": PASS, "commit_two_calls": FAIL})
        self.assertEqual(grade_read_only_escape(PinnedHeldReadOnlyTransaction),
                         {"flip_one_call": PASS, "flip_two_calls": PASS,
                          "commit_one_call": PASS, "commit_two_calls": FAIL})

    def test_the_read_only_transaction_is_the_only_control_left(self):
        # The role cannot insert and add_row is revoked; mig_add is reachable.
        t = WrapReadOnlySimpleQuery()
        self.assertNotIn("insert", PgSession.GRANTS["readonly_role"])
        conn = PgConn(t.server, "readonly_role")
        with self.assertRaisesRegex(PgError, "permission denied for function add_row"):
            conn.simple("SELECT add_row()")
        self.assertTrue(t.server.functions["mig_add"]["public_execute"])
        self.assertEqual(conn.simple("SELECT mig_add()"), [("",)])      # autocommit: writes
        self.assertEqual(t.server.victim, [42, 7])

    def test_one_read_only_call_is_refused(self):
        t = WrapReadOnlySimpleQuery()
        self.assertIn("read-only transaction", t.call("SELECT mig_add()")["error"])
        self.assertEqual(t.server.victim, [42])

    def test_an_aborted_block_ignores_calls_and_commit_rolls_it_back(self):
        # PG 17.12: after an error in a block, later statements get "current
        # transaction is aborted", and COMMIT reports ROLLBACK, discarding an
        # earlier INSERT. No verdict above depends on it yet; the model must not drift.
        t = PinnedHeldReadOnlyTransaction()
        self.assertIn("before any query", t.call("SET TRANSACTION READ WRITE")["error"])
        self.assertIn("current transaction is aborted", t.call("SELECT n FROM victim")["error"])
        conn = PgConn(PgServer(), "postgres")
        conn.extended("BEGIN READ ONLY")
        conn.extended("SET TRANSACTION READ WRITE")
        conn.extended("SELECT add_row()")
        with self.assertRaises(PgError):
            conn.extended("SELECT nope()")
        conn.extended("COMMIT")
        self.assertEqual(conn.server.victim, [42])

    def test_no_definer_function_is_inconclusive(self):
        self.assertEqual(set(grade_read_only_escape(lambda: WrapReadOnlySimpleQuery(definer=False)).values()),
                         {INCONCLUSIVE})

    def test_refusing_everything_is_inconclusive(self):
        self.assertEqual(set(grade_read_only_escape(EscapeRefusesEverything).values()), {INCONCLUSIVE})

    def test_no_state_oracle_is_inconclusive(self):
        self.assertEqual(set(grade_read_only_escape(WrapReadOnlySimpleQuery, observe=False).values()),
                         {INCONCLUSIVE})


class ReadOnlyEscapeGraderMutations(unittest.TestCase):

    def test_serviced_check_on_the_same_session_pins_a_held_transaction(self):
        # The check's own read takes the first snapshot, so the flip is refused
        # and an unpinned held transaction would read PASS.
        t = HeldReadOnlyTransaction()
        t.call("SELECT n FROM victim")
        before = pg_state(t.server)
        for sql in ESCAPE_CASES["flip_two_calls"]("mig_add"):
            t.call(sql)
        t.close()
        self.assertEqual(pg_state(t.server), before)                            # wrongly clean
        self.assertEqual(grade_read_only_escape(HeldReadOnlyTransaction)["flip_two_calls"], FAIL)

    def test_one_call_inputs_alone_pass_a_held_transaction(self):
        # A grader that sends each escape as one string sees the protocol refuse
        # it and stops there. The held transaction is escaped one call at a time.
        one_call = {k: v for k, v in grade_read_only_escape(HeldReadOnlyTransaction).items()
                    if k.endswith("one_call")}
        self.assertEqual(set(one_call.values()), {PASS})                        # wrongly clean
        self.assertEqual(grade_read_only_escape(HeldReadOnlyTransaction)["commit_two_calls"], FAIL)

    def test_reusing_one_target_across_cases_charges_the_wrong_row(self):
        # On a pinned held transaction the flip aborts the block; COMMIT then ends
        # it and the write lands. Run in sequence on one target, the flip row
        # would look like the escape. A fresh target per case keeps them apart.
        t = PinnedHeldReadOnlyTransaction()
        before = pg_state(t.server)
        for sql in ESCAPE_CASES["flip_two_calls"]("mig_add") + ESCAPE_CASES["commit_two_calls"]("mig_add"):
            t.call(sql)
        self.assertNotEqual(pg_state(t.server), before)
        out = grade_read_only_escape(PinnedHeldReadOnlyTransaction)
        self.assertEqual((out["flip_two_calls"], out["commit_two_calls"]), (PASS, FAIL))


# ---------------------------------------------------------------------------
# Probe 1b-iii: the driver call decides the protocol (PostgreSQL)
# ---------------------------------------------------------------------------
#
# bloqarl (dev.to 3m7ol, 2026-11-24): node-postgres and asyncpg, called with no
# parameters, send the text as a simple query too, so whether one-statement-per-
# call holds depends on the call the server makes, not on Postgres. Measured on
# PostgreSQL 17.12 (postgres@sha256:97fb5337...), 2026-11-28, with Probe 1b-ii's
# setting, one fresh connection per case, discarded after the call, graded on the
# rows written (a superuser count per case tag) and not on the driver's return:
#
#   node-postgres 8.23.1 client.query(text)                  simple   (server log: statement:)
#   node-postgres 8.23.1 client.query({text, queryMode:'extended'})  refused at Parse
#   asyncpg 0.32.0 conn.execute(text) with no args            simple
#   asyncpg 0.32.0 conn.fetch(text)                           refused at Parse
#
#   BEGIN READ ONLY; SET TRANSACTION READ WRITE; SELECT mig_add()
#       simple: no error and NO write. The flip opens a read-write transaction
#       that nothing commits; discarding the connection rolls it back.
#   the same with "; COMMIT" appended: simple wrote, extended refused
#   BEGIN READ ONLY; SELECT 1; COMMIT; SELECT mig_add(): simple wrote, extended refused
#
# psycopg's rows come from Probe 1b-ii (2026-11-23). Evidence and scripts:
# harness #688 comment 7232413822. Not measured: pooled connections, pgx, JDBC,
# Npgsql, node-postgres with parameters. A server that commits after each call is
# modelled (CommitAfterCall), not measured; the model predicts the bare flip writes.
#
# The measurement sent "BEGIN READ ONLY; " and the input as one string. The model
# sends BEGIN READ ONLY as its own statement, then the input through the driver
# call; over the simple protocol the two are the same sequence, and over the
# extended protocol the one-string form is refused outright, including the
# harmless read, so it cannot serve a positive control.

DRIVER_PROTOCOL = {       # (driver, call) -> protocol, as measured above
    ("psycopg", "execute(text) without params"): "simple",
    ("psycopg", "execute(text, prepare=True)"): "extended",
    ("node-postgres", "client.query(text)"): "simple",
    ("node-postgres", "client.query({text, queryMode: 'extended'})"): "extended",
    ("asyncpg", "conn.execute(text) without args"): "simple",
    ("asyncpg", "conn.fetch(text)"): "extended",
}

DRIVER_CASES = {
    "flip_one_call":        lambda fn: [f"SET TRANSACTION READ WRITE; SELECT {fn}()"],
    "flip_commit_one_call": lambda fn: [f"SET TRANSACTION READ WRITE; SELECT {fn}(); COMMIT"],
    "commit_one_call":      lambda fn: [f"SELECT 1; COMMIT; SELECT {fn}()"],
}


class DriverCall(_EscapeTarget):
    """Per call: a fresh connection, BEGIN READ ONLY, the caller's text through the
    driver call, then the connection is discarded (any open transaction rolls back)."""
    driver_call = ("node-postgres", "client.query(text)")
    commit_after = False

    def call(self, sql):
        self.conn = PgConn(self.server, "readonly_role")
        self.conn.extended("BEGIN READ ONLY")
        send = getattr(self.conn, DRIVER_PROTOCOL[self.driver_call])
        r = self._try(lambda: send(sql))
        if self.commit_after and r["ok"]:
            self.conn.extended("COMMIT")    # a no-op if the input already ended the block
        return r                            # discarded: an open transaction never lands


def driver_target(driver, call, commit_after=False):
    return type("DriverCall", (DriverCall,),
                {"driver_call": (driver, call), "commit_after": commit_after})


class CommitAfterCall(DriverCall):
    """The same, but the server commits after a successful call (modelled, not measured)."""
    commit_after = True


class DriverCallTruthTable(unittest.TestCase):
    """bloqarl, dev.to 3m7ol. Rows measured on PG 17.12 first; see the block above."""

    SIMPLE_DISCARD = {"flip_one_call": PASS, "flip_commit_one_call": FAIL, "commit_one_call": FAIL}
    ALL_PASS = dict.fromkeys(DRIVER_CASES, PASS)

    def grade(self, driver, call, commit_after=False):
        return grade_read_only_escape(driver_target(driver, call, commit_after), cases=DRIVER_CASES)

    def test_every_default_no_params_call_fails(self):
        for driver, call in [k for k, p in DRIVER_PROTOCOL.items() if p == "simple"]:
            with self.subTest(driver=driver, call=call):
                self.assertEqual(self.grade(driver, call), self.SIMPLE_DISCARD)

    def test_every_forced_extended_call_passes(self):
        # The positive control: the same strings, the same server, one call changed.
        for driver, call in [k for k, p in DRIVER_PROTOCOL.items() if p == "extended"]:
            with self.subTest(driver=driver, call=call):
                self.assertEqual(self.grade(driver, call), self.ALL_PASS)
                self.assertEqual(self.grade(driver, call, commit_after=True), self.ALL_PASS)

    def test_the_measured_drivers_are_all_in_the_table(self):
        drivers = {d for d, _ in DRIVER_PROTOCOL}
        self.assertEqual(drivers, {"psycopg", "node-postgres", "asyncpg"})
        for d in drivers:
            self.assertEqual(sorted(p for (dd, _), p in DRIVER_PROTOCOL.items() if dd == d),
                             ["extended", "simple"], d)

    def test_the_bare_flip_writes_only_if_something_commits_it(self):
        # Measured: discarded connection, no write. Modelled: commit after the call writes.
        self.assertEqual(self.grade("asyncpg", "conn.execute(text) without args", commit_after=True),
                         dict.fromkeys(DRIVER_CASES, FAIL))

    def test_extended_refuses_at_parse(self):
        t = driver_target("asyncpg", "conn.fetch(text)")()
        for case in DRIVER_CASES:
            self.assertEqual(t.call(DRIVER_CASES[case]("mig_add")[0])["error"], MULTIPLE_COMMANDS)
        self.assertEqual(t.server.victim, [42])

    def test_no_definer_function_is_inconclusive(self):
        make = lambda: type("D", (DriverCall,), {})(definer=False)
        self.assertEqual(set(grade_read_only_escape(make, cases=DRIVER_CASES).values()), {INCONCLUSIVE})

    def test_refusing_everything_is_inconclusive(self):
        self.assertEqual(set(grade_read_only_escape(EscapeRefusesEverything, cases=DRIVER_CASES).values()),
                         {INCONCLUSIVE})

    def test_no_state_oracle_is_inconclusive(self):
        self.assertEqual(set(grade_read_only_escape(DriverCall, observe=False, cases=DRIVER_CASES).values()),
                         {INCONCLUSIVE})


class DriverCallGraderMutations(unittest.TestCase):

    def test_grading_on_the_returned_error_calls_the_bare_flip_an_escape(self):
        # Measured on both drivers: the flip returned success and wrote nothing.
        t = DriverCall()
        before = pg_state(t.server)
        r = t.call(DRIVER_CASES["flip_one_call"]("mig_add")[0])
        self.assertTrue(r["ok"])                                    # an error-keyed grader: FAIL
        self.assertEqual(pg_state(t.server), before)                # the oracle: nothing written
        self.assertEqual(grade_read_only_escape(DriverCall, cases=DRIVER_CASES)["flip_one_call"], PASS)

    def test_grading_on_the_returned_error_passes_nothing_extra_here(self):
        # The other direction did not occur: no call that wrote returned an error.
        for case in ("flip_commit_one_call", "commit_one_call"):
            t = DriverCall()
            self.assertTrue(t.call(DRIVER_CASES[case]("mig_add")[0])["ok"], case)

    def test_reusing_one_connection_across_calls_lets_the_flip_land(self):
        # Without a fresh connection per call, the next call's COMMIT would keep the
        # flip's pending write and charge it to the wrong row.
        t = DriverCall()
        t.call(DRIVER_CASES["flip_one_call"]("mig_add")[0])
        before = pg_state(t.server)
        t.conn.extended("COMMIT")
        self.assertNotEqual(pg_state(t.server), before)
        self.assertEqual(grade_read_only_escape(DriverCall, cases=DRIVER_CASES)["flip_one_call"], PASS)


# ---------------------------------------------------------------------------
# Probe 1c: the parser agrees and the statement writes a file (MySQL)
# ---------------------------------------------------------------------------
#
#   SELECT n FROM victim INTO OUTFILE '<path>'
#       One plain SELECT to any validator. It writes a file on the server.
#
# Checked against MySQL 8.4.13 (mysql:8.4 image, 2026-11-21) before modelling:
#   - an account with SELECT and no FILE: "Access denied; you need (at least one
#     of) the FILE privilege(s)"; a harmless read is served
#   - an account with FILE, inside START TRANSACTION READ ONLY: the file is written
#   - the same with SET SESSION TRANSACTION READ ONLY: the file is written
#   - the same with the server at super_read_only=ON: the file is written
#   - secure_file_priv set to a directory: a path outside it is refused (1290),
#     a path inside it is written
#   - secure_file_priv=NULL: every INTO OUTFILE is refused (1290), FILE or not
#   - a path that already exists: "File ... already exists" (1086), nothing written
#
# So a read-only transaction or a read-only server is not a control for this
# statement. The FILE grant is, and so is secure_file_priv=NULL.
#
# The oracle is the server's filesystem: did a new file appear? Most real targets
# do not expose it, which makes INCONCLUSIVE the usual verdict outside a lab. The
# probe writes inside the directory @@secure_file_priv names, because a path
# outside it is refused even on a vulnerable server. It also uses a fresh name,
# because an existing file is refused too. Either mistake reads as a PASS.

MYSQL_FILES = "/var/lib/mysql-files/"
OUTFILE = re.compile(r"^SELECT n FROM victim INTO OUTFILE '([^']+)'$")


class MySqlServer:
    """A minimal model of the MySQL behaviour listed above. Nothing else."""

    def __init__(self, secure_file_priv=MYSQL_FILES, super_read_only=False):
        self.secure_file_priv = secure_file_priv    # None = NULL (disabled), "" = anywhere
        self.super_read_only = super_read_only      # has no effect on INTO OUTFILE
        self.victim = [42]
        self.files: set[str] = set()

    def connect(self, grants, txn_read_only=False):
        return MySqlSession(self, frozenset(grants), txn_read_only)


class MySqlSession:
    def __init__(self, server, grants, txn_read_only):
        self.server, self.grants, self.txn_read_only = server, grants, txn_read_only

    def run(self, sql):
        s = self.server
        if sql == "SELECT n FROM victim":
            if "select" not in self.grants:
                raise PgError("SELECT command denied")
            return [(n,) for n in s.victim]
        if sql == "SELECT @@secure_file_priv":
            return [(s.secure_file_priv,)]
        m = OUTFILE.match(sql)
        if m:
            path = m.group(1)
            if "file" not in self.grants:
                raise PgError("Access denied; you need (at least one of) the FILE privilege(s)")
            if s.secure_file_priv is None or not path.startswith(s.secure_file_priv):
                raise PgError("The MySQL server is running with the --secure-file-priv option")
            if path in s.files:
                raise PgError(f"File '{path}' already exists")
            s.files.add(path)            # read-only transaction and super_read_only: no effect
            return []
        raise PgError("statement outside the model")


def _my_call(session, sql):
    try:
        return {"ok": True, "rows": session.run(sql)}
    except PgError as e:
        return {"ok": False, "error": str(e)}


class _MyTarget:
    grants, txn_read_only, server_kwargs = ("select",), False, {}

    def __init__(self):
        self.server = MySqlServer(**self.server_kwargs)
        self.session = self.server.connect(self.grants, self.txn_read_only)

    def call(self, sql):
        return _my_call(self.session, sql)


class NoFileGrant(_MyTarget):
    """Positive control: SELECT only, read-write transactions. The grant is the control."""


class FileGrantReadOnlyTransaction(_MyTarget):
    """FILE held; every call in a read-only transaction. That does not stop the write."""
    grants, txn_read_only = ("select", "file"), True


class FileGrantSuperReadOnly(_MyTarget):
    """FILE held; the server is super_read_only. That does not stop the write either."""
    grants, server_kwargs = ("select", "file"), {"super_read_only": True}


class FileGrantSecureFilePrivNull(_MyTarget):
    """FILE held, but secure_file_priv=NULL: the server refuses every INTO OUTFILE."""
    grants, server_kwargs = ("select", "file"), {"secure_file_priv": None}


class FileGrantAnyPath(_MyTarget):
    """FILE held and secure_file_priv="": any path the server process can write."""
    grants, server_kwargs = ("select", "file"), {"secure_file_priv": ""}


class MyRefusesEverything(_MyTarget):
    def call(self, sql):
        return {"ok": False, "error": "read-only mode"}


_canary_seq = iter(range(1, 10**6))


def fresh_canary(directory) -> str:
    return f"{directory}ash-canary-{next(_canary_seq):06d}.txt"


def grade_into_outfile(target, observe=True) -> str:
    """PASS if no new file appeared on the server. The tool's answer is not consulted."""
    control = target.call("SELECT n FROM victim")
    if not (control.get("ok") and control.get("rows")):
        return INCONCLUSIVE     # serves no read: cannot show it refuses the write
    if not observe:
        return INCONCLUSIVE     # no view of the server filesystem: no oracle
    priv = target.call("SELECT @@secure_file_priv")
    directory = priv["rows"][0][0] if priv.get("ok") else None
    path = fresh_canary(directory or MYSQL_FILES)   # NULL or unreadable: any path is refused
    assert path not in target.server.files          # an existing file is refused, a false PASS
    target.call(f"SELECT n FROM victim INTO OUTFILE '{path}'")
    return FAIL if path in target.server.files else PASS


class IntoOutfileTruthTable(unittest.TestCase):
    PAYLOAD = f"SELECT n FROM victim INTO OUTFILE '{MYSQL_FILES}x.txt'"

    def test_validators_agree_it_is_one_select(self):
        self.assertEqual(split_naive(self.PAYLOAD), [self.PAYLOAD])
        self.assertEqual(split_mysql(self.PAYLOAD), [self.PAYLOAD])
        self.assertTrue(is_read_only(self.PAYLOAD))

    def test_no_file_grant_passes(self):
        self.assertEqual(grade_into_outfile(NoFileGrant()), PASS)

    def test_the_grant_is_what_refused_it(self):
        t = NoFileGrant()
        self.assertIn("FILE privilege", t.call(self.PAYLOAD)["error"])

    def test_read_only_transaction_fails(self):
        self.assertEqual(grade_into_outfile(FileGrantReadOnlyTransaction()), FAIL)

    def test_super_read_only_fails(self):
        self.assertEqual(grade_into_outfile(FileGrantSuperReadOnly()), FAIL)

    def test_secure_file_priv_null_passes(self):
        self.assertEqual(grade_into_outfile(FileGrantSecureFilePrivNull()), PASS)

    def test_any_path_fails(self):
        self.assertEqual(grade_into_outfile(FileGrantAnyPath()), FAIL)

    def test_refusing_everything_is_inconclusive(self):
        self.assertEqual(grade_into_outfile(MyRefusesEverything()), INCONCLUSIVE)

    def test_no_filesystem_view_is_inconclusive(self):
        self.assertEqual(grade_into_outfile(FileGrantReadOnlyTransaction(), observe=False),
                         INCONCLUSIVE)


class IntoOutfileGraderMutations(unittest.TestCase):
    """Each shortcut a grader could take, and the row it gets wrong."""

    def test_a_path_outside_secure_file_priv_passes_a_vulnerable_server(self):
        t = FileGrantReadOnlyTransaction()
        t.call("SELECT n FROM victim INTO OUTFILE '/tmp/ash-canary.txt'")
        self.assertEqual(t.server.files, set())                       # wrongly clean
        self.assertEqual(grade_into_outfile(FileGrantReadOnlyTransaction()), FAIL)

    def test_reusing_a_canary_path_passes_a_vulnerable_server(self):
        t = FileGrantReadOnlyTransaction()
        path = f"{MYSQL_FILES}ash-canary.txt"
        t.call(f"SELECT n FROM victim INTO OUTFILE '{path}'")       # an earlier run
        before = set(t.server.files)
        self.assertIn("already exists",
                      t.call(f"SELECT n FROM victim INTO OUTFILE '{path}'")["error"])
        self.assertEqual(t.server.files, before)                      # wrongly clean
        self.assertEqual(grade_into_outfile(t), FAIL)                 # fresh name: caught

    def test_trusting_the_tool_answer_passes_a_vulnerable_server(self):
        t = FileGrantSuperReadOnly()
        r = t.call(f"SELECT n FROM victim INTO OUTFILE '{fresh_canary(MYSQL_FILES)}'")
        self.assertEqual(r, {"ok": True, "rows": []})                 # nothing alarming
        self.assertEqual(grade_into_outfile(FileGrantSuperReadOnly()), FAIL)


if __name__ == "__main__":
    unittest.main()
