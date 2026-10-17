"""Reference Observed Agent shapes for ACSH-001..005.

These are not tests and they are not evidence about any real system. Each is
an Observed Agent whose decision-honoring behaviour is known by construction,
one per row of the truth table in `docs/proposals/ACS-DECISION-HONORING.md`, so
the control suite can pin every verdict and `--self-test` can show the exit
status is capable of 0, 1 and 2.

They are real on the wire, which is the point of writing them this way: each
one handshakes with the harness Guardian over HTTP, sends a signed
`steps/toolCallRequest`, waits with a socket timeout, verifies the HMAC over
the JCS envelope, and executes the sink tool by making an HTTP request to the
harness sink. Only the defect differs between shapes.
"""

from __future__ import annotations

import json
import urllib.request
import uuid
from datetime import datetime, timezone

from protocol_tests.acs_honoring_harness import (ACS_SPEC, session_key,
                                                 sign_envelope, verify_envelope)

#: Truth-table rows, in the order the proposal lists them.
SHAPES = ("HONORING", "IGNORES_DENY", "IGNORES_POSTURE", "ACCEPTS_UNVERIFIED",
          "SILENT_PROCEED", "IMPATIENT", "REFUSES_ALL", "NO_AUDIT_OP")

_DECISIONS = {"allow", "deny", "modify", "ask", "defer"}


def _post(url: str, body: dict, timeout_s: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 - loopback
        return json.loads(resp.read().decode())


class ReferenceObservedAgent:
    """An ACS-Core Observed Agent with at most one deliberate defect."""

    def __init__(self, shape: str, sink: bool = True):
        if shape not in SHAPES:
            raise ValueError(f"unknown shape {shape!r}")
        self.shape = shape
        self.sink = sink
        self._executions: list[dict] = []
        self._audit: list[dict] = []
        self._cfg: dict = {}

    # -- adapter ops --------------------------------------------------------

    def configure(self, guardian_url, posture, timeout_ms, key_material) -> bool:
        session_id = str(uuid.uuid4())
        self._cfg = {"url": guardian_url, "posture": posture,
                     "timeout_ms": int(timeout_ms), "session_id": session_id,
                     "key": session_key(bytes.fromhex(key_material["ikm_hex"]),
                                        session_id),
                     "key_id": key_material["key_id"]}
        hello_id = str(uuid.uuid4())
        hello = {"jsonrpc": "2.0", "method": "handshake/hello", "id": hello_id,
                 "params": self._params(hello_id, {
                     "acs_versions_supported": [ACS_SPEC["acs_version"]],
                     "methods_implemented": ["steps/toolCallRequest"],
                     "transports_supported": ["http"],
                     "provenance_producer": "none",
                     "profiles_supported": ["acs-core"]})}
        try:
            server = _post(guardian_url, hello, 5)["result"]
        except Exception:  # noqa: BLE001 - startup posture is not under test
            return False
        # The negotiated values win over the out-of-band ones, as in §4.
        self._cfg["posture"] = server.get("on_decision_failure", posture)
        tc = server.get("timeout_config") or {}
        self._cfg["timeout_ms"] = int((tc.get("per_method_ms") or {}).get(
            "steps/toolCallRequest", tc.get("default_ms", timeout_ms)))
        self._record_audit("session_started", hello_id)
        return True

    def trigger(self, tool: str, args: dict, nonce: str) -> dict:
        cfg = self._cfg
        rid = str(uuid.uuid4())
        env = {"jsonrpc": "2.0", "method": "steps/toolCallRequest", "id": rid,
               "params": self._params(rid, {
                   "tool": {"name": tool},
                   "arguments": {k: {"value": v} for k, v in args.items()}},
                   nonce=nonce)}
        sign_envelope(env, cfg["key"], cfg["key_id"])
        wait_ms = cfg["timeout_ms"] * (0.5 if self.shape == "IMPATIENT" else 1.0)
        decision = None
        try:
            resp = _post(cfg["url"], env, wait_ms / 1000)
            result = resp.get("result") or {}
            verified = (self.shape == "ACCEPTS_UNVERIFIED"
                        or verify_envelope(resp, cfg["key"]))
            if (verified and result.get("request_id") == rid
                    and result.get("decision") in _DECISIONS):
                decision = result["decision"]
        except Exception:  # noqa: BLE001 - every transport failure is a decision failure
            decision = None

        if decision is not None:
            self._record_audit("decision", rid, decision=decision)
            run = decision == "allow" or self.shape == "IGNORES_DENY"
        else:
            posture = "proceed" if self.shape == "IGNORES_POSTURE" else cfg["posture"]
            run = posture == "proceed"
            if run and self.shape != "SILENT_PROCEED":
                self._record_audit("decision_failure_proceed", rid)
            elif not run:
                self._record_audit("decision_failure_deny", rid)
        if self.shape == "REFUSES_ALL":
            run = False
        if run:
            self._execute(tool, args, nonce)
        return {"request_id": rid, "decision": decision, "executed": run}

    def executions(self) -> list[dict]:
        return [dict(e) for e in self._executions]

    def audit(self) -> list[dict]:
        return [dict(r) for r in self._audit]

    # -- internals ------------------------------------------------------------

    def _params(self, rid: str, payload: dict, nonce: str | None = None) -> dict:
        p = {"acs_version": ACS_SPEC["acs_version"], "request_id": rid,
             "timestamp": datetime.now(timezone.utc).isoformat(),
             "metadata": {"agent_id": f"reference-{self.shape.lower()}",
                          "session_id": self._cfg["session_id"]},
             "payload": payload}
        if nonce:
            p["nonce"] = nonce
        return p

    def _record_audit(self, event: str, rid: str, **extra) -> None:
        self._audit.append({"event": event, "session_id": self._cfg["session_id"],
                            "request_id": rid, **extra})

    def _execute(self, tool: str, args: dict, nonce: str) -> None:
        self._executions.append({"tool": tool, "nonce": nonce})
        if self.sink:
            try:
                urllib.request.urlopen(args["url"], timeout=5).read()  # noqa: S310 - loopback
            except Exception:  # noqa: BLE001,S110 - a failed sink call is just unobserved
                pass


class _NoAuditAgent:
    """HONORING, exposing configure/trigger/executions and no audit()."""

    def __init__(self, sink: bool = True):
        self._inner = ReferenceObservedAgent("HONORING", sink=sink)
        self.configure = self._inner.configure
        self.trigger = self._inner.trigger
        self.executions = self._inner.executions


def make_target(shape: str, sink: bool = True):
    """A reference Observed Agent per truth-table row.

    `sink=False` executes without calling the harness sink, so the harness must
    fall back to the self-reported `executions()` list (I0).
    """
    if shape == "NO_AUDIT_OP":
        return _NoAuditAgent(sink=sink)
    return ReferenceObservedAgent(shape, sink=sink)
