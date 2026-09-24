"""Reference target shapes for CR-001..005.

These are not tests and they are not evidence about any real system. Each is a
target whose behaviour is known by construction, one per row of the truth table
in `docs/proposals/CAPABILITY-RESIDUE.md`, so the control suite can pin every
verdict and the module's `--self-test` can show its exit status is capable of
0, 1 and 2.

Moved here from `testing/test_capability_residue_controls.py` (2026-09-24) so
the test and `--self-test` exercise one fixture rather than two copies.
"""

from __future__ import annotations

import base64

#: Truth-table rows, in the order the proposal lists them.
SHAPES = ("REDACTING", "ECHOING", "ENCODING_ONLY", "RESUME_LEAK", "STALE_GRANT",
          "SILENT", "REJECTS_ALL", "UNREACHABLE")


def make_target(shape: str):
    """A target fixture per truth-table row. Closes over its own revocation state."""
    revoked: set[str] = set()
    sessions: dict[str, str] = {}

    def target(request: dict) -> dict | None:
        cap = request.get("capability")
        op = request.get("op")

        if shape == "UNREACHABLE":
            return None

        if op == "revoke":
            revoked.add(cap)
            return {"_status": 200, "accepted": True, "result": "revoked"}

        if op == "resume":
            sid = request.get("session")
            held = sessions.get(sid)
            if shape == "RESUME_LEAK" and held:
                # redacted live, disclosed on resume: the whole point of CR-003
                return {"_status": 200, "accepted": True,
                        "handoff": {"restored_context": f"token={held}"}}
            if shape == "SILENT":
                # SILENT emits nothing inspectable on ANY path. A shape that
                # leaked an artifact here would stop being the zero-denominator
                # row the table needs it to be.
                return {"_status": 200, "accepted": True}
            if shape == "ECHOING" and held:
                # ECHOING echoes on every emission path, or it is not that shape.
                return {"_status": 200, "accepted": True,
                        "handoff": {"bearer": held}}
            if shape == "REJECTS_ALL":
                return {"_status": 403, "accepted": False, "error": "denied"}
            return {"_status": 200, "accepted": True, "result": "resumed"}

        if shape == "REJECTS_ALL":
            return {"_status": 403, "accepted": False, "error": "denied"}

        honoured = cap not in revoked or shape == "STALE_GRANT"
        if not honoured:
            return {"_status": 401, "accepted": False, "error": "revoked"}

        sid = f"sess-{len(sessions)}"
        sessions[sid] = cap
        resp: dict = {"_status": 200, "accepted": True, "session": sid}

        if shape == "SILENT":
            return resp  # accepted, and nothing inspectable comes back

        if shape == "ECHOING":
            resp["trace"] = {"step": "auth", "bearer": cap}
        elif shape == "ENCODING_ONLY":
            resp["trace"] = {"step": "auth",
                             "ctx": base64.b64encode(cap.encode()).decode()}
            resp["result"] = "ok"
        else:
            resp["trace"] = {"step": "auth", "bearer": "[redacted]"}
            resp["result"] = "ok"
        return resp

    return target
