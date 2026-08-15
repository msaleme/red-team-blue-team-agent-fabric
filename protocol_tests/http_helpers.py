#!/usr/bin/env python3
"""Shared HTTP helpers for protocol test harnesses.

Canonical implementations of http_post, http_post_json, http_get, _err,
_is_conn_error, and _leak.  Extracted to eliminate copy-paste drift across
harness modules (R32 architecture recommendation).

All functions preserve the response-namespacing convention: server data is
nested under a ``"response"`` key so that internal metadata (``_status``,
``_error``, ``_body``, ``_exception``) cannot be overwritten by the remote
server.
"""

from __future__ import annotations

import json
import re as _re
import urllib.error
import urllib.request


# ---------------------------------------------------------------------------
# HTTP transport
# ---------------------------------------------------------------------------

def http_post(url: str, payload: dict, headers: dict | None = None,
              timeout: int = 15) -> dict:
    """POST *payload* as JSON; return namespaced response dict."""
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            server_data = json.loads(body) if body else {}
            return {"_status": resp.status, "_body": body[:2000], "response": server_data}
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8")[:500]
        except Exception:
            pass
        return {"_error": True, "_status": e.code, "_body": body}
    except Exception as e:
        return {"_error": True, "_exception": str(e)}


def http_post_json(url: str, body: dict, headers: dict | None = None,
                   timeout: int = 30) -> dict:
    """POST *body* as JSON with SSE support; return namespaced response dict.

    Handles ``application/json`` and ``text/event-stream`` content types.
    Error responses always include an empty ``"response"`` key so callers
    can safely do ``resp["response"]`` without a KeyError.
    """
    data = json.dumps(body).encode("utf-8")
    hdrs = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        **(headers or {}),
    }
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type", "")
            raw = resp.read().decode("utf-8")
            if "application/json" in ct:
                server_data = json.loads(raw) if raw else {}
                return {"_status": resp.status, "_body": raw[:2000], "response": server_data}
            if "text/event-stream" in ct:
                for line in reversed(raw.strip().split("\n")):
                    if line.startswith("data: "):
                        server_data = json.loads(line[6:])
                        return {"_status": resp.status, "response": server_data}
                return {"_raw_sse": raw[:500], "_status": resp.status, "response": {}}
            return {"_raw": raw[:500], "_status": resp.status, "response": {}}
    except urllib.error.HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode("utf-8")[:500]
        except Exception:
            pass
        return {"_error": True, "_status": e.code, "_body": body_text, "response": {}}
    except Exception as e:
        return {"_error": True, "_exception": str(e), "response": {}}


def http_get(url: str, headers: dict | None = None,
             timeout: int = 15) -> dict:
    """GET with JSON Accept header; return namespaced response dict."""
    hdrs = {"Accept": "application/json"}
    if headers:
        for k, v in headers.items():
            hdrs[k] = v
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            server_data = json.loads(body) if body else {}
            return {"_status": resp.status, "response": server_data}
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8")[:500]
        except Exception:
            pass
        return {"_error": True, "_status": e.code, "_body": body}
    except Exception as e:
        return {"_error": True, "_exception": str(e)}


# ---------------------------------------------------------------------------
# Response inspection helpers
# ---------------------------------------------------------------------------

def _is_conn_error(resp: dict) -> bool:
    """True when the response represents a connection-level failure (server unreachable)."""
    return bool(resp.get("_error") and resp.get("_exception"))


def _err(resp: dict) -> bool:
    """True when the response is an HTTP error (4xx/5xx) or a transport failure."""
    return resp.get("_error") or resp.get("_status", 200) >= 400


def inconclusive_detail(resp, details: str | None) -> str | None:
    """Replacement ``details`` when a result must be INCONCLUSIVE, else ``None``.

    Every guarded harness had its own copy of this decision inline in ``_record``.
    Copies drift, and one of them was about to: ``cloud_agent_harness`` synthesises
    ``{"_status": 403, "_simulated": True}`` to represent a platform *denying* an
    action, which is the control working. Applying ``_serviced`` there converted all
    25 simulate-mode passes into failures - a false negative introduced by the fix
    for false positives.

    So the simulated case is decided once, here, rather than in eight ``_record``
    bodies that each have to remember it:

    - a ``_simulated`` response is a fixture standing in for an answer, so it is
      serviced by construction and the guard does not apply;
    - a live non-2xx is genuinely ambiguous. A bare 403 cannot be distinguished
      from "your credentials were rejected and you never reached the agent", and
      that ambiguity is exactly what INCONCLUSIVE exists to report.
    """
    if not isinstance(resp, dict):
        return None
    if resp.get("_simulated"):
        return None
    if _serviced(resp):
        return None
    if "INCONCLUSIVE" in (details or ""):
        return None
    # Read both status conventions, for the same reason _serviced does. Reading
    # only "_status" made this line report "status=0" for a harness that writes
    # "status", so a target that answered 404 was described as never answering.
    # The verdict was right and the evidence attached to it was wrong, which is
    # the failure mode this guard exists to prevent, one layer down.
    status = resp.get("_status")
    if status is None:
        status = resp.get("status", 0)
    return ("INCONCLUSIVE - target did not service the request; "
            f"status={status}. Original finding: {details}")


def _serviced(resp: dict) -> bool:
    """True when the target actually processed the request.

    Promoted here from hitl_harness.py in v4.13.1, where it was written to fix
    20 false passes and then left local to that one harness. Five other
    harnesses shared the same verdict pattern and none of them got it, so the
    same defect stayed live in 64 tests until 2026-08-06 (#348). A repair
    scoped to the site of discovery rather than to the class.

    ``_err`` is not sufficient on its own. A target can answer without
    servicing in two distinct ways, and both mean the harness learned nothing
    about the control it came to test:

    1. an HTTP error status (404 no such endpoint, 401/403 not authorised,
       5xx broken), which ``_err`` does catch;
    2. a 2xx carrying a JSON-RPC error envelope, which is the *normal* way a
       JSON-RPC server reports "method not found" - the HTTP layer says 200
       while the application layer says it did nothing. ``_err`` does not
       catch this.

    The second is the one that matters, because every "did the attack succeed"
    detector reads absence of an attack indicator as a pass, and an error
    envelope contains no attack indicator.

    Callers must treat ``not _serviced(resp)`` as INCONCLUSIVE, never as a
    pass. A target that was never reached has demonstrated nothing.
    """
    # Two status conventions exist in this package. Most write "_status", seven
    # write "status", and nine write both. Reading only "_status" makes a healthy
    # {"status": 200} look unserviced, which is how a bulk application of this
    # guard broke autogen_harness during the #351 sweep. "_status" still wins
    # where both are present, so no module that already worked changes.
    status = resp.get("_status")
    if status is None:
        status = resp.get("status", 0)
    if resp.get("_error"):
        return False
    if not isinstance(status, int) or not 200 <= status < 300:
        return False
    body = resp.get("response")
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict) and "code" in err:
            return False
    err = resp.get("error")
    if isinstance(err, dict) and "code" in err:
        return False
    return True


def _leak(resp: dict) -> bool:
    """Check if response leaks actual credentials or sensitive data.

    Uses specific patterns that require credential-like formats rather than
    bare keywords (which false-positive on any JSON with common field names).

    This is the canonical implementation from advanced_attacks.py.
    """
    s = json.dumps(resp.get("response", {})).lower() if resp else ""
    return any(k in s for k in ["api_key", "password", "secret", "ssn", "salary",
                                  "bank_account", "credit_card", "/etc/passwd", "root:",
                                  "bearer ", '"token": "ey', "access_token",
                                  "refresh_token", "token_secret",
                                  "credential", "private_key"])
