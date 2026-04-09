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
