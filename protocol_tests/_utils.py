"""Shared utilities for the Agent Security Harness protocol_tests package.

This module provides zero-dependency helpers that are used across multiple
harness files.  Import from here instead of copy-pasting implementations.

    from protocol_tests._utils import Severity, wilson_ci, jsonrpc_request, http_post_json
    from protocol_tests._utils import HIDDEN_INSTRUCTION_PATTERN
"""

from __future__ import annotations

import json
import math
import re
import uuid
import urllib.error
import urllib.request
from enum import Enum


#: Prompt injection markers — shared across skill_security_harness.py and mcp_harness.py
HIDDEN_INSTRUCTION_PATTERN = re.compile(
    r'ignore\s+(?:all\s+)?previous\s+instructions'
    r'|you\s+are\s+now\s+(?:unrestricted|unfiltered|DAN)'
    r'|(?<!\w)system\s*:\s*'
    r'|<\s*(?:system|instruction|hidden|secret)\s*>'
    r'|\bdo\s+not\s+tell\s+the\s+user\b'
    r'|\bsend\s+(?:all|the)\s+(?:data|context|conversation)\s+to\b'
    r'|\bexfiltrate\b'
    r'|\bforward\s+(?:all|every)\b.*\bto\b',
    re.IGNORECASE,
)


class Severity(Enum):
    """Test severity classification (P0 = most critical)."""

    CRITICAL = "P0-Critical"
    HIGH = "P1-High"
    MEDIUM = "P2-Medium"
    LOW = "P3-Low"


def wilson_ci(passed: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Compute a Wilson score confidence interval for a binomial proportion.

    Args:
        passed: Number of successes.
        total:  Total number of trials.
        z:      Z-score for the desired confidence level (default 1.96 → 95%).

    Returns:
        A (lower, upper) tuple, both rounded to 4 decimal places.
        Returns (0.0, 0.0) when *total* is zero to avoid division by zero.
    """
    if total == 0:
        return (0.0, 0.0)
    p_hat = passed / total
    z2 = z * z
    n = total
    denominator = 1 + z2 / n
    center = (p_hat + z2 / (2 * n)) / denominator
    spread = z * math.sqrt((p_hat * (1 - p_hat) / n + z2 / (4 * n * n))) / denominator
    return (round(max(0.0, center - spread), 4), round(min(1.0, center + spread), 4))


def jsonrpc_request(
    method: str,
    params: dict | None = None,
    id: str | None = None,
) -> dict:
    """Build a JSON-RPC 2.0 request message.

    Args:
        method: The RPC method name (e.g. ``"tools/list"``).
        params: Optional parameters dict to include in the request.
        id:     Optional request ID.  A random 8-character UUID fragment is
                used when not supplied.

    Returns:
        A dict representing a complete JSON-RPC 2.0 request.
    """
    msg: dict = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    msg["id"] = id or str(uuid.uuid4())[:8]
    return msg


def http_post_json(
    url: str,
    payload: dict,
    headers: dict | None = None,
    timeout: int = 15,
) -> dict:
    """POST a JSON payload and return the parsed response dict.

    Always returns a plain ``dict``; on any error the dict contains an
    ``_error`` key so callers can check ``resp.get("_error")`` without
    catching exceptions.

    Args:
        url:     Target URL.
        payload: Request body (will be JSON-serialised).
        headers: Additional HTTP headers to merge with the default
                 ``Content-Type``/``Accept`` pair.
        timeout: Socket timeout in seconds (default 15).

    Returns:
        Parsed JSON response dict, with ``_status`` injected on success.
        On HTTP errors: ``{"_error": True, "_status": <code>, "_body": ...}``.
        On network/other errors: ``{"_error": True, "_exception": ..., "_message": ...}``.
    """
    data = json.dumps(payload).encode("utf-8")
    hdrs: dict = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        **(headers or {}),
    }
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            result = json.loads(raw) if raw else {}
            result["_status"] = resp.status
            return result
    except urllib.error.HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode("utf-8")[:500]
        except Exception:
            pass
        return {"_error": True, "_status": e.code, "_body": body_text}
    except Exception as e:
        return {"_error": True, "_exception": type(e).__name__, "_message": str(e)[:300]}
