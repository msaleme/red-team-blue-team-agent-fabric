"""RFC 8785 JSON Canonicalization Scheme (JCS), vendored and minimal.

Vendored rather than added as a dependency (owner decision on #650) so the
wheel stays dependency-free. ACS v0.1.4 §10 signs "the RFC 8785 (JCS)
canonicalization of the request or response envelope with the `signature`
field removed, encoded as UTF-8", so the ACS honoring family cannot sign or
verify a decision without it.

What it does, per RFC 8785 §3.2:

* objects: members sorted by their names as arrays of UTF-16 code units
  (§3.2.3), not by code point. The two orders differ for characters above
  U+FFFF, which is the case `testing/test_jcs.py` pins;
* strings: only `"`, `\\` and U+0000..U+001F are escaped, with the short forms
  `\\b \\f \\n \\r \\t` and lowercase `\\u00xx` otherwise; everything else is
  emitted as UTF-8 (§3.2.2.2);
* numbers: the ECMAScript `Number.prototype.toString` form of an IEEE 754
  double (§3.2.2.3), derived from Python's shortest round-trip `repr`;
* literals: `null`, `true`, `false`; no whitespace anywhere.

Limits, stated rather than hidden:

* Input is the Python value `json.loads` produces (dict, list, str, int,
  float, bool, None). Anything else raises `TypeError`.
* An `int` outside +/-2**53 raises `ValueError`. JCS serialises numbers as
  doubles, so such an int has no exact canonical form (I-JSON, RFC 7493).
  Integers inside that range are emitted exactly.
* NaN and the infinities raise `ValueError` (RFC 8785 §3.2.2.3).
* A string holding a lone surrogate raises `ValueError`; it cannot be encoded
  as UTF-8.
* Duplicate member names cannot be represented in a dict, so they are not
  detected here. Parse with a hook that rejects them if that matters.

It is checked against the RFC 8785 examples and the Appendix B number vectors
in `testing/test_jcs.py`. It is enough for the envelopes the ACS module builds
and reads. It is not offered as a general-purpose library.
"""

from __future__ import annotations

import math

_MAX_SAFE_INT = 2 ** 53

_SHORT_ESCAPES = {
    0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r",
    0x22: '\\"', 0x5C: "\\\\",
}


def canonicalize(value) -> bytes:
    """The RFC 8785 canonical form of *value*, as UTF-8 bytes."""
    return _serialize(value).encode("utf-8")


def _serialize(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise ValueError(f"integer {value} has no exact JCS form (|n| > 2**53)")
        return str(value)
    if isinstance(value, float):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(v) for v in value) + "]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise TypeError(f"object member name must be str, not {type(k).__name__}")
        names = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_string(k) + ":" + _serialize(value[k])
                              for k in names) + "}"
    raise TypeError(f"{type(value).__name__} is not a JSON value")


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            raise ValueError("lone surrogate cannot be canonicalized")
        if cp in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[cp])
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(x: float) -> str:
    """ECMAScript Number::toString for a finite double (ECMA-262 §7.1.12.1)."""
    if math.isnan(x) or math.isinf(x):
        raise ValueError("NaN and Infinity are not valid JSON numbers")
    if x == 0:
        return "0"  # also -0
    sign = "-" if x < 0 else ""
    # repr() is the shortest digit string that round-trips, which is what the
    # ECMAScript algorithm selects. Split it into digits and a decimal exponent.
    r = repr(abs(x))
    mantissa, _, exp = r.partition("e")
    exp_i = int(exp) if exp else 0
    if "." in mantissa:
        int_part, frac = mantissa.split(".")
    else:
        int_part, frac = mantissa, ""
    digits = (int_part + frac).lstrip("0")
    # n: position of the decimal point relative to the start of `digits`.
    n = len(int_part) + exp_i
    lead_zeros = len(int_part + frac) - len((int_part + frac).lstrip("0"))
    n -= lead_zeros
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        e_s = f"+{e}" if e >= 0 else str(e)
        body = (digits[0] + ("." + digits[1:] if k > 1 else "")) + "e" + e_s
    return sign + body
