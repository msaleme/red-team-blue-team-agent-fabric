#!/usr/bin/env python3
"""Pure-Python Ed25519 (RFC 8032) — stdlib only (hashlib).

Provided so the receipt claim-level harness can demonstrate *asymmetric signer
provenance* (a verifier holding only public keys; a party unable to forge another
authority's signature) without an external dependency, honoring the repo's
zero-extra-dependency guarantee for ``protocol_tests``.

This follows the RFC 8032 Ed25519 construction and parameters. It is NOT
constant-time and is intended for test/reference use, not production signing.
The test suite validates the curve parameters (canonical base-point encoding and
prime subgroup order) and the signature properties this harness relies on
(determinism, tamper detection, and cross-key unforgeability). It is NOT
checked for byte-level interoperability against the RFC 8032 message test
vectors, and is not a substitute for a maintained cryptographic library.

API:
    secret_to_public(seed32) -> pub32
    sign(seed32, msg) -> sig64
    verify(pub32, msg, sig64) -> bool
"""
from __future__ import annotations

import hashlib

_p = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _sha512(s: bytes) -> bytes:
    return hashlib.sha512(s).digest()


def _modp_inv(x: int) -> int:
    return pow(x, _p - 2, _p)


_d = (-121665 * _modp_inv(121666)) % _p
_modp_sqrt_m1 = pow(2, (_p - 1) // 4, _p)


def _recover_x(y: int, sign: int):
    if y >= _p:
        return None
    x2 = ((y * y - 1) * _modp_inv(_d * y * y + 1)) % _p
    if x2 == 0:
        if sign:
            return None
        return 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = (x * _modp_sqrt_m1) % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


_g_y = (4 * _modp_inv(5)) % _p
_g_x = _recover_x(_g_y, 0)
_G = (_g_x, _g_y, 1, (_g_x * _g_y) % _p)
_NEUTRAL = (0, 1, 1, 0)


def _point_add(P, Q):
    A = ((P[1] - P[0]) * (Q[1] - Q[0])) % _p
    B = ((P[1] + P[0]) * (Q[1] + Q[0])) % _p
    C = (2 * P[3] * Q[3] * _d) % _p
    D = (2 * P[2] * Q[2]) % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return ((E * F) % _p, (G * H) % _p, (F * G) % _p, (E * H) % _p)


def _point_mul(s: int, P):
    Q = _NEUTRAL
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _point_equal(P, Q) -> bool:
    if (P[0] * Q[2] - Q[0] * P[2]) % _p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % _p != 0:
        return False
    return True


def _point_compress(P) -> bytes:
    zinv = _modp_inv(P[2])
    x = (P[0] * zinv) % _p
    y = (P[1] * zinv) % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % _p)


def _secret_expand(seed: bytes):
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return a, h[32:]


def secret_to_public(seed: bytes) -> bytes:
    a, _ = _secret_expand(seed)
    return _point_compress(_point_mul(a, _G))


def sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _secret_expand(seed)
    A = _point_compress(_point_mul(a, _G))
    r = int.from_bytes(_sha512(prefix + msg), "little") % _L
    R = _point_mul(r, _G)
    Rs = _point_compress(R)
    h = int.from_bytes(_sha512(Rs + A + msg), "little") % _L
    s = (r + h * a) % _L
    return Rs + int.to_bytes(s, 32, "little")


def verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _point_decompress(public)
    if A is None:
        return False
    Rs = signature[:32]
    R = _point_decompress(Rs)
    if R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(_sha512(Rs + public + msg), "little") % _L
    sB = _point_mul(s, _G)
    hA = _point_mul(h, A)
    return _point_equal(sB, _point_add(R, hA))
