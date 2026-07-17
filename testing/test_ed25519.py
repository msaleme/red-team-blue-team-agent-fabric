#!/usr/bin/env python3
"""Conformance for the pure-stdlib Ed25519 (RFC 8032) used by receipt attestations.

We verify the curve parameters (canonical base point, correct group order) and the
signature properties the receipt experiment relies on: a valid signature verifies,
a tampered message fails, and a different key cannot verify (asymmetric
unforgeability — the property an HMAC could not provide).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocol_tests import _ed25519 as ed


class TestEd25519(unittest.TestCase):
    def test_base_point_is_canonical(self):
        # The Ed25519 base point compresses to 0x5866..66 (y = 4/5).
        self.assertEqual(
            ed._point_compress(ed._G).hex(),
            "5866666666666666666666666666666666666666666666666666666666666666")

    def test_base_point_has_prime_order_L(self):
        self.assertTrue(ed._point_equal(ed._point_mul(ed._L, ed._G), ed._NEUTRAL))

    def test_sign_verify_roundtrip(self):
        seed = bytes(range(32))
        pub = ed.secret_to_public(seed)
        msg = b"receipt-canonical-body"
        self.assertTrue(ed.verify(pub, msg, ed.sign(seed, msg)))

    def test_tampered_message_fails(self):
        seed = bytes(range(32))
        pub = ed.secret_to_public(seed)
        sig = ed.sign(seed, b"authorized")
        self.assertFalse(ed.verify(pub, b"authorised-tampered", sig))

    def test_wrong_key_cannot_verify(self):
        # The asymmetric property: another party's public key cannot verify, and
        # without the private seed they cannot forge the signature.
        s1, s2 = bytes(range(32)), bytes(range(1, 33))
        p2 = ed.secret_to_public(s2)
        msg = b"checker-attestation"
        sig = ed.sign(s1, msg)
        self.assertFalse(ed.verify(p2, msg, sig))

    def test_deterministic(self):
        seed = bytes(range(32))
        self.assertEqual(ed.sign(seed, b"x"), ed.sign(seed, b"x"))


if __name__ == "__main__":
    unittest.main()
