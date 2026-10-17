"""The vendored RFC 8785 canonicaliser against the RFC's own vectors.

ACSH-001..005 sign and verify Guardian decisions over the JCS form of the
envelope (ACS v0.1.4 §10). A canonicaliser that is wrong in a way both sides of
a self-test share would still verify, so these vectors come from RFC 8785, not
from the module.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from protocol_tests.jcs import canonicalize  # noqa: E402


def _f(bits: str) -> float:
    return struct.unpack(">d", bytes.fromhex(bits))[0]


# RFC 8785 Appendix B: IEEE 754 bit pattern -> canonical string.
APPENDIX_B = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


@pytest.mark.parametrize("bits,expected", APPENDIX_B)
def test_appendix_b_numbers(bits, expected):
    assert canonicalize(_f(bits)) == expected.encode()


@pytest.mark.parametrize("bits", ["7fffffffffffffff", "7ff0000000000000",
                                  "fff0000000000000"])
def test_nan_and_infinity_are_rejected(bits):
    with pytest.raises(ValueError):
        canonicalize(_f(bits))


def test_rfc_8785_section_3_2_2_example():
    """§3.2.2: numbers, escapes, literals, whitespace and member order at once."""
    src = ('{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, '
           '0.000000000000000000000000001], '
           '"string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/", '
           '"literals": [null, true, false]}')
    want = ('{"literals":[null,true,false],'
            '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
            '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}')
    assert canonicalize(json.loads(src)) == want.encode("utf-8")


def test_rfc_8785_section_3_2_3_sorting_is_by_utf16_code_units():
    """§3.2.3: U+1F600 sorts BEFORE U+FB33, because its high surrogate is 0xD83D.

    A code-point sort puts it last, and that is the one place a naive
    `sorted(dict)` disagrees with the RFC.
    """
    src = ('{"\\u20ac": "Euro Sign", "\\r": "Carriage Return", '
           '"\\ufb33": "Hebrew Letter Dalet With Dagesh", "1": "One", '
           '"\\ud83d\\ude00": "Emoji: Grinning Face", "\\u0080": "Control", '
           '"\\u00f6": "Latin Small Letter O With Diaeresis"}')
    got = canonicalize(json.loads(src)).decode("utf-8")
    order = [k for k in json.loads(got)]
    assert order == ["\r", "1", "\u0080", "ö", "€", "\U0001F600", "דּ"]
    assert got.startswith('{"\\r":"Carriage Return","1":"One","\u0080":"Control"')


def test_integers_are_exact_inside_the_safe_range_and_refused_outside():
    assert canonicalize([0, -1, 2 ** 53, -(2 ** 53)]) == b"[0,-1,9007199254740992,-9007199254740992]"
    with pytest.raises(ValueError):
        canonicalize(2 ** 53 + 1)


def test_nested_structures_and_no_whitespace():
    assert canonicalize({"b": [1, {"d": None, "c": True}], "a": "x"}) == \
        b'{"a":"x","b":[1,{"c":true,"d":null}]}'


def test_lone_surrogate_and_non_json_types_are_refused():
    with pytest.raises(ValueError):
        canonicalize("\ud800")
    with pytest.raises(TypeError):
        canonicalize({1: "x"})
    with pytest.raises(TypeError):
        canonicalize(object())
