"""Independent byte-match verification for CTEF v0.3.1 + APS fixtures.

Runs RFC 8785 (JSON Canonicalization Scheme) over published fixture inputs
using a clean-room canonicalizer (`trailofbits/rfc8785.py`), then compares the
resulting canonical bytes and SHA-256 to the values the fixture authors
publish. A match means an independent verifier confirms the canonicalizer
substrate. A divergence is a finding the working group needs to know about.

Tracks A2A WG discussion: a2aproject/A2A#1672, a2aproject/A2A#1786.
Originally posted as a2aproject/A2A#1786#issuecomment-4354353212.

Usage:
    pip install -r tests/jcs/requirements.txt
    python tests/jcs/run_bytematch.py

Exit codes:
    0 — all vectors match
    1 — one or more vectors diverged
"""

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

import rfc8785

CACHE = Path(__file__).parent / ".fixtures"

SOURCES = {
    "AgentGraph CTEF v0.3.1": {
        "url": "https://agentgraph.co/.well-known/cte-test-vectors.json",
        "kind": "agentgraph",
    },
    "APS bilateral-delegation": {
        "url": (
            "https://raw.githubusercontent.com/aeoess/agent-passport-system/"
            "main/fixtures/bilateral-delegation/canonicalize-fixture-v1.json"
        ),
        "kind": "aps_bilateral",
    },
    "APS rotation-attestation": {
        "url": "https://aeoess.com/fixtures/rotation-attestation/test-vectors.json",
        "kind": "aps_rotation",
    },
}

USER_AGENT = "rfc8785-bytematch-verifier/0.1 (+https://github.com/msaleme/red-team-blue-team-agent-fabric)"


def fetch(url: str, dest: Path) -> bytes:
    """Fetch a URL with a User-Agent header and cache the body to `dest`."""
    if dest.exists():
        return dest.read_bytes()
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(body)
    return body


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def jcs(obj) -> bytes:
    return rfc8785.dumps(obj)


def check_agentgraph(body: bytes) -> list[tuple[str, bool, str, str]]:
    """4 inline vectors, each with input_object + canonical_bytes_utf8 + canonical_sha256."""
    data = json.loads(body)
    results = []
    for vname in (
        "envelope_vector",
        "verdict_vector",
        "scope_violation_vector",
        "composition_failure_vector",
    ):
        v = data[vname]
        canon = jcs(v["input_object"])
        actual_sha = sha256_hex(canon)
        expected_bytes = v["canonical_bytes_utf8"].encode("utf-8")
        bytes_ok = canon == expected_bytes
        sha_ok = actual_sha == v["canonical_sha256"]
        results.append((vname, bytes_ok and sha_ok, v["canonical_sha256"], actual_sha))
    return results


def check_aps_bilateral(body: bytes) -> list[tuple[str, bool, str, str]]:
    """10 vectors, each with input + canonical_bytes_hex + canonical_sha256."""
    data = json.loads(body)
    results = []
    for v in data["vectors"]:
        canon = jcs(v["input"])
        actual_sha = sha256_hex(canon)
        expected_bytes = bytes.fromhex(v["canonical_bytes_hex"])
        bytes_ok = canon == expected_bytes
        sha_ok = actual_sha == v["canonical_sha256"]
        results.append((v["name"], bytes_ok and sha_ok, v["canonical_sha256"], actual_sha))
    return results


def check_aps_rotation(body: bytes) -> list[tuple[str, bool, str, str]]:
    """5 fixtures, each at a separate URL with only canonicalSha256 published in the index."""
    index = json.loads(body)
    results = []
    for name, meta in index["fixtures"].items():
        fixture_path = CACHE / f"aps-rotation-{name}.json"
        fixture_body = fetch(meta["url"], fixture_path)
        canon = jcs(json.loads(fixture_body))
        actual_sha = "sha256:" + sha256_hex(canon)
        expected_sha = meta["canonicalSha256"]
        sha_ok = actual_sha == expected_sha
        results.append((name, sha_ok, expected_sha, actual_sha))
    return results


CHECKERS = {
    "agentgraph": check_agentgraph,
    "aps_bilateral": check_aps_bilateral,
    "aps_rotation": check_aps_rotation,
}


def main() -> int:
    print(f"Canonicalizer: rfc8785 {rfc8785.__version__ if hasattr(rfc8785, '__version__') else '(unknown version)'}")
    print(f"Fixture cache: {CACHE}")
    print()

    all_results: list[tuple[str, str, bool, str, str]] = []
    for source_name, meta in SOURCES.items():
        cache_path = CACHE / (source_name.replace(" ", "_").replace("/", "_") + ".json")
        body = fetch(meta["url"], cache_path)
        results = CHECKERS[meta["kind"]](body)
        for name, ok, expected_sha, actual_sha in results:
            all_results.append((source_name, name, ok, expected_sha, actual_sha))

    width_source = max(len(s) for s, _, _, _, _ in all_results)
    width_name = max(len(n) for _, n, _, _, _ in all_results)
    print(f"{'Source':<{width_source}}  {'Vector':<{width_name}}  Result")
    print(f"{'-' * width_source}  {'-' * width_name}  {'-' * 6}")
    for source_name, name, ok, expected_sha, actual_sha in all_results:
        status = "PASS" if ok else "FAIL"
        print(f"{source_name:<{width_source}}  {name:<{width_name}}  {status}")
        if not ok:
            print(f"  expected: {expected_sha}")
            print(f"  got     : {actual_sha}")

    total = len(all_results)
    passed = sum(1 for *_, ok, _, _ in all_results if ok)
    print()
    print(f"Total: {total}    Pass: {passed}    Fail: {total - passed}")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
