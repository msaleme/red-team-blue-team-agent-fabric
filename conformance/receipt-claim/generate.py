#!/usr/bin/env python3
"""Generate the RCL receipt-claim conformance vectors from the harness verifier.

Each vector is a receipt whose envelope signature verifies but whose claims are
(in)valid on semantic grounds. Values are produced by the working ClaimLevelVerifier
in protocol_tests/receipt_claim_harness.py, not hand-authored, so `expected_result`
and `harness_reason` are ground truth. Run from the repo root:

    python conformance/receipt-claim/generate.py
"""
import json, os, sys
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)
from protocol_tests import receipt_claim_harness as R

OUT = os.path.join(REPO, "conformance", "receipt-claim", "fixtures")
os.makedirs(OUT, exist_ok=True)
now = R.ReceiptClaimTests().now
V = R.ClaimLevelVerifier(now)


def who_signed(block):
    if not isinstance(block, dict):
        return None
    for auth in ("checker", "authz", "exec", "emitter"):
        if R._attest_ok(auth, block):
            return auth
    return None


# Per case: receipt-lifecycle phase, the binding a verifier must fail, and a
# harness-native reason code (maps 1:1 to the verifier's reason string).
META = {
 "RCL-001": ("post-execution", "occurrence evidence omitted",                       "OCCURRENCE_EVIDENCE_MISSING"),
 "RCL-002": ("admission",      "check evidence tampered after attestation",          "CHECK_EVIDENCE_TAMPERED"),
 "RCL-003": ("admission",      "check transcript outside the freshness window",       "CHECK_TRANSCRIPT_STALE"),
 "RCL-004": ("admission",      "check bound to a different tool-set digest",           "CHECK_TOOLSET_DIGEST_MISMATCH"),
 "RCL-005": ("admission",      "authorization bound to different params than requested","AUTHORIZATION_PARAMS_MISMATCH"),
 "RCL-006": ("post-execution", "occurrence ack bound to another action",              "OCCURRENCE_ACTION_LINKAGE_MISMATCH"),
 "RCL-007": ("admission",      "check attested by emitter, not an independent authority","CHECK_ATTESTOR_NOT_INDEPENDENT"),
 "RCL-008": ("admission+post-execution", "control: all four properties supported",     "ACCEPT_ALL_PROPERTIES_SUPPORTED"),
 "RCL-009": ("admission",      "control: clean wired check accepted",                  "ACCEPT_ALL_PROPERTIES_SUPPORTED"),
 "RCL-010": ("admission",      "wired MCP-019 verdict is fail",                        "CHECK_OUTPUT_FAIL"),
 "RCL-011": ("admission",      "wired check bound to the wrong tool set",              "CHECK_TOOLSET_DIGEST_MISMATCH"),
}


def build(tid):
    if tid == "RCL-008":
        return R.build_valid_receipt(now)
    if tid == "RCL-009":
        return R.build_tool_context_receipt(now, R._CLEAN_TOOLS)
    if tid == "RCL-010":
        return R.build_tool_context_receipt(now, R._SHARELOCK_TOOLS)
    if tid == "RCL-011":
        return R.build_tool_context_receipt(now, R._CLEAN_TOOLS, action_tools=R._SHARELOCK_TOOLS)
    return dict((t[0], t[2]) for t in R.NEGATIVES)[tid](now)


NAMES = dict((t[0], t[1]) for t in R.NEGATIVES)
NAMES.update({"RCL-008": "Fully-supported receipt accepted (control)",
              "RCL-009": "Wired MCP-019 check (clean) accepted",
              "RCL-010": "Wired MCP-019 check (composite found) rejected",
              "RCL-011": "Wired MCP-019 check bound to wrong tool set rejected"})

index = []
for tid in [f"RCL-{i:03d}" for i in range(1, 12)]:
    rcpt = build(tid)
    out = V.verify(rcpt)
    env = V.verify_envelope(rcpt)
    phase, binding, code = META[tid]
    claims = rcpt.get("claims", {})
    ev = {}
    for prop in ("authorization", "occurrence", "check"):
        b = claims.get(prop)
        if b is None:
            ev[prop] = {"present": False}
            continue
        rec = {"present": True, "attestor": who_signed(b),
               "independent_of_emitter": who_signed(b) not in (None, "emitter")}
        for f in ("action_digest", "params_digest", "outcome_digest",
                  "input_digest", "policy_digest", "output", "issued_at",
                  "checker_id", "version"):
            if f in b:
                rec[f] = b[f]
        ev[prop] = rec
    fixture = {
        "test_id": tid,
        "name": NAMES[tid],
        "expected_result": out.verdict,          # accept | reject  (ground truth)
        "expected_phase": phase,                 # admission | post-execution | both
        "violated_binding": binding,
        "reason_code": code,
        "harness_reason": out.reason,            # verbatim verifier output
        # Evidence-binding descriptor: exactly what a verifier must recompute
        # from referenced evidence, so the vector is not satisfiable at the
        # string level.
        "evidence_binding": {
            "admitted_action_digest": rcpt.get("action_digest"),
            "action_tool_set_digest": rcpt.get("tool_set_digest"),
            "referenced_evidence": ev,
            "attestor_independence_ok": all(
                v.get("independent_of_emitter", True) for v in ev.values() if v.get("present")),
            "policy_digest": (claims.get("check") or {}).get("policy_digest"),
            "freshness_window_seconds": R.FRESHNESS_WINDOW,
        },
        "recomputation_boundary": binding,
        "envelope_signature_valid": env,         # always True: envelope-valid, claim-(in)valid
        "receipt": rcpt,
    }
    with open(os.path.join(OUT, f"{tid}.json"), "w") as f:
        json.dump(fixture, f, indent=2)
    index.append({"test_id": tid, "name": NAMES[tid], "expected_result": out.verdict,
                  "phase": phase, "reason_code": code, "harness_reason": out.reason})

with open(os.path.join(OUT, "index.json"), "w") as f:
    json.dump({"suite": "RCL receipt-claim conformance vectors",
               "source": "protocol_tests/receipt_claim_harness.py",
               "reject_vectors": sum(1 for x in index if x["expected_result"] == "reject"),
               "acceptance_controls": sum(1 for x in index if x["expected_result"] == "accept"),
               "freshness_window_seconds": R.FRESHNESS_WINDOW,
               "cases": index}, f, indent=2)

print(f"wrote {len(index)} fixtures to {OUT}")
for x in index:
    print(f"  {x['test_id']} {x['expected_result']:6} [{x['phase']}] {x['reason_code']}")
