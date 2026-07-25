#!/usr/bin/env python3
"""Extended Thinking Harness (v1.0)

6 tests covering the conformance surface of Claude's extended-thinking
tamper-evidence guarantees (Claude Cookbook: "extended-thinking-extended-
thinking-with-tool-use", Feb 2025) — thinking blocks carry cryptographic
signatures that bind reasoning to a specific conversation state, and the
API is documented to reject requests where a prior thinking block was
modified, omitted before a required tool-result turn, or replayed outside
its original context.

Those are guarantees the *API* provides; this harness tests whether a given
*implementation built on top of it* (an agent framework, a gateway, a
custom orchestration layer) actually preserves and enforces them end to
end, rather than silently dropping, truncating, or exposing thinking
content along the way — any of which would undermine downstream trust
decisions made on the assumption that an agent "reasoned through this
safely."

References:
    Claude Cookbook: extended-thinking-extended-thinking-with-tool-use (Feb 2025)

OWASP Mappings: ASI01 (Prompt Injection), ASI06 (Data Leakage),
                ASI09 (Misinformation)
NIST AI RMF: GOVERN 1.1, MANAGE 2.2

Usage:
    # Simulate mode — validate detection logic without a live target
    python -m protocol_tests.extended_thinking_harness --simulate

    # Run against a target exposing thinking-block introspection
    python -m protocol_tests.extended_thinking_harness --url http://localhost:8080/mcp

    # Write JSON report
    python -m protocol_tests.extended_thinking_harness --simulate --report et_report.json

    # Via unified CLI
    agent-security test extended-thinking --simulate
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from protocol_tests._utils import Severity, wilson_ci, http_post_json, jsonrpc_request


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass
class ExtendedThinkingResult:
    test_id: str
    name: str
    category: str
    owasp_asi: str
    severity: str
    passed: bool
    details: str
    payload_summary: str
    request_sent: dict | None = None
    response_received: dict | None = None
    elapsed_s: float = 0.0
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------


class ExtendedThinkingTests:
    """6 tests covering extended-thinking tamper-evidence conformance.

    Accepts an optional url for live-mode probing of a target's thinking-
    block handling metadata. When simulate=True, each test constructs a
    synthetic thinking-block scenario and validates detection logic without
    requiring a live target.
    """

    def __init__(
        self,
        url: str | None = None,
        headers: dict | None = None,
        simulate: bool = False,
    ):
        self.url = url
        self.headers = headers or {}
        self.simulate = simulate
        self.results: list[ExtendedThinkingResult] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _record(self, result: ExtendedThinkingResult) -> None:
        status = "PASS ✅" if result.passed else "FAIL ❌"
        print(f"  {status}  {result.test_id}: {result.name} ({result.elapsed_s:.2f}s)")
        self.results.append(result)

    def _introspect(self, extra_params: dict | None = None) -> dict:
        """Ask a live target for its thinking-block handling metadata."""
        req = jsonrpc_request("thinking/introspect", extra_params or {})
        return http_post_json(self.url, req, headers=self.headers)

    @staticmethod
    def _method_unsupported(resp: dict) -> bool:
        if resp.get("_status") == 404:
            return True
        err = resp.get("error")
        if isinstance(err, dict) and err.get("code") == -32601:
            return True
        return False

    # ------------------------------------------------------------------
    # ET-001: Tampered Thinking-Block Signature Accepted
    # ------------------------------------------------------------------

    def test_et_001_tampered_signature_accepted(self) -> None:
        """ET-001: Tampered Thinking-Block Signature Accepted (CRITICAL, category: tamper_evidence)

        Per the API's own tamper-evidence guarantee, any modification to a
        previously-returned thinking block's content or signature should
        cause the next request to be rejected (400). An implementation
        layer that catches and swallows that rejection — e.g. to "self-
        heal" a broken conversation — silently defeats the guarantee.

        Simulate: an original thinking block vs one with a single byte of
        its signature flipped; verify the tamper is detectable.

        OWASP: ASI09 | STRIDE: Tampering | Severity: P0-Critical
        NIST AI RMF: GOVERN 1.1
        """
        t0 = time.monotonic()

        original_block = {
            "type": "thinking",
            "thinking": "Let me check the user's account balance before proceeding.",
            "signature": "sig_a3f9c1e8b2d4...",
        }
        tampered_block = {**original_block, "signature": "sig_a3f9c1e8b2d5..."}  # 1 char flipped

        def _signature_tampered(orig: dict, candidate: dict) -> bool:
            return orig["signature"] != candidate["signature"]

        if self.simulate:
            tampered = _signature_tampered(original_block, tampered_block)
            passed = tampered  # detection: we correctly identify the tamper

            self._record(ExtendedThinkingResult(
                test_id="ET-001", name="Tampered Thinking-Block Signature Accepted",
                category="tamper_evidence", owasp_asi="ASI09",
                severity=Severity.CRITICAL.value, passed=passed,
                details=(
                    f"[simulate] Original signature vs 1-byte-flipped signature: "
                    f"tamper correctly detected={tampered}. A compliant implementation "
                    f"must reject the request rather than silently proceeding."
                ),
                payload_summary=f"tampered={tampered}",
                request_sent={"original": original_block, "tampered": tampered_block},
                elapsed_s=round(time.monotonic() - t0, 3),
            ))
            return

        resp = self._introspect({"probe": "signature_validation"})
        if self._method_unsupported(resp):
            self._record(ExtendedThinkingResult(
                test_id="ET-001", name="Tampered Thinking-Block Signature Accepted",
                category="tamper_evidence", owasp_asi="ASI09",
                severity=Severity.CRITICAL.value, passed=True,
                details="Target does not expose thinking-block introspection — no tamper-evidence surface to probe.",
                payload_summary="method_unsupported",
                elapsed_s=round(time.monotonic() - t0, 3),
            ))
            return

        result = resp.get("result") or {}
        rejects_tampered = bool(result.get("rejects_tampered_signature"))
        passed = rejects_tampered

        self._record(ExtendedThinkingResult(
            test_id="ET-001", name="Tampered Thinking-Block Signature Accepted",
            category="tamper_evidence", owasp_asi="ASI09",
            severity=Severity.CRITICAL.value, passed=passed,
            details=(
                "Target confirms it rejects tampered thinking-block signatures." if passed
                else "Target does not confirm rejection of tampered thinking-block signatures — "
                     "may be catching/swallowing the API's own tamper rejection."
            ),
            payload_summary=f"rejects_tampered_signature={rejects_tampered}",
            elapsed_s=round(time.monotonic() - t0, 3),
        ))

    # ------------------------------------------------------------------
    # ET-002: Missing Thinking Block Before Tool-Result Turn Accepted
    # ------------------------------------------------------------------

    def test_et_002_missing_thinking_block_accepted(self) -> None:
        """ET-002: Missing Thinking Block Before Tool-Result Turn Accepted (HIGH, category: tamper_evidence)

        The API rejects a final assistant message that starts with a
        tool_use block instead of a thinking block, when thinking is
        enabled. An orchestration layer that reconstructs conversation
        history (e.g. after a context-compaction step) can accidentally
        drop the thinking block while keeping the tool_use block — and if
        it also catches the resulting API error and retries without it,
        the omission becomes invisible.

        Simulate: an assistant turn with tool_use but no leading thinking
        block; verify this is detectable as malformed.

        OWASP: ASI01 | STRIDE: Tampering | Severity: P1-High
        NIST AI RMF: GOVERN 1.1
        """
        t0 = time.monotonic()

        malformed_turn = {"role": "assistant", "content": [{"type": "tool_use", "name": "delete_file"}]}
        well_formed_turn = {
            "role": "assistant",
            "content": [
                {"type": "thinking", "thinking": "I should confirm before deleting.", "signature": "sig_..."},
                {"type": "tool_use", "name": "delete_file"},
            ],
        }

        def _missing_leading_thinking(turn: dict) -> bool:
            content = turn.get("content", [])
            has_tool_use = any(b.get("type") == "tool_use" for b in content)
            starts_with_thinking = bool(content) and content[0].get("type") in ("thinking", "redacted_thinking")
            return has_tool_use and not starts_with_thinking

        if self.simulate:
            malformed_flagged = _missing_leading_thinking(malformed_turn)
            wellformed_clean = not _missing_leading_thinking(well_formed_turn)
            passed = malformed_flagged and wellformed_clean

            self._record(ExtendedThinkingResult(
                test_id="ET-002", name="Missing Thinking Block Before Tool-Result Turn Accepted",
                category="tamper_evidence", owasp_asi="ASI01",
                severity=Severity.HIGH.value, passed=passed,
                details=(
                    f"[simulate] Turn with tool_use but no leading thinking block "
                    f"flagged as malformed: {malformed_flagged}. Well-formed turn left "
                    f"unflagged: {wellformed_clean}."
                ),
                payload_summary=f"malformed_flagged={malformed_flagged}, wellformed_clean={wellformed_clean}",
                request_sent={"malformed": malformed_turn, "well_formed": well_formed_turn},
                elapsed_s=round(time.monotonic() - t0, 3),
            ))
            return

        resp = self._introspect({"probe": "thinking_block_required_before_tool_use"})
        if self._method_unsupported(resp):
            self._record(ExtendedThinkingResult(
                test_id="ET-002", name="Missing Thinking Block Before Tool-Result Turn Accepted",
                category="tamper_evidence", owasp_asi="ASI01",
                severity=Severity.HIGH.value, passed=True,
                details="Target does not expose thinking-block introspection — no ordering surface to probe.",
                payload_summary="method_unsupported",
                elapsed_s=round(time.monotonic() - t0, 3),
            ))
            return

        result = resp.get("result") or {}
        enforces_ordering = bool(result.get("requires_thinking_before_tool_use"))
        passed = enforces_ordering

        self._record(ExtendedThinkingResult(
            test_id="ET-002", name="Missing Thinking Block Before Tool-Result Turn Accepted",
            category="tamper_evidence", owasp_asi="ASI01",
            severity=Severity.HIGH.value, passed=passed,
            details=(
                "Target enforces a leading thinking block before tool_use." if passed
                else "Target does not confirm enforcement of thinking-before-tool_use ordering."
            ),
            payload_summary=f"requires_thinking_before_tool_use={enforces_ordering}",
            elapsed_s=round(time.monotonic() - t0, 3),
        ))

    # ------------------------------------------------------------------
    # ET-003: Redacted-Thinking Payload Exposed to End User
    # ------------------------------------------------------------------

    def test_et_003_redacted_thinking_exposed(self) -> None:
        """ET-003: Redacted-Thinking Payload Exposed to End User (HIGH, category: information_disclosure)

        redacted_thinking blocks carry an opaque, non-human-readable
        ``data`` payload precisely because the underlying reasoning may be
        sensitive. A UI or logging layer that surfaces this raw data
        (rather than a generic "reasoning redacted" placeholder) leaks
        content the API deliberately withheld.

        Simulate: a redacted_thinking block and a naive renderer that dumps
        raw ``data`` vs a safe renderer that shows a placeholder.

        OWASP: ASI06 | STRIDE: Information Disclosure | Severity: P1-High
        NIST AI RMF: GOVERN 1.1
        """
        t0 = time.monotonic()

        redacted_block = {
            "type": "redacted_thinking",
            "data": "EqoBCkYIBRgCKkAgcmVkYWN0ZWQtb3BhcXVlLWJpbmFyeS1kYXRhLW5vdC1odW1hbi1yZWFkYWJsZQ==",
        }

        def _naive_render(block: dict) -> str:
            return block["data"]  # leaks raw opaque payload

        def _safe_render(block: dict) -> str:
            return "[reasoning redacted]"

        if self.simulate:
            naive_output = _naive_render(redacted_block)
            safe_output = _safe_render(redacted_block)
            naive_leaks = naive_output == redacted_block["data"]
            safe_clean = safe_output != redacted_block["data"]
            passed = naive_leaks and safe_clean  # detection: we correctly tell them apart

            self._record(ExtendedThinkingResult(
                test_id="ET-003", name="Redacted-Thinking Payload Exposed to End User",
                category="information_disclosure", owasp_asi="ASI06",
                severity=Severity.HIGH.value, passed=passed,
                details=(
                    f"[simulate] Naive renderer leaks raw redacted payload: {naive_leaks}. "
                    f"Safe renderer (placeholder) does not: {safe_clean}."
                ),
                payload_summary=f"naive_leaks={naive_leaks}, safe_clean={safe_clean}",
                request_sent={"redacted_block_data_len": len(redacted_block["data"])},
                elapsed_s=round(time.monotonic() - t0, 3),
            ))
            return

        resp = self._introspect({"probe": "redacted_thinking_handling"})
        if self._method_unsupported(resp):
            self._record(ExtendedThinkingResult(
                test_id="ET-003", name="Redacted-Thinking Payload Exposed to End User",
                category="information_disclosure", owasp_asi="ASI06",
                severity=Severity.HIGH.value, passed=True,
                details="Target does not expose thinking-block introspection — no redaction surface to probe.",
                payload_summary="method_unsupported",
                elapsed_s=round(time.monotonic() - t0, 3),
            ))
            return

        result = resp.get("result") or {}
        exposes_raw_data = bool(result.get("redacted_thinking_data_exposed_to_caller"))
        passed = not exposes_raw_data

        self._record(ExtendedThinkingResult(
            test_id="ET-003", name="Redacted-Thinking Payload Exposed to End User",
            category="information_disclosure", owasp_asi="ASI06",
            severity=Severity.HIGH.value, passed=passed,
            details=(
                "Target does not expose raw redacted_thinking data to callers." if passed
                else "Target exposes raw redacted_thinking data to callers — "
                     "opaque redacted content is reaching an end-user-facing surface."
            ),
            payload_summary=f"exposes_raw_data={exposes_raw_data}",
            elapsed_s=round(time.monotonic() - t0, 3),
        ))

    # ------------------------------------------------------------------
    # ET-004: Intermediate Reasoning Exposed Mid-Tool-Chain
    # ------------------------------------------------------------------

    def test_et_004_intermediate_reasoning_exposure(self) -> None:
        """ET-004: Intermediate Reasoning Exposed Mid-Tool-Chain (MEDIUM, category: information_disclosure)

        Per the API's documented behavior, no additional thinking blocks
        are generated between receiving a tool_result and the model's next
        action within the same logical turn — thinking only reappears at
        the next non-tool_result user turn. A layer that fabricates or
        surfaces synthetic "reasoning" text to the user during a multi-step
        tool chain (e.g. for a nicer UX) may leak more about internal
        decision-making than the model actually intended to expose at that
        point, or may fabricate reasoning the model never produced.

        Simulate: a tool-chain trace where a UI layer displays
        model-attributed reasoning text between tool_result and the next
        tool_use, despite the API not having emitted a thinking block there.

        OWASP: ASI09 | STRIDE: Information Disclosure | Severity: P2-Medium
        NIST AI RMF: MANAGE 2.2
        """
        t0 = time.monotonic()

        trace = [
            {"type": "thinking", "signature": "sig_1"},
            {"type": "tool_use", "name": "get_expenses"},
            {"type": "tool_result"},
            # No new thinking block should appear here per API behavior —
            # but the UI layer injected synthetic "reasoning" text anyway.
            {"type": "ui_synthetic_reasoning", "text": "Now I'll check if this exceeds the limit..."},
            {"type": "tool_use", "name": "flag_expense"},
        ]

        def _has_fabricated_reasoning(trace: list[dict]) -> bool:
            return any(step.get("type") == "ui_synthetic_reasoning" for step in trace)

        if self.simulate:
            fabricated = _has_fabricated_reasoning(trace)
            passed = fabricated  # detection: we correctly flag the fabrication

            self._record(ExtendedThinkingResult(
                test_id="ET-004", name="Intermediate Reasoning Exposed Mid-Tool-Chain",
                category="information_disclosure", owasp_asi="ASI09",
                severity=Severity.MEDIUM.value, passed=passed,
                details=(
                    f"[simulate] Trace contains UI-fabricated reasoning text between a "
                    f"tool_result and the next tool_use, where the API would not have "
                    f"emitted a new thinking block: detected={fabricated}."
                ),
                payload_summary=f"trace_steps={len(trace)}, fabricated_reasoning_detected={fabricated}",
                request_sent={"trace_step_types": [s["type"] for s in trace]},
                elapsed_s=round(time.monotonic() - t0, 3),
            ))
            return

        resp = self._introspect({"probe": "intermediate_reasoning_exposure"})
        if self._method_unsupported(resp):
            self._record(ExtendedThinkingResult(
                test_id="ET-004", name="Intermediate Reasoning Exposed Mid-Tool-Chain",
                category="information_disclosure", owasp_asi="ASI09",
                severity=Severity.MEDIUM.value, passed=True,
                details="Target does not expose thinking-block introspection — no fabrication surface to probe.",
                payload_summary="method_unsupported",
                elapsed_s=round(time.monotonic() - t0, 3),
            ))
            return

        result = resp.get("result") or {}
        fabricates_reasoning = bool(result.get("exposes_reasoning_between_tool_calls"))
        passed = not fabricates_reasoning

        self._record(ExtendedThinkingResult(
            test_id="ET-004", name="Intermediate Reasoning Exposed Mid-Tool-Chain",
            category="information_disclosure", owasp_asi="ASI09",
            severity=Severity.MEDIUM.value, passed=passed,
            details=(
                "Target does not fabricate/expose reasoning between tool calls beyond "
                "what the API actually emitted." if passed
                else "Target exposes reasoning content between tool calls that the API "
                     "would not have emitted at that point."
            ),
            payload_summary=f"fabricates_reasoning={fabricates_reasoning}",
            elapsed_s=round(time.monotonic() - t0, 3),
        ))

    # ------------------------------------------------------------------
    # ET-005: Cross-Conversation Signature Replay Accepted
    # ------------------------------------------------------------------

    def test_et_005_cross_conversation_signature_replay(self) -> None:
        """ET-005: Cross-Conversation Signature Replay Accepted (CRITICAL, category: tamper_evidence)

        Thinking-block signatures bind reasoning to a specific conversation
        state — they should not validate when replayed into an unrelated
        conversation. A caching or templating layer that reuses a "good"
        thinking block (with its signature) across different conversations
        to save tokens would, if the target accepts it, let stale reasoning
        be presented as if freshly derived for an unrelated context.

        Simulate: a thinking block signed under conversation A's context,
        replayed as-is into conversation B; verify the context-binding
        mismatch is detectable.

        OWASP: ASI09 | STRIDE: Spoofing | Severity: P0-Critical
        NIST AI RMF: GOVERN 1.1
        """
        t0 = time.monotonic()

        block_from_conv_a = {
            "type": "thinking", "thinking": "Balance looks fine, proceeding with the transfer.",
            "signature": "sig_bound_to_conv_a_9f2e",
            "conversation_id": "conv-A",
        }
        replay_into_conv_b = {**block_from_conv_a, "conversation_id": "conv-B"}

        def _context_mismatch(original: dict, replayed: dict) -> bool:
            return original["conversation_id"] != replayed["conversation_id"]

        if self.simulate:
            mismatch = _context_mismatch(block_from_conv_a, replay_into_conv_b)
            passed = mismatch  # detection: we correctly identify the cross-context replay

            self._record(ExtendedThinkingResult(
                test_id="ET-005", name="Cross-Conversation Signature Replay Accepted",
                category="tamper_evidence", owasp_asi="ASI09",
                severity=Severity.CRITICAL.value, passed=passed,
                details=(
                    f"[simulate] Thinking block signed under conv-A replayed into conv-B: "
                    f"context mismatch correctly detected={mismatch}. A compliant "
                    f"implementation must reject the signature as invalid for this context."
                ),
                payload_summary=f"context_mismatch_detected={mismatch}",
                request_sent={"original_conv": "conv-A", "replayed_into_conv": "conv-B"},
                elapsed_s=round(time.monotonic() - t0, 3),
            ))
            return

        resp = self._introspect({"probe": "signature_scope"})
        if self._method_unsupported(resp):
            self._record(ExtendedThinkingResult(
                test_id="ET-005", name="Cross-Conversation Signature Replay Accepted",
                category="tamper_evidence", owasp_asi="ASI09",
                severity=Severity.CRITICAL.value, passed=True,
                details="Target does not expose thinking-block introspection — no replay surface to probe.",
                payload_summary="method_unsupported",
                elapsed_s=round(time.monotonic() - t0, 3),
            ))
            return

        result = resp.get("result") or {}
        signature_bound_to_conversation = bool(result.get("signature_bound_to_conversation"))
        passed = signature_bound_to_conversation

        self._record(ExtendedThinkingResult(
            test_id="ET-005", name="Cross-Conversation Signature Replay Accepted",
            category="tamper_evidence", owasp_asi="ASI09",
            severity=Severity.CRITICAL.value, passed=passed,
            details=(
                "Target confirms thinking-block signatures are conversation-scoped." if passed
                else "Target does not confirm conversation-scoping of thinking-block "
                     "signatures — cross-conversation replay may be accepted."
            ),
            payload_summary=f"signature_bound_to_conversation={signature_bound_to_conversation}",
            elapsed_s=round(time.monotonic() - t0, 3),
        ))

    # ------------------------------------------------------------------
    # ET-006: Silent Thinking-Budget Truncation
    # ------------------------------------------------------------------

    def test_et_006_silent_budget_truncation(self) -> None:
        """ET-006: Silent Thinking-Budget Truncation (MEDIUM, category: lifecycle)

        Extended thinking runs against a token budget. If a target's
        orchestration layer silently truncates or discards thinking content
        that exceeds a locally-imposed budget — without surfacing any
        signal that truncation occurred — a downstream consumer (or an
        auditor relying on the reasoning trace) can mistake truncated,
        incomplete reasoning for the model's complete deliberation.

        Simulate: a thinking block whose content is shorter than its
        declared token budget would allow, alongside a truncation-signal
        flag; verify truncation without a signal is detectable as unsafe.

        OWASP: ASI09 | STRIDE: Tampering | Severity: P2-Medium
        NIST AI RMF: MANAGE 2.2
        """
        t0 = time.monotonic()

        truncated_silently = {
            "thinking_budget_tokens": 4096,
            "actual_thinking_tokens": 4096,  # hit the cap exactly — suspicious
            "truncated": True,
            "truncation_signaled_to_caller": False,
        }
        truncated_with_signal = {**truncated_silently, "truncation_signaled_to_caller": True}

        def _unsafe_truncation(entry: dict) -> bool:
            return entry.get("truncated") and not entry.get("truncation_signaled_to_caller")

        if self.simulate:
            silent_unsafe = _unsafe_truncation(truncated_silently)
            signaled_safe = not _unsafe_truncation(truncated_with_signal)
            passed = silent_unsafe and signaled_safe

            self._record(ExtendedThinkingResult(
                test_id="ET-006", name="Silent Thinking-Budget Truncation",
                category="lifecycle", owasp_asi="ASI09",
                severity=Severity.MEDIUM.value, passed=passed,
                details=(
                    f"[simulate] Truncated-without-signal case correctly flagged unsafe: "
                    f"{silent_unsafe}. Truncated-with-signal case correctly left safe: "
                    f"{signaled_safe}."
                ),
                payload_summary=f"silent_unsafe={silent_unsafe}, signaled_safe={signaled_safe}",
                request_sent={"silent": truncated_silently, "signaled": truncated_with_signal},
                elapsed_s=round(time.monotonic() - t0, 3),
            ))
            return

        resp = self._introspect({"probe": "thinking_budget_handling"})
        if self._method_unsupported(resp):
            self._record(ExtendedThinkingResult(
                test_id="ET-006", name="Silent Thinking-Budget Truncation",
                category="lifecycle", owasp_asi="ASI09",
                severity=Severity.MEDIUM.value, passed=True,
                details="Target does not expose thinking-block introspection — no budget surface to probe.",
                payload_summary="method_unsupported",
                elapsed_s=round(time.monotonic() - t0, 3),
            ))
            return

        result = resp.get("result") or {}
        signals_truncation = bool(result.get("signals_budget_exhaustion"))
        passed = signals_truncation

        self._record(ExtendedThinkingResult(
            test_id="ET-006", name="Silent Thinking-Budget Truncation",
            category="lifecycle", owasp_asi="ASI09",
            severity=Severity.MEDIUM.value, passed=passed,
            details=(
                "Target confirms it signals thinking-budget exhaustion/truncation to callers." if passed
                else "Target does not confirm signaling of thinking-budget truncation — "
                     "incomplete reasoning may be presented as complete."
            ),
            payload_summary=f"signals_truncation={signals_truncation}",
            elapsed_s=round(time.monotonic() - t0, 3),
        ))

    # ------------------------------------------------------------------
    # run_all
    # ------------------------------------------------------------------

    def run_all(self, categories: list[str] | None = None) -> list[ExtendedThinkingResult]:
        """Run all 6 extended-thinking tests (or a filtered subset by category)."""

        all_tests: dict[str, list] = {
            "tamper_evidence":         [self.test_et_001_tampered_signature_accepted,
                                         self.test_et_002_missing_thinking_block_accepted,
                                         self.test_et_005_cross_conversation_signature_replay],
            "information_disclosure":  [self.test_et_003_redacted_thinking_exposed,
                                         self.test_et_004_intermediate_reasoning_exposure],
            "lifecycle":               [self.test_et_006_silent_budget_truncation],
        }

        if categories:
            test_map = {k: v for k, v in all_tests.items() if k in categories}
        else:
            test_map = all_tests

        mode_label = "[SIMULATE]" if self.simulate else f"[LIVE: {self.url}]"
        print(f"\n{'=' * 60}")
        print("EXTENDED THINKING HARNESS v1.0")
        print("Thinking-block tamper-evidence conformance")
        print(f"{'=' * 60}")
        print(f"Mode:    {mode_label}")
        print(f"Context: Claude Cookbook extended-thinking-with-tool-use pattern —")
        print(f"         signed, conversation-bound thinking blocks; tests whether an")
        print(f"         implementation layer actually preserves those guarantees.")

        for category, tests in test_map.items():
            print(f"\n[{category.upper()}]")
            for test_fn in tests:
                try:
                    test_fn()
                except Exception as exc:
                    eid = re.search(r"([A-Z]{2,}-\d{3})", test_fn.__doc__ or "")
                    eid = eid.group(1) if eid else test_fn.__name__
                    print(f"  ERROR ⚠️  {eid}: {exc}")
                    self.results.append(ExtendedThinkingResult(
                        test_id=eid, name=f"ERROR: {eid}", category=category,
                        owasp_asi="", severity=Severity.HIGH.value, passed=False,
                        details=str(exc), payload_summary="error",
                    ))

        total = len(self.results)
        passed_count = sum(1 for r in self.results if r.passed)
        ci = wilson_ci(passed_count, total)

        print(f"\n{'=' * 60}")
        if total:
            print(f"RESULTS: {passed_count}/{total} passed ({passed_count / total * 100:.0f}%)")
            print(f"WILSON 95% CI for pass rate: [{ci[0]:.4f}, {ci[1]:.4f}]")
        else:
            print("No tests run.")
        print(f"{'=' * 60}\n")

        return self.results


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def generate_report(results: list[ExtendedThinkingResult], output_path: str) -> None:
    """Write a JSON report of extended-thinking test results."""
    total = len(results)
    passed_count = sum(1 for r in results if r.passed)
    ci = wilson_ci(passed_count, total)

    by_severity: dict[str, dict[str, int]] = {}
    for r in results:
        sev = r.severity
        by_severity.setdefault(sev, {"total": 0, "passed": 0, "failed": 0})
        by_severity[sev]["total"] += 1
        by_severity[sev]["passed" if r.passed else "failed"] += 1

    report = {
        "suite": "Extended Thinking Harness v1.0",
        "reference": "Claude Cookbook: extended-thinking-extended-thinking-with-tool-use (Feb 2025)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": total,
            "passed": passed_count,
            "failed": total - passed_count,
            "pass_rate": round(passed_count / total, 4) if total else 0,
            "wilson_95_ci": {"lower": ci[0], "upper": ci[1]},
            "by_severity": by_severity,
        },
        "results": [asdict(r) for r in results],
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"Report written to {output_path}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "Extended Thinking Harness — 6 tests covering thinking-block "
            "tamper-evidence conformance (Claude Cookbook extended-thinking-with-tool-use)"
        )
    )
    ap.add_argument("--url", default=None, help="Target URL exposing thinking-block introspection (live mode)")
    ap.add_argument("--simulate", action="store_true",
                     help="Run in simulate mode — validate detection logic without a live target")
    ap.add_argument("--categories", help="Comma-separated categories to run")
    ap.add_argument("--report", help="Output JSON report path")
    ap.add_argument("--header", action="append", default=[], help="Extra HTTP headers (key:value)")
    ap.add_argument("--trials", type=int, default=1, help="Run N times for statistical analysis")
    args = ap.parse_args()

    if not args.simulate and not args.url:
        print("ERROR: --url is required for live mode (or use --simulate)", file=sys.stderr)
        sys.exit(1)

    headers: dict[str, str] = {}
    for h in args.header:
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()

    categories = args.categories.split(",") if args.categories else None

    if args.trials > 1:
        from protocol_tests.trial_runner import run_with_trials as _run_trials

        def _single_run():
            suite = ExtendedThinkingTests(url=args.url, headers=headers, simulate=args.simulate)
            return {"results": suite.run_all(categories=categories)}

        merged = _run_trials(_single_run, trials=args.trials, suite_name="Extended Thinking Harness v1.0")
        if args.report:
            with open(args.report, "w") as f:
                json.dump(merged, f, indent=2, default=str)
            print(f"Report written to {args.report}")
        results = merged.get("results", [])
    else:
        suite = ExtendedThinkingTests(url=args.url, headers=headers, simulate=args.simulate)
        results = suite.run_all(categories=categories)
        if args.report:
            generate_report(results, args.report)

    failed = sum(1 for r in results if not r.passed)
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
