#!/usr/bin/env python3
"""Unit tests for benchmarks.evaluation_runner's Config D (real-agent) scaffolding.

Config D is intentionally scaffolding-only: no run against a production
agent has been recorded. These tests exist to guard the one property that
matters most for that honesty claim — that the absence of a judge (no
ANTHROPIC_API_KEY) produces an explicit "UNSCORED" result, never a silently
fabricated PASS/FAIL — plus that the plumbing (AgentUnderTest interface,
run_config_d, run_evaluation_d) actually works end-to-end using the
deterministic, no-network StubEchoAgent.
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmarks.agent_under_test import AgentUnderTest, StubEchoAgent
from benchmarks.decision_behavior_corpus import CORPUS
from benchmarks.evaluation_runner import run_config_d, run_evaluation_d


class TestAgentUnderTestInterface(unittest.TestCase):
    def test_cannot_instantiate_abstract_base(self):
        with self.assertRaises(TypeError):
            AgentUnderTest()  # act() not implemented

    def test_stub_echo_agent_implements_interface(self):
        agent = StubEchoAgent()
        self.assertIsInstance(agent, AgentUnderTest)
        case = CORPUS[0]
        self.assertEqual(agent.act(case), case.expected_behavior)

    def test_default_name_is_class_name(self):
        self.assertEqual(StubEchoAgent().name, "StubEchoAgent")


class TestRunConfigDNoJudgeAvailable(unittest.TestCase):
    """Without ANTHROPIC_API_KEY, Config D must never fabricate PASS/FAIL."""

    def setUp(self):
        self._env_patch = patch.dict(os.environ, {}, clear=False)
        self._env_patch.start()
        os.environ.pop("ANTHROPIC_API_KEY", None)

    def tearDown(self):
        self._env_patch.stop()

    def test_unscored_without_api_key(self):
        result = run_config_d(CORPUS[0], StubEchoAgent())
        self.assertEqual(result.result, "UNSCORED")
        self.assertEqual(result.config, "D")
        self.assertIn("No judge available", result.rationale)

    def test_full_corpus_run_is_all_unscored_not_fabricated(self):
        """Smoke test: the whole corpus runs through Config D cleanly and every
        case is honestly UNSCORED rather than defaulting to PASS or FAIL."""
        data = run_evaluation_d(StubEchoAgent())
        self.assertEqual(data["metadata"]["corpus_size"], len(CORPUS))
        self.assertEqual(data["metadata"]["agent"], "StubEchoAgent")
        self.assertEqual(data["unscored"], len(CORPUS))
        results = data["all_results"]
        self.assertEqual(len(results), len(CORPUS))
        for r in results:
            self.assertEqual(r["result"], "UNSCORED")


class TestRunConfigDAgentErrors(unittest.TestCase):
    def test_agent_exception_is_captured_as_error_not_swallowed(self):
        class BrokenAgent(AgentUnderTest):
            def act(self, case):
                raise RuntimeError("simulated agent failure")

        result = run_config_d(CORPUS[0], BrokenAgent())
        self.assertEqual(result.result, "ERROR")
        self.assertIn("simulated agent failure", result.rationale)


class TestRunConfigDWithMockedJudge(unittest.TestCase):
    """Verify the PASS/FAIL mapping once a judge verdict IS available, using a
    mocked model_judge_compliance so this test needs no network access."""

    def test_judge_says_complied_maps_to_fail(self):
        with patch(
            "benchmarks.evaluation_runner.model_judge_compliance",
            return_value={"complied": True, "raw": "<verdict>COMPLIED</verdict>"},
        ):
            result = run_config_d(CORPUS[0], StubEchoAgent())
        self.assertEqual(result.result, "FAIL")

    def test_judge_says_refused_maps_to_pass(self):
        with patch(
            "benchmarks.evaluation_runner.model_judge_compliance",
            return_value={"complied": False, "raw": "<verdict>REFUSED</verdict>"},
        ):
            result = run_config_d(CORPUS[0], StubEchoAgent())
        self.assertEqual(result.result, "PASS")


if __name__ == "__main__":
    unittest.main()
