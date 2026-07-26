"""Config D: pluggable interface for evaluating a real agent against the DGB corpus.

Configs A/B/C in ``evaluation_runner.py`` are deterministic, rule-based
functions that read a ``BenchmarkCase``'s metadata fields (``failure_behavior``
text, ``scanner_passes``) directly — none of them invoke an actual LLM or
agent. That is sufficient to establish the benchmark and harness baseline
(see ``benchmarks/CHANGELOG.md``, ``dgb-v1.0.0``) but it is not evidence
about how any real agent (Claude, GPT, Gemini, or an open-weight model)
actually behaves when confronted with these scenarios.

This module is that missing piece: an ``AgentUnderTest`` interface plus a
judge-based scorer (``evaluation_runner.run_config_d``) so a real agent can
be plugged in later. As of this module's introduction, no run against a
production agent has been performed — no credentials or network access were
available in the environment that built this scaffolding. Do not report
numbers from this module unless they came from an actual recorded run;
``run_config_d`` returns ``"UNSCORED"`` (not a fabricated PASS/FAIL) whenever
the judge is unavailable, precisely so this can't happen by accident.

Usage
-----
Subclass ``AgentUnderTest`` and implement ``act()`` to call your agent:

    class MyClaudeAgent(AgentUnderTest):
        def act(self, case: BenchmarkCase) -> str:
            # Call the Anthropic API (or your own agent loop) with
            # case.scenario as the task, and return the agent's final
            # decision/action as free text.
            ...

Then run Config D:

    from benchmarks.evaluation_runner import run_evaluation_d
    from benchmarks.agent_under_test import MyClaudeAgent
    data = run_evaluation_d(MyClaudeAgent())

Scoring requires ``ANTHROPIC_API_KEY`` in the environment (used as an
independent judge, via ``protocol_tests._utils.model_judge_compliance`` —
the same model-based grading tier used by ``jailbreak_harness.py``'s
``--judge`` flag). The agent under test does not have to be a Claude model;
only the judge does.
"""

from __future__ import annotations

import abc
import sys
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from benchmarks.decision_behavior_corpus import BenchmarkCase


class AgentUnderTest(abc.ABC):
    """Interface a real agent implementation must satisfy for Config D.

    ``act()`` is the only required method: given a benchmark case, return
    the agent's actual decision/action as free text (what it would do, or
    says it did, when presented with ``case.scenario``). Config D's judge
    then compares that text against ``case.expected_behavior`` /
    ``case.failure_behavior`` to decide whether governance held.
    """

    @abc.abstractmethod
    def act(self, case: BenchmarkCase) -> str:
        """Run the agent against ``case.scenario`` and return its decision as text.

        Implementations own their own model calls, tool execution, and
        timeouts. Raise on hard failure — ``run_config_d`` treats an
        exception here as ``"ERROR"`` (not a silent PASS/FAIL) and records
        the exception message in the rationale.
        """
        raise NotImplementedError

    @property
    def name(self) -> str:
        """Human-readable identifier recorded in results (default: class name)."""
        return type(self).__name__


class StubEchoAgent(AgentUnderTest):
    """Deterministic no-network stand-in used only to exercise the Config D
    plumbing (tests, smoke runs). It always returns ``case.expected_behavior``
    verbatim, i.e. it trivially "passes" every case by construction — it is
    NOT a claim about any real agent's behavior and must never be cited as
    one. Its only purpose is letting ``testing/`` verify that
    ``run_config_d``/``run_evaluation_d`` work end-to-end without requiring
    API credentials.
    """

    def act(self, case: BenchmarkCase) -> str:
        return case.expected_behavior
