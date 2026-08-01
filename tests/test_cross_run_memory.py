"""
Tests for cross-run memory — prior run insights and strategy evidence.
Updated for Competition-Grade core.py.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.core import OzzAgent, Observation, Plan, AgentState
from agent.memory import Memory
from agent.tools import ToolRegistry


class TestCrossRunMemory(unittest.TestCase):
    def _make_agent(self):
        agent = object.__new__(OzzAgent)
        agent.memory = Memory(db_path=os.path.join(tempfile.gettempdir(), f"ozz-test-cross-run-{os.getpid()}.db"))
        agent.plan = Plan(objective="test", findings={}, credentials=[], flags_found=[])
        agent.run_metrics = {"new_info_actions": 0, "llm_fallbacks": 0}
        agent.targets = ["target-01"]
        agent.current_target_idx = 0
        agent.history = []
        agent._actions_without_new_info = 0
        agent._last_phase = None
        agent.tools = ToolRegistry()
        return agent

    def test_format_prior_context_with_history(self):
        agent = self._make_agent()
        agent.memory.store_run_metrics({"run_id": "run-1", "flags_found": 1, "iterations": 10, "tool_failures": 2}, run_id="run-1")
        agent.memory.store_run_metrics({"run_id": "run-2", "flags_found": 0, "iterations": 5, "tool_failures": 3}, run_id="run-2")

        context = agent._format_prior_context()
        self.assertIn("run-1", context)
        self.assertIn("flags=1", context)

    def test_format_prior_context_empty(self):
        agent = self._make_agent()
        context = agent._format_prior_context()
        self.assertIn("No prior", context)

    def test_format_effectiveness_context_with_evidence(self):
        agent = self._make_agent()
        agent.memory.store_strategy_evidence(
            target="target-01", service="http", vulnerability="sql_injection",
            action="sqlmap", reference="https://www.exploit-db.com",
            confidence=0.91, outcome="success"
        )

        context = agent._format_effectiveness_context()
        self.assertIn("sqlmap", context.lower())
        self.assertIn("success", context)

    def test_build_context_includes_exploitdb_references(self):
        agent = self._make_agent()
        agent.plan.findings["services"] = ["80/tcp open http"]
        agent.plan.findings["vulnerabilities"] = ["sql_injection"]
        agent.plan.state = AgentState.EXPLOITATION

        context = agent._build_context()
        self.assertIn("sql_injection", context.lower())

    def test_build_context_includes_service_specific_strategy(self):
        agent = self._make_agent()
        agent.plan.findings["services"] = ["80/tcp open http"]
        agent.plan.findings["vulnerabilities"] = ["sql_injection"]
        agent.memory.store_strategy_evidence(
            target="target-01", service="http", vulnerability="sql_injection",
            action="sqlmap", reference="https://www.exploit-db.com",
            confidence=0.91, outcome="success",
        )

        context = agent._build_context()
        self.assertIn("sqlmap", context.lower())
        # The new core.py doesn't include exploit-db URLs in context,
        # but it does include strategy evidence with action names
        self.assertIn("success", context.lower())


if __name__ == "__main__":
    unittest.main()
