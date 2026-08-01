"""
Tests for LLM context building — structured findings, phase, tools.
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


class TestLLMContext(unittest.TestCase):
    def _make_agent(self):
        agent = object.__new__(OzzAgent)
        agent.memory = Memory(db_path=os.path.join(tempfile.gettempdir(), "ozz-test-llm-context.db"))
        agent.plan = Plan(objective="test", findings={"services": ["80/tcp open http"], "vulnerabilities": ["sql_injection"]}, credentials=[{"username": "admin", "password": "s3cr3t"}], flags_found=[])
        agent.run_metrics = {"new_info_actions": 0, "llm_fallbacks": 0}
        agent.targets = ["target-01"]
        agent.current_target_idx = 0
        agent.history = []
        agent._actions_without_new_info = 0
        agent._last_phase = None
        agent.tools = ToolRegistry()
        return agent

    def test_context_includes_structured_findings(self):
        agent = self._make_agent()
        context = agent._build_context()
        self.assertIn("sql_injection", context)
        self.assertIn("80/tcp open http", context)
        self.assertIn("admin", context)

    def test_context_mentions_current_phase(self):
        agent = self._make_agent()
        agent.plan.state = AgentState.RECON
        context = agent._build_context()
        self.assertIn("RECON", context)

    def test_context_includes_tools(self):
        agent = self._make_agent()
        context = agent._build_context()
        self.assertIn("nmap:", context)
        self.assertIn("curl:", context)
        self.assertIn("submit_flag:", context)

    def test_context_includes_targets(self):
        agent = self._make_agent()
        context = agent._build_context()
        self.assertIn("target-01", context)

    def test_context_includes_recent_history(self):
        agent = self._make_agent()
        agent.history.append(Observation(tool="nmap", command="nmap -sV", output="80/tcp open http", success=True))
        context = agent._build_context()
        self.assertIn("nmap", context)
        self.assertIn("SUCCESS", context)

    def test_context_includes_flags_found(self):
        agent = self._make_agent()
        agent.plan.flags_found = ["flag{test}"]
        context = agent._build_context()
        self.assertIn("flag{test}", context)


if __name__ == "__main__":
    unittest.main()
