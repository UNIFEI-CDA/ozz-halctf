"""
Tests for agent action prioritization — context provides correct signals for LLM decisions.
Updated for Competition-Grade core.py (LLM-only decisions, no hardcoded routing).
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.core import OzzAgent, Observation, Plan, AgentState
from agent.memory import Memory
from agent.tools import ToolRegistry


class TestActionPrioritization(unittest.TestCase):
    """Tests that the agent's context provides correct signals for LLM decisions."""

    def _make_agent(self):
        agent = object.__new__(OzzAgent)
        agent.memory = Memory(db_path=os.path.join(tempfile.gettempdir(), "ozz-test-priority.db"))
        agent.plan = Plan(objective="test", findings={"services": ["80/tcp open http"], "vulnerabilities": ["sql_injection"]}, credentials=[{"username": "admin", "password": "s3cr3t"}], flags_found=[])
        agent.run_metrics = {"new_info_actions": 0, "llm_fallbacks": 0}
        agent.targets = ["10.0.0.1"]
        agent.current_target_idx = 0
        agent.history = []
        agent._actions_without_new_info = 0
        agent._last_phase = None
        agent.tools = ToolRegistry()
        return agent

    def test_context_includes_vulnerabilities(self):
        """When vulnerabilities are found, context should include them for LLM exploitation."""
        agent = self._make_agent()
        agent.plan.state = AgentState.EXPLOITATION
        context = agent._build_context()
        self.assertIn("sql_injection", context)

    def test_context_includes_credentials(self):
        """When credentials are found, context should include them."""
        agent = self._make_agent()
        context = agent._build_context()
        self.assertIn("admin", context)
        self.assertIn("s3cr3t", context)

    def test_context_includes_services(self):
        """When services are found, context should include them."""
        agent = self._make_agent()
        context = agent._build_context()
        self.assertIn("80/tcp open http", context)

    def test_context_includes_tools(self):
        """Context should list available tools for the LLM."""
        agent = self._make_agent()
        context = agent._build_context()
        self.assertIn("nmap:", context)
        self.assertIn("curl:", context)

    def test_context_includes_phase(self):
        """Context should indicate the current phase."""
        agent = self._make_agent()
        agent.plan.state = AgentState.EXPLOITATION
        context = agent._build_context()
        self.assertIn("EXPLOITATION", context)


if __name__ == "__main__":
    unittest.main()
