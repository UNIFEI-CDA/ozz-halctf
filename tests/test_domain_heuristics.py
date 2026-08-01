"""
Tests for domain heuristics — context provides correct signals for LLM decisions.
Updated for Competition-Grade core.py (LLM-only, no hardcoded routing).
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.core import OzzAgent, Observation, Plan, AgentState
from agent.memory import Memory
from agent.tools import ToolRegistry


class TestDomainHeuristics(unittest.TestCase):
    def _make_agent(self):
        agent = object.__new__(OzzAgent)
        agent.memory = Memory(db_path=os.path.join(tempfile.gettempdir(), "ozz-test-domain.db"))
        agent.plan = Plan(objective="test", findings={}, credentials=[], flags_found=[])
        agent.run_metrics = {"new_info_actions": 0, "llm_fallbacks": 0, "phase_transitions": 0}
        agent.targets = ["10.0.0.1"]
        agent.current_target_idx = 0
        agent.history = []
        agent._actions_without_new_info = 0
        agent._last_phase = None
        agent.tools = ToolRegistry()
        return agent

    def test_http_service_appears_in_context(self):
        """When HTTP service is found, it should appear in the LLM context."""
        agent = self._make_agent()
        obs = Observation(tool="nmap", command="nmap", output="80/tcp open http", success=True)
        agent._interpret_observation(obs)

        context = agent._build_context()
        self.assertIn("80/tcp open http", context)

    def test_ssh_service_appears_in_context(self):
        """When SSH service is found, it should appear in the LLM context."""
        agent = self._make_agent()
        obs = Observation(tool="nmap", command="nmap", output="22/tcp open ssh", success=True)
        agent._interpret_observation(obs)

        context = agent._build_context()
        self.assertIn("22/tcp open ssh", context)

    def test_services_trigger_enumeration_phase(self):
        """When enough services are found, agent should transition to ENUMERATION."""
        agent = self._make_agent()
        agent.plan.state = AgentState.RECON
        agent.plan.findings = {"services": ["80/tcp open http", "22/tcp open ssh"]}

        agent._update_state({}, Observation(tool="nmap", command="nmap", output="", success=True))
        self.assertEqual(agent.plan.state, AgentState.ENUMERATION)


if __name__ == "__main__":
    unittest.main()
