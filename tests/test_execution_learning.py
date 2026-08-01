"""
Tests for execution learning and effectiveness tracking.
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


class TestExecutionLearning(unittest.TestCase):
    def _make_agent(self):
        agent = object.__new__(OzzAgent)
        agent.memory = Memory(db_path=os.path.join(tempfile.gettempdir(), "ozz-test-learning.db"))
        agent.plan = Plan(objective="test", findings={}, credentials=[], flags_found=[])
        agent.run_metrics = {"new_info_actions": 0, "llm_fallbacks": 0}
        agent.targets = ["target-01"]
        agent.current_target_idx = 0
        agent.history = []
        agent._actions_without_new_info = 0
        agent._last_phase = None
        agent.tools = ToolRegistry()
        return agent

    def test_track_effectiveness_records_success(self):
        """_track_effectiveness should record successful actions to strategy evidence."""
        agent = self._make_agent()
        agent.plan.target = "target-01"
        decision = {"action": "nmap", "action_input": "-sV 10.0.0.1"}
        obs = Observation(tool="nmap", command="nmap -sV 10.0.0.1", output="80/tcp open http", success=True)

        agent._track_effectiveness(decision, obs)

        evidence = agent.memory.get_strategy_evidence(target="target-01")
        self.assertGreaterEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["outcome"], "success")
        self.assertAlmostEqual(evidence[0]["confidence"], 0.8)

    def test_track_effectiveness_records_failure(self):
        """_track_effectiveness should record failed actions with low confidence."""
        agent = self._make_agent()
        agent.plan.target = "target-01"
        decision = {"action": "shell", "action_input": "bad_command"}
        obs = Observation(tool="shell", command="shell bad_command", output="error", success=False)

        agent._track_effectiveness(decision, obs)

        evidence = agent.memory.get_strategy_evidence(target="target-01")
        self.assertGreaterEqual(len(evidence), 1)
        last = evidence[-1]  # Get the most recent entry
        self.assertEqual(last["outcome"], "failure")
        self.assertAlmostEqual(last["confidence"], 0.2)

    def test_effectiveness_appears_in_context(self):
        """Strategy evidence should appear in the LLM context."""
        agent = self._make_agent()
        agent.plan.target = "target-01"
        agent.memory.store_strategy_evidence(
            target="target-01", service="http", vulnerability="sql_injection",
            action="sqlmap", confidence=0.8, outcome="success"
        )

        context = agent._build_context()
        self.assertIn("sqlmap", context.lower())
        self.assertIn("success", context.lower())

    def test_circuit_breaker_recovery_with_next_target(self):
        """Circuit breaker should try switching to next target."""
        agent = self._make_agent()
        agent.targets = ["t1", "t2", "t3"]
        agent.current_target_idx = 0
        agent._consecutive_failures = 15
        agent.plan.state = AgentState.RECON

        recovered = agent._try_circuit_breaker_recovery()
        self.assertTrue(recovered)
        self.assertEqual(agent.current_target_idx, 1)
        self.assertEqual(agent.plan.target, "t2")

    def test_circuit_breaker_no_recovery_on_last_target_exploitation(self):
        """Circuit breaker should fail when on last target in exploitation."""
        agent = self._make_agent()
        agent.targets = ["t1"]
        agent.current_target_idx = 0
        agent._consecutive_failures = 15
        agent.plan.state = AgentState.EXPLOITATION

        recovered = agent._try_circuit_breaker_recovery()
        self.assertFalse(recovered)


if __name__ == "__main__":
    unittest.main()
