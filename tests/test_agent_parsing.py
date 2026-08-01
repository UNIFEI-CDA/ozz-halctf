"""
Tests for agent parsing — service, credential, and vulnerability extraction.
Updated for Competition-Grade core.py.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.core import OzzAgent, Observation, Plan
from agent.memory import Memory


class TestAgentParsing(unittest.TestCase):
    def _make_agent(self):
        agent = object.__new__(OzzAgent)
        agent.memory = Memory(db_path=os.path.join(tempfile.gettempdir(), "ozz-test-parsing.db"))
        agent.plan = Plan(objective="test", findings={}, credentials=[], flags_found=[])
        agent.run_metrics = {"new_info_actions": 0}
        agent._actions_without_new_info = 0
        return agent

    def test_extract_services_from_nmap_output(self):
        agent = self._make_agent()
        obs = Observation(tool="nmap", command="nmap -sV", output="80/tcp open http\n22/tcp open ssh", success=True)

        agent._interpret_observation(obs)

        self.assertIn("80/tcp open http", agent.plan.findings["services"])
        self.assertIn("22/tcp open ssh", agent.plan.findings["services"])

    def test_extract_credentials_from_output(self):
        agent = self._make_agent()
        obs = Observation(tool="curl", command="curl", output="username=admin\npassword=s3cr3t", success=True)

        agent._interpret_observation(obs)

        self.assertEqual(agent.plan.credentials[0]["username"], "admin")
        self.assertEqual(agent.plan.credentials[0]["password"], "s3cr3t")

    def test_extract_vulnerabilities_from_output(self):
        agent = self._make_agent()
        obs = Observation(tool="nikto", command="nikto", output="Possible SQL injection detected via parameter id", success=True)

        agent._interpret_observation(obs)

        self.assertIn("sql_injection", agent.plan.findings["vulnerabilities"])

    def test_tracks_new_info_action(self):
        agent = self._make_agent()
        obs = Observation(tool="nmap", command="nmap -sV", output="80/tcp open http", success=True)
        agent._interpret_observation(obs)
        self.assertEqual(agent.run_metrics["new_info_actions"], 1)
        self.assertEqual(agent._actions_without_new_info, 0)

    def test_tracks_no_new_info(self):
        agent = self._make_agent()
        obs = Observation(tool="nmap", command="nmap", output="Host is up", success=True)
        agent._interpret_observation(obs)
        self.assertEqual(agent.run_metrics["new_info_actions"], 0)
        self.assertEqual(agent._actions_without_new_info, 1)


if __name__ == "__main__":
    unittest.main()
