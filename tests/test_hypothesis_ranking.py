"""
Tests for flag extraction and hypothesis-related context building.
Updated for Competition-Grade core.py (_build_hypotheses removed, LLM-only).
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.core import OzzAgent, Observation, Plan, AgentState
from agent.memory import Memory
from agent.tools import ToolRegistry


class TestFlagExtraction(unittest.TestCase):
    """Tests for _extract_flags() comprehensive flag detection."""

    def _make_agent(self):
        agent = object.__new__(OzzAgent)
        agent.plan = Plan(objective="test", findings={}, credentials=[], flags_found=[])
        agent.run_metrics = {}
        return agent

    def test_detects_flag_braces(self):
        agent = self._make_agent()
        flags = agent._extract_flags("The secret is flag{abc123_xyz}")
        self.assertIn("flag{abc123_xyz}", flags)

    def test_detects_ctf_format(self):
        agent = self._make_agent()
        flags = agent._extract_flags("CTF{found_it}")
        self.assertIn("CTF{found_it}", flags)

    def test_detects_halctf_format(self):
        agent = self._make_agent()
        flags = agent._extract_flags("HALCTF{super_secret}")
        self.assertIn("HALCTF{super_secret}", flags)

    def test_detects_case_insensitive(self):
        agent = self._make_agent()
        flags = agent._extract_flags("found: FLAG{case_test}")
        self.assertTrue(any("case_test" in f for f in flags))

    def test_no_flags_in_normal_output(self):
        agent = self._make_agent()
        flags = agent._extract_flags("80/tcp open http\n22/tcp open ssh")
        self.assertEqual(len(flags), 0)

    def test_multiple_flags(self):
        agent = self._make_agent()
        flags = agent._extract_flags("First: flag{one} and second: CTF{two}")
        self.assertEqual(len(flags), 2)

    def test_excludes_already_found_flags(self):
        agent = self._make_agent()
        agent.plan.flags_found = ["flag{already}"]
        flags = agent._extract_flags("flag{already} and flag{new}")
        self.assertNotIn("flag{already}", flags)
        self.assertIn("flag{new}", flags)

    def test_empty_output(self):
        agent = self._make_agent()
        flags = agent._extract_flags("")
        self.assertEqual(flags, [])


class TestHypothesisContextBuilding(unittest.TestCase):
    """Tests that context building provides rich information for LLM hypothesis formation."""

    def _make_agent(self):
        agent = object.__new__(OzzAgent)
        agent.memory = Memory(db_path=os.path.join(tempfile.gettempdir(), "ozz-test-hyp.db"))
        agent.plan = Plan(objective="test", findings={"services": ["80/tcp open http"], "vulnerabilities": ["sql_injection"]}, credentials=[{"username": "admin", "password": "s3cr3t"}], flags_found=[])
        agent.run_metrics = {"new_info_actions": 0, "llm_fallbacks": 0}
        agent.targets = ["target-01"]
        agent.current_target_idx = 0
        agent.history = []
        agent._actions_without_new_info = 0
        agent._last_phase = None
        agent.tools = ToolRegistry()
        return agent

    def test_context_includes_vulnerabilities(self):
        agent = self._make_agent()
        agent.plan.state = AgentState.EXPLOITATION
        context = agent._build_context()
        self.assertIn("sql_injection", context)

    def test_context_includes_credentials(self):
        agent = self._make_agent()
        context = agent._build_context()
        self.assertIn("admin", context)

    def test_context_includes_phase(self):
        agent = self._make_agent()
        agent.plan.state = AgentState.EXPLOITATION
        context = agent._build_context()
        self.assertIn("EXPLOITATION", context)

    def test_context_includes_flags_found(self):
        agent = self._make_agent()
        agent.plan.flags_found = ["flag{test}"]
        context = agent._build_context()
        self.assertIn("flag{test}", context)


if __name__ == "__main__":
    unittest.main()
