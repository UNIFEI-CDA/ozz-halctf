"""
Tests for OzzAgent core behaviors: flag extraction, state transitions, act, etc.
Updated for Competition-Grade core.py.
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.core import OzzAgent, Observation, Plan, AgentState, ScoreboardClient
from agent.memory import Memory
from agent.tools import ToolRegistry


class TestFlagDetection(unittest.TestCase):
    """Tests for _extract_flags() regex-based flag extraction."""

    def _make_agent(self):
        agent = object.__new__(OzzAgent)
        agent.plan = Plan(objective="test", findings={}, credentials=[], flags_found=[])
        agent.run_metrics = {"flags_found": 0}
        return agent

    def test_detects_flag_braces_format(self):
        agent = self._make_agent()
        flags = agent._extract_flags("The secret is flag{abc123_xyz}")
        self.assertIn("flag{abc123_xyz}", flags)

    def test_detects_ctf_braces_format(self):
        agent = self._make_agent()
        flags = agent._extract_flags("CTF{found_it}")
        self.assertIn("CTF{found_it}", flags)

    def test_detects_halctf_format(self):
        agent = self._make_agent()
        flags = agent._extract_flags("HALCTF{super_secret}")
        self.assertIn("HALCTF{super_secret}", flags)

    def test_detects_defcon_format(self):
        agent = self._make_agent()
        flags = agent._extract_flags("DEFCON{pwn3d}")
        self.assertIn("DEFCON{pwn3d}", flags)

    def test_detects_case_insensitive(self):
        agent = self._make_agent()
        flags = agent._extract_flags("found: FLAG{case_test}")
        self.assertTrue(any("case_test" in f for f in flags))

    def test_no_duplicate_flags(self):
        agent = self._make_agent()
        agent.plan.flags_found = ["flag{dup_test}"]
        flags = agent._extract_flags("flag{dup_test}")
        count = sum(1 for f in flags if "dup_test" in f)
        self.assertEqual(count, 0)

    def test_multiple_flags_in_output(self):
        agent = self._make_agent()
        flags = agent._extract_flags("First: flag{one} and second: flag{two}")
        self.assertEqual(len(flags), 2)

    def test_no_flags_in_normal_output(self):
        agent = self._make_agent()
        flags = agent._extract_flags("80/tcp open http\n22/tcp open ssh")
        self.assertEqual(len(flags), 0)

    def test_empty_output(self):
        agent = self._make_agent()
        flags = agent._extract_flags("")
        self.assertEqual(flags, [])


class TestAgentAct(unittest.TestCase):
    """Tests for _act() method."""

    def _make_agent(self):
        agent = object.__new__(OzzAgent)
        agent.memory = Memory(db_path=os.path.join(tempfile.gettempdir(), f"ozz-test-act-{time.time()}.db"))
        agent.plan = Plan(objective="test", findings={}, credentials=[], flags_found=[])
        agent.run_metrics = {"tool_failures": 0, "flags_submitted": 0}
        agent.tools = ToolRegistry()
        agent.scoreboard = ScoreboardClient(url="")
        agent._consecutive_failures = 0
        return agent

    def test_act_submit_flag_returns_observation(self):
        agent = self._make_agent()
        decision = {"action": "submit_flag", "action_input": "flag{test}"}
        obs = agent._act(decision)
        self.assertEqual(obs.tool, "submit_flag")
        self.assertTrue(obs.success)
        self.assertIn("flag{test}", obs.output)

    def test_act_executes_tool(self):
        agent = self._make_agent()
        decision = {"action": "grep", "action_input": "root /etc/passwd"}
        obs = agent._act(decision)
        self.assertEqual(obs.tool, "grep")
        self.assertIsInstance(obs.success, bool)

    def test_act_unknown_tool_records_failure(self):
        agent = self._make_agent()
        decision = {"action": "nonexistent", "action_input": "args"}
        obs = agent._act(decision)
        self.assertFalse(obs.success)
        self.assertEqual(agent.run_metrics["tool_failures"], 1)


class TestStateTransitions(unittest.TestCase):
    """Tests for _update_state() automatic phase transitions."""

    def _make_agent(self):
        agent = object.__new__(OzzAgent)
        agent.plan = Plan(objective="test", findings={}, credentials=[], flags_found=[])
        agent.run_metrics = {"phase_transitions": 0}
        agent.targets = ["10.0.0.1"]
        agent.current_target_idx = 0
        agent._last_phase = None
        agent._actions_without_new_info = 0
        return agent

    def test_enumeration_to_exploitation_with_vulns(self):
        agent = self._make_agent()
        agent.plan.state = AgentState.ENUMERATION
        agent.plan.findings["vulnerabilities"] = ["sql_injection"]

        agent._update_state({}, Observation(tool="nikto", command="nikto", output="", success=True))
        self.assertEqual(agent.plan.state, AgentState.EXPLOITATION)

    def test_enumeration_to_exploitation_with_creds(self):
        agent = self._make_agent()
        agent.plan.state = AgentState.ENUMERATION
        agent.plan.credentials = [{"username": "admin", "password": "pass"}]

        agent._update_state({}, Observation(tool="nikto", command="nikto", output="", success=True))
        self.assertEqual(agent.plan.state, AgentState.EXPLOITATION)

    def test_exploitation_to_pivot_with_compromised(self):
        agent = self._make_agent()
        agent.plan.state = AgentState.EXPLOITATION
        agent.plan.findings["compromised"] = ["10.0.0.1"]

        agent._update_state({}, Observation(tool="shell", command="shell", output="", success=True))
        self.assertEqual(agent.plan.state, AgentState.PIVOT)

    def test_phase_transition_increments_metric(self):
        agent = self._make_agent()
        agent.plan.state = AgentState.RECON
        agent.plan.findings["services"] = ["80/tcp open http", "22/tcp open ssh"]

        agent._update_state({}, Observation(tool="nmap", command="nmap", output="", success=True))
        self.assertEqual(agent.run_metrics["phase_transitions"], 1)

    def test_plan_update_logged(self):
        agent = self._make_agent()
        # Should not raise
        agent._update_state({"plan_update": "Moving to next phase"}, Observation(tool="nmap", command="nmap", output="", success=True))

    def test_recon_to_enumeration_with_services(self):
        agent = self._make_agent()
        agent.plan.state = AgentState.RECON
        agent.plan.findings["services"] = ["80/tcp open http", "22/tcp open ssh"]

        agent._update_state({}, Observation(tool="nmap", command="nmap", output="", success=True))
        self.assertEqual(agent.plan.state, AgentState.ENUMERATION)


class TestTrackEffectiveness(unittest.TestCase):
    """Tests for _track_effectiveness() action outcome tracking."""

    def _make_agent(self):
        agent = object.__new__(OzzAgent)
        agent.memory = Memory(db_path=os.path.join(tempfile.gettempdir(), f"ozz-test-track-{time.time()}.db"))
        agent.plan = Plan(objective="test", findings={}, credentials=[], flags_found=[])
        agent.plan.target = "target-01"
        agent.run_metrics = {}
        agent.targets = ["target-01"]
        agent.current_target_idx = 0
        return agent

    def test_tracks_success(self):
        agent = self._make_agent()
        agent.plan.target = "target-01"
        decision = {"action": "nmap"}
        obs = Observation(tool="nmap", command="nmap", output="80/tcp open", success=True)
        agent._track_effectiveness(decision, obs)
        evidence = agent.memory.get_strategy_evidence(target="target-01")
        self.assertEqual(evidence[0]["outcome"], "success")
        self.assertAlmostEqual(evidence[0]["confidence"], 0.8)

    def test_tracks_failure(self):
        agent = self._make_agent()
        agent.plan.target = "target-01"
        decision = {"action": "shell"}
        obs = Observation(tool="shell", command="shell", output="error", success=False)
        agent._track_effectiveness(decision, obs)
        evidence = agent.memory.get_strategy_evidence(target="target-01")
        self.assertEqual(evidence[0]["outcome"], "failure")
        self.assertAlmostEqual(evidence[0]["confidence"], 0.2)


class TestInterpretObservation(unittest.TestCase):
    """Tests for _interpret_observation() finding extraction."""

    def _make_agent(self):
        agent = object.__new__(OzzAgent)
        agent.memory = Memory(db_path=os.path.join(tempfile.gettempdir(), f"ozz-test-interpret-{time.time()}.db"))
        agent.plan = Plan(objective="test", findings={}, credentials=[], flags_found=[])
        agent.run_metrics = {"new_info_actions": 0}
        agent._actions_without_new_info = 0
        return agent

    def test_extracts_services_from_nmap(self):
        agent = self._make_agent()
        obs = Observation(tool="nmap", command="nmap", output="80/tcp open http\n22/tcp open ssh", success=True)
        agent._interpret_observation(obs)
        self.assertIn("80/tcp open http", agent.plan.findings["services"])
        self.assertIn("22/tcp open ssh", agent.plan.findings["services"])

    def test_extracts_credentials(self):
        agent = self._make_agent()
        obs = Observation(tool="curl", command="curl", output="username=admin\npassword=secret", success=True)
        agent._interpret_observation(obs)
        self.assertEqual(agent.plan.credentials[0]["username"], "admin")
        self.assertEqual(agent.plan.credentials[0]["password"], "secret")

    def test_extracts_vulnerabilities(self):
        agent = self._make_agent()
        obs = Observation(tool="nikto", command="nikto", output="Found SQL injection vulnerability", success=True)
        agent._interpret_observation(obs)
        self.assertIn("sql_injection", agent.plan.findings["vulnerabilities"])

    def test_no_duplicate_services(self):
        agent = self._make_agent()
        obs = Observation(tool="nmap", command="nmap", output="80/tcp open http\n80/tcp open http", success=True)
        agent._interpret_observation(obs)
        self.assertEqual(agent.plan.findings["services"].count("80/tcp open http"), 1)

    def test_handles_empty_output(self):
        agent = self._make_agent()
        obs = Observation(tool="nmap", command="nmap", output="", success=True)
        agent._interpret_observation(obs)

    def test_handles_none_output(self):
        agent = self._make_agent()
        obs = Observation(tool="nmap", command="nmap", output=None, success=True)
        agent._interpret_observation(obs)


class TestLoopDetection(unittest.TestCase):
    """Tests for _detect_loop() and _break_loop()."""

    def _make_agent(self):
        agent = object.__new__(OzzAgent)
        agent.plan = Plan(objective="test", findings={}, credentials=[], flags_found=[])
        agent.run_metrics = {"loop_detected": 0}
        agent.history = []
        agent._consecutive_same_action = 0
        agent._actions_without_new_info = 0
        agent._last_phase = None
        return agent

    def test_detects_repeated_actions(self):
        agent = self._make_agent()
        for _ in range(5):
            agent.history.append(Observation(tool="nmap", command="nmap 10.0.0.1", output="", success=True))
        # _detect_loop needs to be called LOOP_DETECTION_THRESHOLD times (3)
        # with the same signatures to trigger detection
        for _ in range(2):
            agent._detect_loop()  # Increments _consecutive_same_action to 1, then 2
        self.assertTrue(agent._detect_loop())  # Now at 3, should detect

    def test_no_false_positive_with_varied_actions(self):
        agent = self._make_agent()
        agent.history.append(Observation(tool="nmap", command="nmap 10.0.0.1", output="", success=True))
        agent.history.append(Observation(tool="curl", command="curl http://target", output="", success=True))
        agent.history.append(Observation(tool="gobuster", command="gobuster dir", output="", success=True))
        self.assertFalse(agent._detect_loop())

    def test_break_loop_forces_state_change(self):
        agent = self._make_agent()
        agent.plan.state = AgentState.RECON
        agent._break_loop()
        self.assertNotEqual(agent.plan.state, AgentState.RECON)
        self.assertEqual(agent.run_metrics["loop_detected"], 1)


if __name__ == "__main__":
    unittest.main()
