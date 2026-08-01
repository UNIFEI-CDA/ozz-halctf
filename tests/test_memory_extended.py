"""
Tests for Memory extended operations: credentials, observations, strategy evidence, run history.
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.memory import Memory
from agent.core import Observation


class TestMemoryCredentials(unittest.TestCase):
    """Tests for credential storage and retrieval."""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.memory = Memory(db_path=self.db_path)

    def tearDown(self):
        os.close(self.db_fd)
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_store_and_retrieve_credential(self):
        self.memory.store_credential(username="admin", password="secret", target="10.0.0.1", source="nikto")
        creds = self.memory.get_credentials(target="10.0.0.1")
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["username"], "admin")
        self.assertEqual(creds[0]["password"], "secret")

    def test_get_credentials_all(self):
        self.memory.store_credential(username="a", password="b", target="t1")
        self.memory.store_credential(username="c", password="d", target="t2")
        creds = self.memory.get_credentials()
        self.assertEqual(len(creds), 2)

    def test_get_credentials_filtered(self):
        self.memory.store_credential(username="a", password="b", target="t1")
        self.memory.store_credential(username="c", password="d", target="t2")
        creds = self.memory.get_credentials(target="t1")
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0]["username"], "a")

    def test_credential_with_hash(self):
        self.memory.store_credential(username="user", hash_value="abc123hash", target="t1")
        creds = self.memory.get_credentials(target="t1")
        self.assertEqual(creds[0]["hash"], "abc123hash")


class TestMemoryObservations(unittest.TestCase):
    """Tests for observation storage and retrieval."""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.memory = Memory(db_path=self.db_path)

    def tearDown(self):
        os.close(self.db_fd)
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_store_and_retrieve_observation(self):
        obs = Observation(tool="nmap", command="nmap -sV 10.0.0.1", output="80/tcp open http", success=True)
        self.memory.store(obs)
        recent = self.memory.get_recent_observations(limit=1)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["tool"], "nmap")
        self.assertEqual(recent[0]["command"], "nmap -sV 10.0.0.1")

    def test_recent_observations_ordered_desc(self):
        for i in range(5):
            obs = Observation(tool=f"tool_{i}", command=f"cmd_{i}", output=f"out_{i}", success=True)
            self.memory.store(obs)
            time.sleep(0.01)
        recent = self.memory.get_recent_observations(limit=3)
        self.assertEqual(len(recent), 3)
        # Most recent first
        self.assertEqual(recent[0]["tool"], "tool_4")

    def test_recent_observations_limit(self):
        for i in range(10):
            obs = Observation(tool=f"tool_{i}", command=f"cmd_{i}", output="", success=True)
            self.memory.store(obs)
        recent = self.memory.get_recent_observations(limit=5)
        self.assertEqual(len(recent), 5)


class TestMemoryStrategyEvidence(unittest.TestCase):
    """Tests for strategy evidence storage and retrieval."""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.memory = Memory(db_path=self.db_path)

    def tearDown(self):
        os.close(self.db_fd)
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_store_and_retrieve_strategy_evidence(self):
        self.memory.store_strategy_evidence(
            target="10.0.0.1", service="http", vulnerability="sql injection",
            action="sqlmap", reference="https://exploit-db.com/12345",
            confidence=0.85, outcome="success"
        )
        evidence = self.memory.get_strategy_evidence(target="10.0.0.1")
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["service"], "http")
        self.assertEqual(evidence[0]["vulnerability"], "sql injection")
        self.assertAlmostEqual(evidence[0]["confidence"], 0.85)

    def test_strategy_evidence_no_filter(self):
        self.memory.store_strategy_evidence(target="t1", service="http", vulnerability="sqli", action="sqlmap")
        self.memory.store_strategy_evidence(target="t2", service="ssh", vulnerability="creds", action="hydra")
        evidence = self.memory.get_strategy_evidence()
        self.assertEqual(len(evidence), 2)

    def test_strategy_evidence_filtered(self):
        self.memory.store_strategy_evidence(target="t1", service="http", vulnerability="sqli", action="sqlmap")
        self.memory.store_strategy_evidence(target="t2", service="ssh", vulnerability="creds", action="hydra")
        evidence = self.memory.get_strategy_evidence(target="t1")
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["service"], "http")


class TestMemoryRunMetricsHistory(unittest.TestCase):
    """Tests for run metrics history retrieval."""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.memory = Memory(db_path=self.db_path)

    def tearDown(self):
        os.close(self.db_fd)
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_empty_history(self):
        history = self.memory.get_run_metrics_history()
        self.assertEqual(len(history), 0)

    def test_multiple_runs_in_history(self):
        self.memory.store_run_metrics({"run_id": "r1", "flags_found": 1}, run_id="r1")
        self.memory.store_run_metrics({"run_id": "r2", "flags_found": 2}, run_id="r2")
        self.memory.store_run_metrics({"run_id": "r3", "flags_found": 0}, run_id="r3")

        history = self.memory.get_run_metrics_history()
        self.assertEqual(len(history), 3)
        # Chronological order
        self.assertEqual(history[0]["run_id"], "r1")
        self.assertEqual(history[2]["run_id"], "r3")

    def test_history_contains_metrics(self):
        self.memory.store_run_metrics({"run_id": "r1", "iterations": 42, "flags_found": 3}, run_id="r1")
        history = self.memory.get_run_metrics_history()
        self.assertEqual(history[0]["iterations"], 42)
        self.assertEqual(history[0]["flags_found"], 3)


class TestMemoryFlagIdempotency(unittest.TestCase):
    """Additional tests for flag idempotency."""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.memory = Memory(db_path=self.db_path)

    def tearDown(self):
        os.close(self.db_fd)
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_same_flag_same_target_stored_once(self):
        self.memory.store_flag("flag{test}", source="src", target="t1")
        self.memory.store_flag("flag{test}", source="src", target="t1")
        flags = self.memory.get_flags()
        self.assertEqual(len(flags), 1)

    def test_same_flag_different_target_stored_separately(self):
        self.memory.store_flag("flag{test}", source="src", target="t1")
        self.memory.store_flag("flag{test}", source="src", target="t2")
        flags = self.memory.get_flags()
        self.assertEqual(len(flags), 2)

    def test_different_flags_stored_separately(self):
        self.memory.store_flag("flag{one}", source="src", target="t1")
        self.memory.store_flag("flag{two}", source="src", target="t1")
        flags = self.memory.get_flags()
        self.assertEqual(len(flags), 2)


if __name__ == "__main__":
    unittest.main()
