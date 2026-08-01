import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.memory import Memory


class TestAgentRobustness(unittest.TestCase):
    def test_memory_can_store_and_retrieve_run_metrics(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "metrics.db")
            memory = Memory(db_path=db_path)

            memory.store_run_metrics({
                "run_id": "run-001",
                "targets": ["target-01"],
                "iterations": 3,
                "flags_found": 1,
                "loop_detected": 2,
                "phase_transitions": 2,
                "tool_failures": 1,
            })

            metrics = memory.get_run_metrics()
            self.assertEqual(metrics["run_id"], "run-001")
            self.assertEqual(metrics["iterations"], 3)
            self.assertEqual(metrics["flags_found"], 1)
            self.assertEqual(metrics["loop_detected"], 2)


if __name__ == "__main__":
    unittest.main()
