#!/usr/bin/env python3
"""
Mock Runner — Simulates the Ozz agent with a MockLLM for local testing
and synthetic CTF universe validation.

Runs the agent against the 4 synthetic targets in docker-compose.full.yml
without requiring a real LLM or GPU.

Usage:
    python scripts/mock_runner.py [--targets target-01,target-02,...]
"""

import os
import sys
import json
import random
import argparse
import logging
from typing import Optional, List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.core import OzzAgent, AgentState, Observation, Plan
from agent.memory import Memory
from agent.tools import ToolRegistry, ToolResult

logger = logging.getLogger("ozz.mock_runner")


class MockLLM:
    """Mock LLM that simulates agent behavior for synthetic CTF targets.

    Follows the same decision-making pattern as the real agent but uses
    predefined strategies for known synthetic challenge types.
    """

    def __init__(self, targets: List[str]):
        self.targets = targets
        self.current_step = 0
        self.flag_patterns = {
            "target-01": "flag{web_master_2026}",
            "target-02": "flag{crypto_breaker_2026}",
            "target-03": "flag{forensic_hunter_2026}",
            "target-04": "flag{pwn_overlord_2026}",
        }

    def generate_json(self, context: str) -> Optional[dict]:
        """Generate a mock decision based on the current context and step."""
        self.current_step += 1

        # Phase 1: Recon
        if self.current_step <= 2:
            target = self.targets[0] if self.targets else "10.0.0.1"
            return {
                "thought": f"Starting recon on {target}",
                "action": "nmap",
                "action_input": f"-sV -sC {target}",
                "plan_update": "Beginning reconnaissance phase",
            }

        # Phase 2: Web enumeration
        if self.current_step <= 4:
            return {
                "thought": "Found HTTP service, enumerating web application",
                "action": "curl",
                "action_input": "http://target-01/",
            }

        # Phase 3: Exploitation
        if self.current_step <= 6:
            return {
                "thought": "Found potential vulnerability, attempting exploitation",
                "action": "shell",
                "action_input": "echo 'username=admin\npassword=secret123'",
            }

        # Phase 4: Flag capture
        target_idx = min(self.current_step - 7, len(self.targets) - 1)
        target_name = self.targets[target_idx] if target_idx < len(self.targets) else "target-01"
        flag = self.flag_patterns.get(target_name, f"flag{{captured_{target_name}}}")

        return {
            "thought": f"Found flag on {target_name}!",
            "action": "submit_flag",
            "action_input": flag,
        }


class MockOzzAgent:
    """Mock agent that uses MockLLM instead of a real LLM server."""

    def __init__(self, targets: List[str], db_path: Optional[str] = None):
        self.targets = targets
        self.memory = Memory(db_path=db_path or "/tmp/ozz_mock_runner.db")
        self.tools = ToolRegistry()
        self.plan = Plan(objective="Find and capture all flags")
        self.history: List[Observation] = []
        self.mock_llm = MockLLM(targets)
        self.run_metrics = {
            "run_id": f"mock-run-{int(__import__('time').time() * 1000)}",
            "targets": list(targets),
            "iterations": 0,
            "flags_found": 0,
            "loop_detected": 0,
            "phase_transitions": 0,
            "tool_failures": 0,
        }

    def run(self, max_iterations: int = 10):
        """Run the mock agent loop."""
        logger.info(f"🏴 Mock Ozz starting. Targets: {self.targets}")
        self.plan.state = AgentState.RECON
        self.plan.target = self.targets[0] if self.targets else ""

        for i in range(max_iterations):
            self.run_metrics["iterations"] = i + 1

            # Get mock decision
            decision = self.mock_llm.generate_json("")
            if not decision:
                continue

            action = decision.get("action", "")
            action_input = decision.get("action_input", "")

            # Execute
            if action == "submit_flag":
                obs = Observation(
                    tool="submit_flag",
                    command=f"submit_flag({action_input})",
                    output=f"Flag captured: {action_input}",
                    success=True,
                )
                if action_input not in self.plan.flags_found:
                    self.plan.flags_found.append(action_input)
                    self.memory.store_flag(action_input, source="mock_runner", target=self.plan.target)
            else:
                result = self.tools.execute(action, action_input)
                obs = Observation(
                    tool=action,
                    command=f"{action} {action_input}",
                    output=result.output,
                    success=result.success,
                )
                if not result.success:
                    self.run_metrics["tool_failures"] += 1

            self.history.append(obs)
            self.memory.store(obs)

            logger.info(f"Step {i+1}: {action} -> {'OK' if obs.success else 'FAIL'}")

        self.run_metrics["flags_found"] = len(self.plan.flags_found)
        self.memory.store_run_metrics(self.run_metrics, run_id=self.run_metrics["run_id"])
        return self.run_metrics


def main():
    parser = argparse.ArgumentParser(description="Mock Ozz CTF Runner")
    parser.add_argument(
        "--targets",
        default="target-01,target-02,target-03,target-04",
        help="Comma-separated target names",
    )
    parser.add_argument("--iterations", type=int, default=10, help="Max iterations per target")
    parser.add_argument("--db-path", default=None, help="SQLite DB path for memory")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    targets = [t.strip() for t in args.targets.split(",")]
    agent = MockOzzAgent(targets, db_path=args.db_path)
    metrics = agent.run(max_iterations=args.iterations)

    print("\n" + "=" * 60)
    print("🏴 MOCK RUNNER RESULTS")
    print("=" * 60)
    print(f"Targets: {metrics['targets']}")
    print(f"Iterations: {metrics['iterations']}")
    print(f"Flags found: {metrics['flags_found']}")
    print(f"Tool failures: {metrics['tool_failures']}")
    print(f"Flags: {agent.plan.flags_found}")
    print("=" * 60)

    return metrics


if __name__ == "__main__":
    main()
