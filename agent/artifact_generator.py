"""
Artifact Generator — Produces test artifacts from scenarios.

Generates:
  - Policy YAML templates
  - Test data for scenario evaluation
  - Regression test baselines
  - Reporting artifacts
"""

import json
import logging
import time
from typing import Any, Optional

logger = logging.getLogger("ozz.artifact_generator")


class ArtifactGenerator:
    """Generates test artifacts from scenario generator output."""

    def generate_policy_yaml(self, policy_output: dict) -> str:
        """Generate a YAML policy document from mapper output."""
        risks = policy_output.get("risks", [])
        actors = policy_output.get("actors", [])
        scenarios = policy_output.get("gherkin_scenarios", [])

        lines = [
            "# Auto-generated Security Policy Document",
            f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "metadata:",
            "  version: '1.0'",
            "  generator: ozz-policy-mapper",
            "",
            "risks:",
        ]

        for risk in risks:
            lines.append(f"  - id: {risk.get('id', 'unknown')}")
            lines.append(f"    title: \"{risk.get('title', '')[:80]}\"")
            lines.append(f"    severity: {risk.get('severity', 'medium')}")
            lines.append(f"    category: {risk.get('category', 'general')}")
            if risk.get("cwe_id"):
                lines.append(f"    cwe: {risk.get('cwe_id')}")
            lines.append("")

        lines.append("actors:")
        for actor in actors:
            lines.append(f"  - id: {actor.get('id', 'unknown')}")
            lines.append(f"    name: \"{actor.get('name', 'Unknown')}\"")
            lines.append(f"    skill_level: {actor.get('skill_level', 'intermediate')}")
            lines.append(f"    access_level: {actor.get('access_level', 'external')}")
            lines.append("")

        lines.append("test_scenarios:")
        for i, scenario in enumerate(scenarios[:10]):  # Limit to first 10
            lines.append(f"  - # Scenario {i+1}")
            for line in scenario.split("\n"):
                lines.append(f"    # {line}")
            lines.append("")

        return "\n".join(lines)

    def generate_test_data(self, scenarios: list[dict]) -> list[dict]:
        """Generate test data for scenario evaluation."""
        test_cases = []
        for scenario in scenarios:
            for step in scenario.get("steps", []):
                test_case = {
                    "scenario_id": scenario.get("scenario_id", ""),
                    "step_id": step.get("step_id", ""),
                    "tool": step.get("tool", ""),
                    "command": step.get("command", ""),
                    "context": {
                        "tool": step.get("tool", ""),
                        "command": step.get("command", ""),
                        "output": "",  # To be filled during execution
                        "allowed_tools": set(),
                        "prompt_sanitized": True,
                        "prompt_risk": "safe",
                        "audit_chain_valid": True,
                    },
                    "expected_predicate": step.get("evaluation_predicate", ""),
                    "expected_outcome": step.get("expected_outcome", ""),
                }
                test_cases.append(test_case)
        return test_cases

    def generate_baseline_report(self, evaluation_results: list[dict]) -> dict:
        """Generate a baseline report for regression testing."""
        total = len(evaluation_results)
        passed = sum(1 for r in evaluation_results if r.get("all_passed", False))

        predicate_stats = {}
        for result in evaluation_results:
            for pred_result in result.get("results", []):
                name = pred_result.get("name", "unknown")
                if name not in predicate_stats:
                    predicate_stats[name] = {"pass": 0, "fail": 0, "total": 0}
                predicate_stats[name]["total"] += 1
                if pred_result.get("passed", False):
                    predicate_stats[name]["pass"] += 1
                else:
                    predicate_stats[name]["fail"] += 1

        return {
            "baseline_timestamp": time.time(),
            "total_scenarios": total,
            "passed_scenarios": passed,
            "pass_rate": passed / total if total > 0 else 0.0,
            "predicate_statistics": predicate_stats,
            "regression_threshold": 0.85,  # Minimum acceptable pass rate
        }
