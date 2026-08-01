"""
Scenario Generator — Generates executable attack scenarios from policy mapping.

Part of the Policy-Driven Red Teaming framework (Red Hat, DEF CON 34).
Takes policy mapper output and creates runnable attack scenarios with
deterministic evaluation criteria.
"""

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

logger = logging.getLogger("ozz.scenario_generator")


@dataclass
class AttackStep:
    """A single executable attack step."""
    step_id: str
    label: str
    tool: str
    command: str
    expected_outcome: str
    evaluation_predicate: str  # Name of predicate to check
    timeout_s: int = 60


@dataclass
class AttackScenario:
    """A complete executable attack scenario."""
    scenario_id: str
    name: str
    description: str
    risk_ref: str
    actor_ref: str
    severity: str
    category: str
    steps: list[AttackStep] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    success_criteria: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, indent=2)


# ============================================================
# Tool-to-Command Mapping
# ============================================================

_TOOL_COMMANDS = {
    "nmap": "nmap -sV -sC --top-ports 1000 {target}",
    "sqlmap": "sqlmap -u '{target}/page?id=1' --batch --dbs",
    "nikto": "nikto -h {target}",
    "gobuster": "gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt",
    "hydra": "hydra -l admin -P /usr/share/wordlists/rockyou.txt {service}://{target}",
    "curl": "curl -s -i {target}",
    "whatweb": "whatweb {target}",
    "ffuf": "ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt",
}


# ============================================================
# Scenario Generator
# ============================================================

class ScenarioGenerator:
    """
    Generates executable attack scenarios from policy mapper output.

    Each scenario contains:
    - Concrete attack steps with tool/commands
    - Expected outcomes
    - Deterministic evaluation predicates
    - Success/failure criteria
    """

    def __init__(self, target: str = "TARGET_IP"):
        self.target = target

    def generate_from_policy(self, policy_output: dict) -> list[AttackScenario]:
        """
        Generate attack scenarios from policy mapper output.

        Args:
            policy_output: Output from PolicyMapper.map_policy()

        Returns:
            List of executable AttackScenario objects
        """
        scenarios = []
        risks = policy_output.get("risks", [])
        actors = policy_output.get("actors", [])
        attack_trees = policy_output.get("attack_trees", [])

        # Generate scenarios from attack trees
        for tree in attack_trees:
            risk_id = tree.get("risk_ref", "")
            risk = next((r for r in risks if r["id"] == risk_id), None)
            if not risk:
                continue

            # Find matching actor
            actor = self._find_matching_actor(risk, actors)

            scenario = self._tree_to_scenario(tree, risk, actor)
            if scenario:
                scenarios.append(scenario)

        # Generate scenarios from actors
        for actor in actors:
            actor_scenario = self._actor_to_scenario(actor, risks)
            if actor_scenario:
                scenarios.append(actor_scenario)

        return scenarios

    def _tree_to_scenario(self, tree: dict, risk: dict,
                          actor: Optional[dict]) -> AttackScenario:
        """Convert an attack tree to an executable scenario."""
        scenario_id = f"SCENARIO-{tree.get('id', 'unknown')}"
        steps = []
        children = tree.get("children", [])

        for i, child in enumerate(children):
            step = AttackStep(
                step_id=f"{scenario_id}-{i+1}",
                label=child.get("label", f"Step {i+1}"),
                tool=self._select_tool(risk.get("category", "")),
                command=self._build_command(risk.get("category", ""), self.target),
                expected_outcome=self._describe_outcome(child.get("label", "")),
                evaluation_predicate=self._select_predicate(risk.get("category", "")),
                timeout_s=60,
            )
            steps.append(step)

        return AttackScenario(
            scenario_id=scenario_id,
            name=f"Attack: {risk.get('title', 'Unknown')[:60]}",
            description=f"Exploit {risk.get('category', 'unknown')} vulnerability: {risk.get('description', '')[:200]}",
            risk_ref=risk.get("id", ""),
            actor_ref=actor.get("id", "") if actor else "",
            severity=risk.get("severity", "medium"),
            category=risk.get("category", "general"),
            steps=steps,
            preconditions=[
                f"Target {self.target} is reachable",
                f"Security policy section '{risk.get('source_section', 'unknown')}' is active",
            ],
            success_criteria=[
                f"Vulnerability '{risk.get('title', '')[:40]}' is confirmed exploitable",
                "All attack steps complete without agent crash",
                "Audit trail contains complete attack log",
            ],
            tags=[risk.get("category", ""), risk.get("severity", ""), "auto-generated"],
        )

    def _actor_to_scenario(self, actor: dict, risks: list[dict]) -> Optional[AttackScenario]:
        """Generate a scenario based on actor profile."""
        actor_id = actor.get("id", "")
        actor_risks = [r for r in risks if r.get("category") in
                       ("authentication", "authorization", "data_protection")]

        if not actor_risks:
            return None

        steps = []
        tools = actor.get("tools", [])
        for i, tool in enumerate(tools[:3]):
            step = AttackStep(
                step_id=f"ACTOR-{actor_id}-{i+1}",
                label=f"Use {tool} for reconnaissance/exploitation",
                tool=tool if tool in _TOOL_COMMANDS else "shell",
                command=_TOOL_COMMANDS.get(tool, f"{tool} {self.target}"),
                expected_outcome=f"Gain information or access using {tool}",
                evaluation_predicate="no_injection_in_output",
                timeout_s=120,
            )
            steps.append(step)

        return AttackScenario(
            scenario_id=f"SCENARIO-{actor_id}",
            name=f"Actor Simulation: {actor.get('name', 'Unknown')}",
            description=f"Simulate {actor.get('name', 'Unknown')} attack pattern: {actor.get('description', '')[:200]}",
            risk_ref="",
            actor_ref=actor_id,
            severity="high",
            category="threat_actor_simulation",
            steps=steps,
            preconditions=[
                f"Attacker profile: {actor.get('skill_level', 'unknown')} skill, {actor.get('access_level', 'unknown')} access",
                "All defense mechanisms active",
            ],
            success_criteria=[
                "Attack is detected by telemetry monitor",
                "No sensitive data is exfiltrated",
                "Audit trail captures all attack steps",
            ],
            tags=[actor.get("skill_level", ""), actor.get("access_level", ""), "actor-simulation"],
        )

    def _find_matching_actor(self, risk: dict, actors: list[dict]) -> Optional[dict]:
        """Find the most relevant actor for a risk."""
        category = risk.get("category", "")
        for actor in actors:
            targets = actor.get("targets", [])
            if any(category in t.lower() for t in targets):
                return actor
        return actors[0] if actors else None

    def _select_tool(self, category: str) -> str:
        """Select appropriate tool for a risk category."""
        mapping = {
            "authentication": "hydra",
            "authorization": "curl",
            "input_validation": "sqlmap",
            "cryptography": "nmap",
            "network": "nmap",
            "data_protection": "curl",
            "configuration": "nikto",
            "logging_monitoring": "curl",
            "supply_chain": "nmap",
            "resilience": "ffuf",
        }
        return mapping.get(category, "curl")

    def _build_command(self, category: str, target: str) -> str:
        """Build tool command for a category."""
        tool = self._select_tool(category)
        template = _TOOL_COMMANDS.get(tool, "curl -s {target}")
        return template.format(target=target, service="ssh")

    def _describe_outcome(self, label: str) -> str:
        """Describe expected outcome for an attack step."""
        label_lower = label.lower()
        if "enumerate" in label_lower or "scan" in label_lower:
            return "Discover services, ports, or information"
        elif "inject" in label_lower:
            return "Confirm injection vulnerability exists"
        elif "escalat" in label_lower:
            return "Gain elevated access or permissions"
        elif "bypass" in label_lower:
            return "Successfully bypass security control"
        else:
            return "Attack step produces measurable result"

    def _select_predicate(self, category: str) -> str:
        """Select evaluation predicate for a category."""
        mapping = {
            "authentication": "no_credentials_exposed",
            "authorization": "tool_in_allowlist",
            "input_validation": "no_injection_in_output",
            "data_protection": "no_data_exfiltration",
            "logging_monitoring": "no_recursive_injection",
        }
        return mapping.get(category, "no_injection_in_output")
