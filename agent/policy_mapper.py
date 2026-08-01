"""
Policy-Driven Red Teaming — Policy Mapper

Inspired by:
  - "Policy driven agentic red teaming" (Red Hat, DEF CON 34)

Reads policy documents (YAML/JSON) and extracts risks, generates attack trees,
creates actor profiles, and produces Gherkin specs for testing.
"""

import json
import logging
import re
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("ozz.policy_mapper")


# ============================================================
# Data Structures
# ============================================================

class RiskSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackComplexity(Enum):
    LOW = "low"        # No special access needed
    MEDIUM = "medium"  # Some access/knowledge needed
    HIGH = "high"      # Significant access/expertise needed


@dataclass
class Risk:
    """A single identified risk."""
    id: str
    title: str
    description: str
    severity: RiskSeverity
    category: str
    source_section: str = ""
    cvss_estimate: float = 0.0
    cwe_id: str = ""
    attack_vectors: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class AttackTreeNode:
    """A node in an attack tree."""
    id: str
    label: str
    node_type: str = "AND"  # AND, OR, LEAF
    children: list = field(default_factory=list)
    risk_ref: str = ""
    complexity: AttackComplexity = AttackComplexity.MEDIUM

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "type": self.node_type,
            "complexity": self.complexity.value,
            "risk_ref": self.risk_ref,
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class ActorProfile:
    """Threat actor profile."""
    id: str
    name: str
    description: str
    skill_level: str = "intermediate"  # novice, intermediate, advanced, expert
    motivation: str = ""
    access_level: str = "external"     # external, internal, privileged
    tools: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    ttps: list[str] = field(default_factory=list)  # MITRE ATT&CK TTPs

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class GherkinScenario:
    """A Gherkin-format test scenario."""
    feature: str
    scenario: str
    given: list[str] = field(default_factory=list)
    when: list[str] = field(default_factory=list)
    then: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_gherkin(self) -> str:
        lines = []
        if self.tags:
            lines.append(" ".join(f"@{t}" for t in self.tags))
        lines.append(f"Feature: {self.feature}")
        lines.append(f"  Scenario: {self.scenario}")
        for step in self.given:
            lines.append(f"    Given {step}")
        for step in self.when:
            lines.append(f"    When {step}")
        for step in self.then:
            lines.append(f"    Then {step}")
        return "\n".join(lines)


# ============================================================
# Policy Risk Extractor
# ============================================================

class PolicyRiskExtractor:
    """Extracts risks from policy document sections."""

    # Keywords that signal risk-relevant content
    _RISK_KEYWORDS = {
        "critical": RiskSeverity.CRITICAL,
        "high": RiskSeverity.HIGH,
        "medium": RiskSeverity.MEDIUM,
        "low": RiskSeverity.LOW,
        "danger": RiskSeverity.HIGH,
        "warning": RiskSeverity.MEDIUM,
        "vulnerability": RiskSeverity.HIGH,
        "threat": RiskSeverity.HIGH,
        "exploit": RiskSeverity.CRITICAL,
        "injection": RiskSeverity.CRITICAL,
        "overflow": RiskSeverity.CRITICAL,
        "authentication": RiskSeverity.HIGH,
        "authorization": RiskSeverity.HIGH,
        "encryption": RiskSeverity.MEDIUM,
        "access control": RiskSeverity.HIGH,
        "privilege": RiskSeverity.HIGH,
        "credential": RiskSeverity.HIGH,
        "token": RiskSeverity.MEDIUM,
        "session": RiskSeverity.MEDIUM,
        "input validation": RiskSeverity.HIGH,
        "sanitization": RiskSeverity.HIGH,
        "bypass": RiskSeverity.HIGH,
        "escalation": RiskSeverity.CRITICAL,
        "exfiltration": RiskSeverity.CRITICAL,
        "denial of service": RiskSeverity.HIGH,
        "dos": RiskSeverity.HIGH,
        "rce": RiskSeverity.CRITICAL,
        "remote code execution": RiskSeverity.CRITICAL,
        "ssrf": RiskSeverity.HIGH,
        "xss": RiskSeverity.HIGH,
        "csrf": RiskSeverity.MEDIUM,
        "sql injection": RiskSeverity.CRITICAL,
        "path traversal": RiskSeverity.HIGH,
        "file upload": RiskSeverity.HIGH,
        "default password": RiskSeverity.HIGH,
        "weak password": RiskSeverity.HIGH,
        "misconfiguration": RiskSeverity.MEDIUM,
        "logging": RiskSeverity.LOW,
        "monitoring": RiskSeverity.LOW,
        "audit": RiskSeverity.LOW,
    }

    # Category mapping
    _CATEGORY_KEYWORDS = {
        "authentication": ["auth", "login", "password", "credential", "token", "session"],
        "authorization": ["access", "permission", "role", "privilege", "acl", "rbac"],
        "input_validation": ["input", "validation", "sanitiz", "inject", "xss", "sqli"],
        "cryptography": ["encrypt", "decrypt", "hash", "key", "certificate", "tls", "ssl"],
        "network": ["network", "port", "firewall", "proxy", "dns", "tcp", "udp"],
        "data_protection": ["data", "privacy", "pii", "gdpr", "retention", "backup"],
        "configuration": ["config", "default", "hardcod", "secret", "env", "setting"],
        "logging_monitoring": ["log", "audit", "monitor", "alert", "siem", "trace"],
        "supply_chain": ["dependency", "library", "package", "vendor", "third-party"],
        "resilience": ["availability", "redundancy", "failover", "recovery", "backup"],
    }

    def extract_from_text(self, text: str, section_name: str = "") -> list[Risk]:
        """Extract risks from a text section."""
        risks = []
        text_lower = text.lower()
        seen = set()

        # Find risk-relevant sentences
        sentences = re.split(r'[.!?\n]+', text)
        for sentence in sentences:
            sentence = sentence.strip()
            if len(sentence) < 10:
                continue

            sentence_lower = sentence.lower()
            for keyword, severity in self._RISK_KEYWORDS.items():
                if keyword in sentence_lower and sentence not in seen:
                    seen.add(sentence)
                    category = self._categorize(sentence_lower)
                    risk_id = f"RISK-{len(risks)+1:03d}"
                    risks.append(Risk(
                        id=risk_id,
                        title=sentence[:100],
                        description=sentence,
                        severity=severity,
                        category=category,
                        source_section=section_name,
                    ))
                    break  # One risk per sentence

        return risks

    def _categorize(self, text: str) -> str:
        """Categorize a risk based on keywords."""
        for category, keywords in self._CATEGORY_KEYWORDS.items():
            for kw in keywords:
                if kw in text:
                    return category
        return "general"


# ============================================================
# Policy Mapper — Main Engine
# ============================================================

class PolicyMapper:
    """
    Reads policy documents and generates:
    1. Risk inventory
    2. Attack trees
    3. Actor profiles
    4. Gherkin test scenarios

    Implements Red Hat's policy-driven agentic red teaming approach.
    """

    def __init__(self):
        self.extractor = PolicyRiskExtractor()

    def map_policy(self, policy: dict) -> dict:
        """
        Process a policy document and generate all artifacts.

        Args:
            policy: Policy document as dict (parsed YAML/JSON)

        Returns:
            Dict with risks, attack_trees, actors, scenarios
        """
        risks = self._extract_risks(policy)
        attack_trees = self._generate_attack_trees(risks)
        actors = self._generate_actor_profiles(risks)
        scenarios = self._generate_gherkin_scenarios(risks, actors)
        metrics = self._calculate_metrics(risks, attack_trees, actors, scenarios)

        return {
            "risks": [r.to_dict() for r in risks],
            "attack_trees": [t.to_dict() for t in attack_trees],
            "actors": [a.to_dict() for a in actors],
            "gherkin_scenarios": [s.to_gherkin() for s in scenarios],
            "metrics": metrics,
            "generated_at": time.time(),
        }

    def _extract_risks(self, policy: dict) -> list[Risk]:
        """Extract risks from all sections of a policy document."""
        all_risks = []
        risk_counter = 0

        def process_section(data: Any, path: str = ""):
            nonlocal risk_counter
            if isinstance(data, dict):
                for key, value in data.items():
                    new_path = f"{path}.{key}" if path else key
                    process_section(value, new_path)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    process_section(item, f"{path}[{i}]")
            elif isinstance(data, str) and len(data) > 5:
                risks = self.extractor.extract_from_text(data, section_name=path)
                for risk in risks:
                    risk_counter += 1
                    risk.id = f"RISK-{risk_counter:03d}"
                all_risks.extend(risks)

        process_section(policy)

        # Deduplicate by title similarity
        return self._deduplicate_risks(all_risks)

    def _deduplicate_risks(self, risks: list[Risk]) -> list[Risk]:
        """Remove duplicate risks based on title similarity."""
        if not risks:
            return risks

        unique = []
        seen_titles = set()
        for risk in risks:
            # Normalize title for comparison
            normalized = re.sub(r'[^a-z0-9]', '', risk.title.lower())
            if normalized[:50] not in seen_titles:
                seen_titles.add(normalized[:50])
                unique.append(risk)

        # Re-number
        for i, risk in enumerate(unique):
            risk.id = f"RISK-{i+1:03d}"

        return unique

    def _generate_attack_trees(self, risks: list[Risk]) -> list[AttackTreeNode]:
        """Generate attack trees from identified risks."""
        trees = []
        for risk in risks:
            root = AttackTreeNode(
                id=f"TREE-{risk.id}",
                label=f"Exploit: {risk.title[:60]}",
                node_type="OR",
                risk_ref=risk.id,
                complexity=self._estimate_complexity(risk),
            )

            # Generate attack steps based on category
            steps = self._generate_attack_steps(risk)
            for i, step in enumerate(steps):
                child = AttackTreeNode(
                    id=f"{root.id}-{i+1}",
                    label=step,
                    node_type="LEAF",
                    risk_ref=risk.id,
                )
                root.children.append(child)

            if root.children:
                trees.append(root)

        return trees

    def _generate_attack_steps(self, risk: Risk) -> list[str]:
        """Generate concrete attack steps for a risk."""
        category_steps = {
            "authentication": [
                "Enumerate valid usernames via response differences",
                "Attempt credential stuffing with common passwords",
                "Test for password reset token predictability",
                "Check for session fixation vulnerabilities",
                "Test MFA bypass via API endpoints",
            ],
            "authorization": [
                "Test horizontal privilege escalation (IDOR)",
                "Test vertical privilege escalation",
                "Check for missing function-level access control",
                "Test JWT token manipulation",
                "Verify role-based access on all endpoints",
            ],
            "input_validation": [
                "Test for SQL injection in all input fields",
                "Test for XSS (reflected, stored, DOM-based)",
                "Test for command injection via system calls",
                "Test for path traversal in file parameters",
                "Test for SSTI in template rendering",
            ],
            "cryptography": [
                "Check for weak cipher suites",
                "Test for predictable random number generation",
                "Verify certificate validation",
                "Check for hardcoded keys/secrets",
                "Test for timing attacks in comparison",
            ],
            "network": [
                "Scan for open ports and services",
                "Test for DNS rebinding",
                "Check for SSRF via URL parameters",
                "Test firewall rule bypass techniques",
                "Enumerate internal network via error messages",
            ],
            "data_protection": [
                "Check for sensitive data in responses",
                "Test for PII leakage in error messages",
                "Verify data encryption at rest and in transit",
                "Check for improper data retention",
                "Test for backup file exposure",
            ],
            "configuration": [
                "Check for default credentials",
                "Test for debug mode enabled",
                "Check for exposed admin interfaces",
                "Verify security headers",
                "Test for directory listing",
            ],
            "logging_monitoring": [
                "Check if security events are logged",
                "Test for log injection vulnerabilities",
                "Verify alert thresholds",
                "Check for sensitive data in logs",
                "Test SIEM query injection",
            ],
            "supply_chain": [
                "Check for known CVEs in dependencies",
                "Test for typosquatting in packages",
                "Verify dependency integrity checks",
                "Check for outdated libraries",
                "Test for prototype pollution",
            ],
            "resilience": [
                "Test rate limiting effectiveness",
                "Check for resource exhaustion",
                "Test failover mechanisms",
                "Verify backup restoration",
                "Test for cascade failure scenarios",
            ],
        }

        steps = category_steps.get(risk.category, [
            "Reconnaissance and information gathering",
            "Vulnerability identification and verification",
            "Exploitation attempt",
            "Impact assessment",
            "Evidence collection",
        ])

        # Return 3-5 steps based on severity
        count = 5 if risk.severity in (RiskSeverity.CRITICAL, RiskSeverity.HIGH) else 3
        return steps[:count]

    def _estimate_complexity(self, risk: Risk) -> AttackComplexity:
        """Estimate attack complexity based on risk characteristics."""
        if risk.severity == RiskSeverity.CRITICAL:
            return AttackComplexity.LOW
        elif risk.severity == RiskSeverity.HIGH:
            return AttackComplexity.LOW
        elif risk.severity == RiskSeverity.MEDIUM:
            return AttackComplexity.MEDIUM
        else:
            return AttackComplexity.HIGH

    def _generate_actor_profiles(self, risks: list[Risk]) -> list[ActorProfile]:
        """Generate threat actor profiles based on identified risks."""
        actors = []

        # External attacker (low sophistication)
        actors.append(ActorProfile(
            id="ACTOR-001",
            name="Script Kiddie",
            description="Low-skill attacker using automated tools and public exploits",
            skill_level="novice",
            motivation="Curiosity, reputation",
            access_level="external",
            tools=["nmap", "sqlmap", "metasploit", "nikto", "hydra"],
            targets=[r.title for r in risks if r.severity in (RiskSeverity.CRITICAL, RiskSeverity.HIGH)][:5],
            ttps=["T1190", "T1110", "T1059"],
        ))

        # Organized cybercrime
        actors.append(ActorProfile(
            id="ACTOR-002",
            name="Organized Cybercriminal",
            description="Financially motivated group with moderate technical capabilities",
            skill_level="intermediate",
            motivation="Financial gain",
            access_level="external",
            tools=["cobalt_strike", "custom_exploits", "phishing_kits", "ransomware"],
            targets=[r.title for r in risks if r.category in ("authentication", "data_protection")][:5],
            ttps=["T1566", "T1486", "T1078", "T1053"],
        ))

        # Advanced Persistent Threat
        actors.append(ActorProfile(
            id="ACTOR-003",
            name="APT Operator",
            description="State-sponsored or advanced group with significant resources",
            skill_level="expert",
            motivation="Espionage, strategic advantage",
            access_level="privileged",
            tools=["zero_days", "custom_implants", "supply_chain_attacks", "social_engineering"],
            targets=[r.title for r in risks][:10],
            ttps=["T1195", "T1071", "T1056", "T1027", "T1070"],
        ))

        # Insider threat
        actors.append(ActorProfile(
            id="ACTOR-004",
            name="Insider Threat",
            description="Malicious or compromised internal user with legitimate access",
            skill_level="intermediate",
            motivation="Financial, revenge, coercion",
            access_level="internal",
            tools=["legitimate_credentials", "internal_tools", "data_export"],
            targets=[r.title for r in risks if r.category in ("authorization", "data_protection", "logging_monitoring")][:5],
            ttps=["T1078", "T1530", "T1565"],
        ))

        # AI-powered attacker
        actors.append(ActorProfile(
            id="ACTOR-005",
            name="AI-Augmented Attacker",
            description="Attacker leveraging AI/LLM for automated vulnerability discovery and exploitation",
            skill_level="advanced",
            motivation="Research, competition, profit",
            access_level="external",
            tools=["llm_agents", "automated_fuzzers", "ml_payload_generators"],
            targets=[r.title for r in risks if r.category in ("input_validation", "logging_monitoring")][:5],
            ttps=["T1190", "T1059", "T1027"],
        ))

        return actors

    def _generate_gherkin_scenarios(self, risks: list[Risk],
                                     actors: list[ActorProfile]) -> list[GherkinScenario]:
        """Generate Gherkin test scenarios for each risk."""
        scenarios = []

        for risk in risks:
            # Base scenario for each risk
            scenario = GherkinScenario(
                feature=f"Security: {risk.category}",
                scenario=f"Verify protection against {risk.title[:60]}",
                given=[
                    f"a {risk.category} security policy is enforced",
                    f"the system is deployed in a production-like environment",
                ],
                when=[
                    f"an attacker attempts to exploit {risk.title[:40]}",
                ],
                then=[
                    f"the attack must be detected or blocked",
                    f"an alert must be generated with severity {risk.severity.value}",
                    f"the audit trail must record the attempt",
                ],
                tags=[risk.category, risk.severity.value, "security"],
            )
            scenarios.append(scenario)

            # Injection-specific scenario if applicable
            if "injection" in risk.category.lower() or "inject" in risk.title.lower():
                injection_scenario = GherkinScenario(
                    feature=f"Security: Injection Defense",
                    scenario=f"Detect and neutralize {risk.title[:50]}",
                    given=[
                        "the telemetry sanitizer is active",
                        "the injection detector monitors all inputs",
                    ],
                    when=[
                        f"a {risk.category} payload is embedded in log data",
                        "the contaminated data enters the processing pipeline",
                    ],
                    then=[
                        "the sanitizer must detect the injection attempt",
                        "the payload must be neutralized before reaching the LLM",
                        "a CRITICAL severity alert must fire",
                        "the audit trail must log the sanitization event",
                    ],
                    tags=["injection", "sanitization", risk.severity.value],
                )
                scenarios.append(injection_scenario)

        # Actor-specific scenarios
        for actor in actors:
            scenario = GherkinScenario(
                feature=f"Threat Actor Defense: {actor.name}",
                scenario=f"Defend against {actor.name} attack patterns",
                given=[
                    f"the system faces a {actor.skill_level}-level attacker",
                    f"the attacker has {actor.access_level} access",
                ],
                when=[
                    f"the attacker uses {', '.join(actor.tools[:3])} techniques",
                ],
                then=[
                    "the attack must be detected within 1 iteration",
                    "the agent must not leak sensitive information",
                    "all attack actions must be logged in the audit trail",
                ],
                tags=[actor.skill_level, actor.access_level, "threat_actor"],
            )
            scenarios.append(scenario)

        return scenarios

    def _calculate_metrics(self, risks: list[Risk], trees: list[AttackTreeNode],
                           actors: list[ActorProfile],
                           scenarios: list[GherkinScenario]) -> dict:
        """Calculate quality metrics for the policy mapping."""
        severity_counts = {}
        for risk in risks:
            s = risk.severity.value
            severity_counts[s] = severity_counts.get(s, 0) + 1

        category_counts = {}
        for risk in risks:
            c = risk.category
            category_counts[c] = category_counts.get(c, 0) + 1

        total_attack_steps = sum(len(t.children) for t in trees)

        return {
            "total_risks": len(risks),
            "severity_distribution": severity_counts,
            "category_distribution": category_counts,
            "attack_trees_generated": len(trees),
            "total_attack_steps": total_attack_steps,
            "actor_profiles": len(actors),
            "gherkin_scenarios": len(scenarios),
        }
