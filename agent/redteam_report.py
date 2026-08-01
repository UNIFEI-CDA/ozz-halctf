"""
Ozz — Automated Red-Team Reporting (Track E)

Inspired by "Improving AI Red-Teaming by Systematizing Red-Teaming Reports" (CSET, DEF CON 34).

Every test generates a structured report with:
  - Threat model (what's being tested and why)
  - Methodological details (step-by-step reproduction)
  - Harms elicited (what damage was possible)
  - Actionable mitigation info (how to fix)

Output: JSON + Markdown formats.

Reports are self-contained, reproducible, and follow CSET's taxonomy
for systematic red-teaming documentation.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from pathlib import Path

logger = logging.getLogger("ozz.redteam")

REPORT_DIR = os.environ.get(
    "OZZ_REPORT_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reports"),
)


# ============================================================
# Taxonomy (CSET-aligned)
# ============================================================

class ThreatCategory(Enum):
    """CSET-aligned threat categories for AI red-teaming."""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DENIAL_OF_SERVICE = "denial_of_service"
    SUPPLY_CHAIN = "supply_chain"
    MODEL_EXTRACTION = "model_extraction"
    ADVERSARIAL_INPUT = "adversarial_input"
    DECEPTION = "deception"
    SOCIAL_ENGINEERING = "social_engineering"
    COMMAND_INJECTION = "command_injection"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    INFORMATION_DISCLOSURE = "information_disclosure"
    LOGIC_FLAW = "logic_flaw"
    RESOURCE_EXHAUSTION = "resource_exhaustion"


class SeverityLevel(Enum):
    """Impact severity levels."""
    CRITICAL = "critical"   # Full system compromise, flag exfiltration
    HIGH = "high"           # Significant access, credential theft
    MEDIUM = "medium"       # Limited access, information disclosure
    LOW = "low"             # Minor impact, cosmetic issues
    INFO = "info"           # Informational finding


class Reproducibility(Enum):
    """How reliably the finding can be reproduced."""
    ALWAYS = "always"       # 100% reproduction rate
    OFTEN = "often"         # >75% reproduction rate
    SOMETIMES = "sometimes" # 25-75% reproduction rate
    RARELY = "rarely"       # <25% reproduction rate
    ONCE = "once"           # Observed only once


# ============================================================
# Report Data Structures
# ============================================================

@dataclass
class ThreatModel:
    """What is being tested and why."""
    target: str                      # Target system/component
    category: ThreatCategory         # Type of threat
    attack_vector: str               # How the attack is delivered
    attacker_capability: str         # Required attacker skill/resources
    preconditions: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        return d


@dataclass
class MethodStep:
    """A single step in the reproduction methodology."""
    step_number: int
    action: str
    command: str = ""
    expected_result: str = ""
    actual_result: str = ""
    notes: str = ""


@dataclass
class HarmRecorded:
    """A specific harm or damage that was possible."""
    description: str
    severity: SeverityLevel
    data_affected: str = ""
    scope: str = ""  # "local", "network", "global"
    reversible: bool = True

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Mitigation:
    """Actionable mitigation recommendation."""
    description: str
    priority: str = "high"  # critical, high, medium, low
    implementation_effort: str = "medium"  # low, medium, high
    category: str = "fix"  # fix, workaround, detection, prevention
    code_snippet: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class RedTeamReport:
    """
    Structured red-team report following CSET methodology.

    Self-contained, reproducible, and actionable.
    """
    # Identity
    report_id: str = ""
    timestamp: float = field(default_factory=time.time)
    tester: str = "Ozz-Autonomous-Agent"

    # Threat Model
    threat_model: Optional[ThreatModel] = None

    # Methodology
    objective: str = ""
    methodology_summary: str = ""
    steps: list[MethodStep] = field(default_factory=list)

    # Findings
    finding_title: str = ""
    finding_description: str = ""
    harms: list[HarmRecorded] = field(default_factory=list)

    # Reproducibility
    reproducibility: Reproducibility = Reproducibility.ALWAYS
    reproduction_rate: float = 1.0  # 0.0 to 1.0

    # Evidence
    evidence: list[str] = field(default_factory=list)  # Log excerpts, screenshots, etc.
    raw_logs: list[str] = field(default_factory=list)

    # Mitigations
    mitigations: list[Mitigation] = field(default_factory=list)

    # Metadata
    tags: list[str] = field(default_factory=list)
    related_reports: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "timestamp": self.timestamp,
            "tester": self.tester,
            "threat_model": self.threat_model.to_dict() if self.threat_model else None,
            "objective": self.objective,
            "methodology_summary": self.methodology_summary,
            "steps": [asdict(s) for s in self.steps],
            "finding_title": self.finding_title,
            "finding_description": self.finding_description,
            "harms": [h.to_dict() for h in self.harms],
            "reproducibility": self.reproducibility.value,
            "reproduction_rate": self.reproduction_rate,
            "evidence": self.evidence,
            "raw_logs": self.raw_logs[-20:],  # Limit raw logs
            "mitigations": [asdict(m) for m in self.mitigations],
            "tags": self.tags,
            "related_reports": self.related_reports,
            "duration_seconds": self.duration_seconds,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str, ensure_ascii=False)

    def to_markdown(self) -> str:
        """Generate a human-readable Markdown report."""
        tm = self.threat_model
        lines = [
            f"# Red-Team Report: {self.finding_title}",
            f"",
            f"**Report ID:** `{self.report_id}`",
            f"**Timestamp:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.timestamp))}",
            f"**Tester:** {self.tester}",
            f"**Duration:** {self.duration_seconds:.1f}s",
            f"",
            f"---",
            f"",
            f"## 1. Threat Model",
            f"",
        ]

        if tm:
            lines.extend([
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **Target** | {tm.target} |",
                f"| **Category** | {tm.category.value} |",
                f"| **Attack Vector** | {tm.attack_vector} |",
                f"| **Attacker Capability** | {tm.attacker_capability} |",
                f"",
            ])
            if tm.preconditions:
                lines.append("**Preconditions:**")
                for p in tm.preconditions:
                    lines.append(f"- {p}")
                lines.append("")
            if tm.assumptions:
                lines.append("**Assumptions:**")
                for a in tm.assumptions:
                    lines.append(f"- {a}")
                lines.append("")

        lines.extend([
            f"## 2. Objective",
            f"",
            f"{self.objective}",
            f"",
            f"## 3. Methodology",
            f"",
            f"{self.methodology_summary}",
            f"",
        ])

        if self.steps:
            lines.append("### Steps to Reproduce")
            lines.append("")
            for step in self.steps:
                lines.append(f"**Step {step.step_number}:** {step.action}")
                if step.command:
                    lines.append(f"```bash\n{step.command}\n```")
                if step.expected_result:
                    lines.append(f"Expected: {step.expected_result}")
                if step.actual_result:
                    lines.append(f"Actual: {step.actual_result}")
                if step.notes:
                    lines.append(f"Note: {step.notes}")
                lines.append("")

        lines.extend([
            f"## 4. Finding",
            f"",
            f"**Title:** {self.finding_title}",
            f"",
            f"**Description:**",
            f"{self.finding_description}",
            f"",
            f"**Reproducibility:** {self.reproducibility.value} ({self.reproduction_rate * 100:.0f}%)",
            f"",
        ])

        if self.harms:
            lines.extend([
                f"## 5. Harms Elicited",
                f"",
                f"| # | Description | Severity | Scope | Reversible |",
                f"|---|-------------|----------|-------|------------|",
            ])
            for i, h in enumerate(self.harms, 1):
                lines.append(
                    f"| {i} | {h.description} | {h.severity.value} | {h.scope} | {'Yes' if h.reversible else 'No'} |"
                )
            lines.append("")

        if self.evidence:
            lines.extend([
                f"## 6. Evidence",
                f"",
            ])
            for i, e in enumerate(self.evidence, 1):
                lines.append(f"### Evidence {i}")
                lines.append(f"```\n{e}\n```")
                lines.append("")

        if self.mitigations:
            lines.extend([
                f"## 7. Mitigations",
                f"",
            ])
            for i, m in enumerate(self.mitigations, 1):
                lines.extend([
                    f"### Mitigation {i}: {m.description}",
                    f"",
                    f"- **Priority:** {m.priority}",
                    f"- **Effort:** {m.implementation_effort}",
                    f"- **Category:** {m.category}",
                ])
                if m.code_snippet:
                    lines.append(f"```python\n{m.code_snippet}\n```")
                if m.references:
                    lines.append(f"- **References:** {', '.join(m.references)}")
                lines.append("")

        if self.tags:
            lines.extend([
                f"---",
                f"",
                f"**Tags:** {', '.join(self.tags)}",
            ])

        return "\n".join(lines)


# ============================================================
# Report Builder (convenience API)
# ============================================================

class ReportBuilder:
    """Fluent API for building red-team reports."""

    def __init__(self, report_id: str = ""):
        self._report = RedTeamReport(
            report_id=report_id or f"RPT-{int(time.time() * 1000)}",
        )
        self._start_time = time.time()

    def threat(self, target: str, category: ThreatCategory,
               attack_vector: str, attacker_capability: str,
               preconditions: list = None, assumptions: list = None) -> "ReportBuilder":
        self._report.threat_model = ThreatModel(
            target=target,
            category=category,
            attack_vector=attack_vector,
            attacker_capability=attacker_capability,
            preconditions=preconditions or [],
            assumptions=assumptions or [],
        )
        return self

    def objective(self, text: str) -> "ReportBuilder":
        self._report.objective = text
        return self

    def methodology(self, summary: str) -> "ReportBuilder":
        self._report.methodology_summary = summary
        return self

    def step(self, action: str, command: str = "", expected: str = "",
             actual: str = "", notes: str = "") -> "ReportBuilder":
        self._report.steps.append(MethodStep(
            step_number=len(self._report.steps) + 1,
            action=action,
            command=command,
            expected_result=expected,
            actual_result=actual,
            notes=notes,
        ))
        return self

    def finding(self, title: str, description: str,
                reproducibility: Reproducibility = Reproducibility.ALWAYS,
                rate: float = 1.0) -> "ReportBuilder":
        self._report.finding_title = title
        self._report.finding_description = description
        self._report.reproducibility = reproducibility
        self._report.reproduction_rate = rate
        return self

    def harm(self, description: str, severity: SeverityLevel,
             data_affected: str = "", scope: str = "local",
             reversible: bool = True) -> "ReportBuilder":
        self._report.harms.append(HarmRecorded(
            description=description,
            severity=severity,
            data_affected=data_affected,
            scope=scope,
            reversible=reversible,
        ))
        return self

    def evidence(self, text: str) -> "ReportBuilder":
        self._report.evidence.append(text)
        return self

    def log(self, text: str) -> "ReportBuilder":
        self._report.raw_logs.append(text)
        return self

    def mitigation(self, description: str, priority: str = "high",
                   effort: str = "medium", category: str = "fix",
                   code: str = "", refs: list = None) -> "ReportBuilder":
        self._report.mitigations.append(Mitigation(
            description=description,
            priority=priority,
            implementation_effort=effort,
            category=category,
            code_snippet=code,
            references=refs or [],
        ))
        return self

    def tags(self, *tags: str) -> "ReportBuilder":
        self._report.tags.extend(tags)
        return self

    def build(self) -> RedTeamReport:
        self._report.duration_seconds = time.time() - self._start_time
        return self._report


# ============================================================
# Report Manager — Save and retrieve reports
# ============================================================

class ReportManager:
    """Manage red-team report storage and retrieval."""

    def __init__(self, report_dir: str = REPORT_DIR):
        self.report_dir = report_dir
        Path(report_dir).mkdir(parents=True, exist_ok=True)

    def save(self, report: RedTeamReport, formats: list[str] = None) -> dict[str, str]:
        """
        Save a report in specified formats.

        Args:
            report: The report to save
            formats: List of formats ("json", "markdown"). Default: both.

        Returns:
            Dict of format → file path
        """
        formats = formats or ["json", "markdown"]
        saved = {}

        for fmt in formats:
            if fmt == "json":
                path = os.path.join(self.report_dir, f"{report.report_id}.json")
                with open(path, "w") as f:
                    f.write(report.to_json())
                saved["json"] = path
            elif fmt == "markdown":
                path = os.path.join(self.report_dir, f"{report.report_id}.md")
                with open(path, "w") as f:
                    f.write(report.to_markdown())
                saved["markdown"] = path

        logger.info(f"📝 Report saved: {report.report_id} → {list(saved.values())}")
        return saved

    def load_json(self, report_id: str) -> Optional[dict]:
        """Load a JSON report."""
        path = os.path.join(self.report_dir, f"{report_id}.json")
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
        return None

    def list_reports(self, limit: int = 50) -> list[str]:
        """List available report IDs."""
        reports = []
        for f in os.listdir(self.report_dir):
            if f.endswith(".json"):
                reports.append(f[:-5])
        reports.sort(reverse=True)
        return reports[:limit]

    def get_summary(self) -> dict:
        """Get summary of all reports."""
        reports = self.list_reports()
        return {
            "total_reports": len(reports),
            "report_ids": reports[:20],
            "report_dir": self.report_dir,
        }


# ============================================================
# Specialized Report Factories
# ============================================================

def create_prompt_injection_report(
    target: str,
    injection_payload: str,
    was_successful: bool,
    bypassed_guardrails: list[str],
    damage_possible: str,
) -> RedTeamReport:
    """Create a report for a prompt injection test."""
    builder = ReportBuilder(f"PI-{int(time.time() * 1000)}")

    builder.threat(
        target=target,
        category=ThreatCategory.PROMPT_INJECTION,
        attack_vector="User-controlled input injected into LLM prompt context",
        attacker_capability="Low — requires only ability to send messages",
        preconditions=["Agent processes user input in LLM context window"],
    )

    builder.objective(
        "Test whether the agent's prompt injection defenses can be bypassed "
        "to execute unauthorized actions or extract protected information."
    )

    builder.methodology(
        "Automated prompt injection testing using known injection patterns. "
        "Each payload is sent as user input and the agent's response is analyzed "
        "for signs of guardrail bypass."
    )

    builder.step(
        "Send injection payload",
        command=f"Input: {injection_payload[:200]}",
        expected="Agent rejects or safely handles the injection",
        actual="Injection successful" if was_successful else "Injection blocked",
    )

    if was_successful:
        builder.finding(
            title=f"Prompt Injection Bypass on {target}",
            description=(
                f"Successfully bypassed agent guardrails using injection pattern. "
                f"Guardrails bypassed: {', '.join(bypassed_guardrails)}. "
                f"Damage possible: {damage_possible}"
            ),
            reproducibility=Reproducibility.OFTEN,
            rate=0.8,
        )
        builder.harm(
            description=damage_possible,
            severity=SeverityLevel.HIGH,
            scope="system",
        )
        builder.mitigation(
            description="Implement input sanitization and output validation layers",
            priority="critical",
            code="# Add to input pipeline:\nvalidate_no_injection(user_input)",
        )
    else:
        builder.finding(
            title=f"Prompt Injection Blocked on {target}",
            description="Injection attempt was successfully blocked by existing guardrails.",
            reproducibility=Reproducibility.ALWAYS,
        )

    builder.tags("prompt_injection", "automated_test", "defense_validation")
    return builder.build()


def create_deception_report(
    attacker_id: str,
    scan_type: str,
    deception_method: str,
    fake_flags_served: int,
) -> RedTeamReport:
    """Create a report for a deception/bifurcation event."""
    builder = ReportBuilder(f"DEC-{int(time.time() * 1000)}")

    builder.threat(
        target="Ozz Agent",
        category=ThreatCategory.DECEPTION,
        attack_vector="External bot/scanner probing agent endpoints",
        attacker_capability="Medium — automated scanning tools",
    )

    builder.objective(
        "Deploy bifurcation deception against detected scanner to waste "
        "attacker time and corrupt their scoreboard with fake flags."
    )

    builder.methodology(
        f"Detected {scan_type} scan from attacker {attacker_id[:16]}... "
        f"via behavioral fingerprinting. Served parallel reality with "
        f"{deception_method} deception method."
    )

    builder.finding(
        title=f"Deception Deployed: {scan_type} Scanner Bifurcated",
        description=(
            f"Attacker {attacker_id[:16]}... was detected performing {scan_type} scans. "
            f"Bifurcation engine served {fake_flags_served} fake flags via {deception_method}. "
            f"Attacker's time wasted and potential scoreboard penalties applied."
        ),
        reproducibility=Reproducibility.ALWAYS,
    )

    builder.harm(
        description="Attacker receives corrupted intelligence and fake flags",
        severity=SeverityLevel.LOW,
        scope="network",
        reversible=True,
    )

    builder.tags("deception", "bifurcation", "active_defense")
    return builder.build()
