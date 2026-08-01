"""
Ozz — Metrics Module
Evaluation metrics for autonomous pentesting agent performance.

Inspired by DEF CON 34 AI Village posters:
- "Beyond CTFs: Engineering AI Agents for Real-World Web Pentesting" (BugBase)
- "The Collapse of the Skill Barrier: Building Autonomous CTF Tools Through Pure Intent" (Puzzled Hackers)

Metrics:
  1. Meaningful Coverage: % of target surface area explored
  2. Bug Density: vulnerabilities found per unit of exploration
  3. Context Cost: tokens consumed per useful finding
  4. Loop Rate: how often the agent repeats actions (should be < 5%)
"""

import hashlib
import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

logger = logging.getLogger("ozz.metrics")


# ============================================================
# Data Structures
# ============================================================


@dataclass
class ExplorationUnit:
    """A single unit of surface area explored."""
    unit_type: str  # endpoint, port, parameter, technology, file
    identifier: str  # e.g., "/api/login", "80/tcp", "id param", "nginx 1.21"
    target: str = ""
    timestamp: float = field(default_factory=time.time)
    phase: str = ""
    tool: str = ""
    is_new: bool = True  # First time seeing this unit

    def key(self) -> str:
        return f"{self.target}:{self.unit_type}:{self.identifier}"


@dataclass
class Finding:
    """A vulnerability or useful discovery."""
    finding_type: str  # vulnerability, credential, flag, information
    category: str  # sql_injection, xss, ssti, default_creds, etc.
    target: str = ""
    severity: str = "medium"  # low, medium, high, critical
    description: str = ""
    timestamp: float = field(default_factory=time.time)
    action_index: int = 0
    tokens_consumed: int = 0


@dataclass
class ActionRecord:
    """A record of an agent action for loop detection."""
    action_index: int
    tool: str
    command_hash: str  # Hash of the command for comparison
    target: str = ""
    phase: str = ""
    timestamp: float = field(default_factory=time.time)
    produced_new_info: bool = False


# ============================================================
# Metric Definitions
# ============================================================


@dataclass
class CoverageMetric:
    """Meaningful coverage: % of target surface area explored."""
    total_units_discovered: int = 0
    unique_units: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    by_target: dict[str, int] = field(default_factory=dict)
    coverage_pct: float = 0.0  # 0-100
    estimated_surface: int = 0  # Estimated total surface area

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BugDensityMetric:
    """Bug density: vulnerabilities found per unit of exploration."""
    total_findings: int = 0
    total_exploration_units: int = 0
    density: float = 0.0  # findings per unit
    by_severity: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)
    by_target: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ContextCostMetric:
    """Context cost: tokens consumed per useful finding."""
    total_tokens: int = 0
    useful_findings: int = 0  # flags + vulnerabilities
    cost_per_finding: float = 0.0  # tokens per finding
    cost_per_flag: float = 0.0  # tokens per flag
    by_phase: dict[str, int] = field(default_factory=dict)  # tokens per phase

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LoopRateMetric:
    """Loop rate: how often the agent repeats actions."""
    total_actions: int = 0
    repeated_actions: int = 0
    loop_rate: float = 0.0  # 0-1 (should be < 0.05)
    repeated_commands: list[dict] = field(default_factory=list)  # Top repeated
    phase_loop_rates: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class MetricsSnapshot:
    """Complete metrics snapshot."""
    timestamp: float = field(default_factory=time.time)
    run_id: str = ""
    coverage: CoverageMetric = field(default_factory=CoverageMetric)
    bug_density: BugDensityMetric = field(default_factory=BugDensityMetric)
    context_cost: ContextCostMetric = field(default_factory=ContextCostMetric)
    loop_rate: LoopRateMetric = field(default_factory=LoopRateMetric)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "run_id": self.run_id,
            "coverage": self.coverage.to_dict(),
            "bug_density": self.bug_density.to_dict(),
            "context_cost": self.context_cost.to_dict(),
            "loop_rate": self.loop_rate.to_dict(),
        }

    def summary_string(self) -> str:
        """One-line summary for logging."""
        return (
            f"Coverage: {self.coverage.coverage_pct:.1f}% | "
            f"Bug Density: {self.bug_density.density:.3f} | "
            f"Context Cost: {self.context_cost.cost_per_finding:.0f} tok/finding | "
            f"Loop Rate: {self.loop_rate.loop_rate:.1%}"
        )


# ============================================================
# Metrics Collector
# ============================================================


class MetricsCollector:
    """
    Collects and computes evaluation metrics throughout the agent's run.

    Thread-safe for single-agent use. Computes metrics incrementally
    to avoid recomputing from scratch on each query.
    """

    def __init__(self, run_id: str = ""):
        self.run_id = run_id or f"metrics-{int(time.time())}"
        self.start_time = time.time()

        # Raw data stores
        self._exploration_units: dict[str, ExplorationUnit] = {}  # keyed by unit.key()
        self._findings: list[Finding] = []
        self._action_records: list[ActionRecord] = []
        self._token_usage: list[dict] = []  # {"phase": str, "tokens": int, "timestamp": float}

        # Counters
        self._total_tokens = 0
        self._flags_count = 0
        self._command_hashes: dict[str, int] = defaultdict(int)  # command_hash → count
        self._action_index = 0

    # ============================================================
    # Recording Methods
    # ============================================================

    def record_exploration(self, unit_type: str, identifier: str,
                           target: str = "", phase: str = "", tool: str = "") -> bool:
        """Record an exploration unit. Returns True if it's new."""
        unit = ExplorationUnit(
            unit_type=unit_type,
            identifier=identifier,
            target=target,
            phase=phase,
            tool=tool,
        )
        key = unit.key()
        if key in self._exploration_units:
            self._exploration_units[key].is_new = False
            return False
        self._exploration_units[key] = unit
        return True

    def record_finding(self, finding_type: str, category: str,
                       target: str = "", severity: str = "medium",
                       description: str = "", tokens: int = 0):
        """Record a vulnerability or useful discovery."""
        self._action_index += 1
        finding = Finding(
            finding_type=finding_type,
            category=category,
            target=target,
            severity=severity,
            description=description,
            action_index=self._action_index,
            tokens_consumed=tokens,
        )
        self._findings.append(finding)

        if finding_type == "flag":
            self._flags_count += 1

    def record_action(self, tool: str, command: str, target: str = "",
                      phase: str = "", produced_new_info: bool = False,
                      tokens: int = 0):
        """Record an agent action for loop detection and cost tracking."""
        self._action_index += 1
        cmd_hash = hashlib.md5(command.encode()).hexdigest()[:12]

        record = ActionRecord(
            action_index=self._action_index,
            tool=tool,
            command_hash=cmd_hash,
            target=target,
            phase=phase,
            produced_new_info=produced_new_info,
        )
        self._action_records.append(record)
        self._command_hashes[cmd_hash] += 1

        # Track token usage
        self._total_tokens += tokens
        if tokens > 0:
            self._token_usage.append({
                "phase": phase,
                "tokens": tokens,
                "timestamp": time.time(),
            })

    def record_tokens(self, tokens: int, phase: str = ""):
        """Record token consumption."""
        self._total_tokens += tokens
        if tokens > 0:
            self._token_usage.append({
                "phase": phase,
                "tokens": tokens,
                "timestamp": time.time(),
            })

    # ============================================================
    # Metric Computation
    # ============================================================

    def compute_coverage(self) -> CoverageMetric:
        """Compute meaningful coverage metric."""
        units = list(self._exploration_units.values())
        by_type: dict[str, int] = defaultdict(int)
        by_target: dict[str, int] = defaultdict(int)

        for u in units:
            by_type[u.unit_type] += 1
            by_target[u.target] += 1

        # Estimate surface area based on discovered units
        # Heuristic: assume we've explored ~30-50% when we stop finding new things
        total = len(units)
        new_count = sum(1 for u in units if u.is_new)
        # Coverage is new units as a fraction of estimated total
        # Use a heuristic: if we're still finding new things rapidly, surface is larger
        if total == 0:
            coverage_pct = 0.0
            estimated_surface = 0
        elif new_count == total:
            # Still finding all new things — surface is at least 2x what we've seen
            estimated_surface = total * 2
            coverage_pct = 50.0
        else:
            # Some repeats — estimate surface from discovery rate
            repeat_ratio = 1 - (new_count / total)
            estimated_surface = max(total, int(total / max(1 - repeat_ratio, 0.1)))
            coverage_pct = min(100.0, (total / max(estimated_surface, 1)) * 100)

        return CoverageMetric(
            total_units_discovered=total,
            unique_units=total,
            by_type=dict(by_type),
            by_target=dict(by_target),
            coverage_pct=round(coverage_pct, 1),
            estimated_surface=estimated_surface,
        )

    def compute_bug_density(self) -> BugDensityMetric:
        """Compute bug density metric."""
        exploration_count = len(self._exploration_units)
        findings = self._findings

        by_severity: dict[str, int] = defaultdict(int)
        by_category: dict[str, int] = defaultdict(int)
        by_target: dict[str, int] = defaultdict(int)

        # Only count actual vulnerabilities and flags
        vuln_findings = [f for f in findings if f.finding_type in ("vulnerability", "flag")]

        for f in vuln_findings:
            by_severity[f.severity] += 1
            by_category[f.category] += 1
            by_target[f.target] += 1

        density = len(vuln_findings) / max(exploration_count, 1)

        return BugDensityMetric(
            total_findings=len(vuln_findings),
            total_exploration_units=exploration_count,
            density=round(density, 4),
            by_severity=dict(by_severity),
            by_category=dict(by_category),
            by_target=dict(by_target),
        )

    def compute_context_cost(self) -> ContextCostMetric:
        """Compute context cost metric."""
        # Useful findings = flags + vulnerabilities
        useful = [f for f in self._findings if f.finding_type in ("flag", "vulnerability")]
        useful_count = len(useful)
        flag_count = sum(1 for f in self._findings if f.finding_type == "flag")

        cost_per_finding = self._total_tokens / max(useful_count, 1)
        cost_per_flag = self._total_tokens / max(flag_count, 1) if flag_count > 0 else 0.0

        # Tokens by phase
        by_phase: dict[str, int] = defaultdict(int)
        for entry in self._token_usage:
            by_phase[entry["phase"]] += entry["tokens"]

        return ContextCostMetric(
            total_tokens=self._total_tokens,
            useful_findings=useful_count,
            cost_per_finding=round(cost_per_finding, 0),
            cost_per_flag=round(cost_per_flag, 0),
            by_phase=dict(by_phase),
        )

    def compute_loop_rate(self) -> LoopRateMetric:
        """Compute loop rate metric."""
        total = len(self._action_records)
        if total == 0:
            return LoopRateMetric()

        # Count repeated actions (same command hash appearing more than once)
        repeated = 0
        phase_totals: dict[str, int] = defaultdict(int)
        phase_repeats: dict[str, int] = defaultdict(int)

        for record in self._action_records:
            phase_totals[record.phase] += 1
            if self._command_hashes[record.command_hash] > 1:
                repeated += 1
                phase_repeats[record.phase] += 1

        loop_rate = repeated / total

        # Phase-specific loop rates
        phase_loop_rates = {}
        for phase, count in phase_totals.items():
            phase_loop_rates[phase] = round(phase_repeats.get(phase, 0) / max(count, 1), 3)

        # Top repeated commands
        top_repeated = []
        for cmd_hash, count in sorted(self._command_hashes.items(), key=lambda x: -x[1]):
            if count > 1:
                # Find the command for this hash
                for record in self._action_records:
                    if record.command_hash == cmd_hash:
                        top_repeated.append({
                            "tool": record.tool,
                            "command_hash": cmd_hash,
                            "count": count,
                            "phase": record.phase,
                        })
                        break
            if len(top_repeated) >= 5:
                break

        return LoopRateMetric(
            total_actions=total,
            repeated_actions=repeated,
            loop_rate=round(loop_rate, 4),
            repeated_commands=top_repeated,
            phase_loop_rates=phase_loop_rates,
        )

    def snapshot(self) -> MetricsSnapshot:
        """Compute a complete metrics snapshot."""
        return MetricsSnapshot(
            run_id=self.run_id,
            coverage=self.compute_coverage(),
            bug_density=self.compute_bug_density(),
            context_cost=self.compute_context_cost(),
            loop_rate=self.compute_loop_rate(),
        )

    # ============================================================
    # Reporting
    # ============================================================

    def to_json(self) -> str:
        """Serialize full metrics to JSON."""
        return json.dumps(self.snapshot().to_dict(), indent=2, default=str)

    def summary(self) -> str:
        """One-line summary."""
        return self.snapshot().summary_string()

    def detailed_report(self) -> str:
        """Human-readable detailed metrics report."""
        snap = self.snapshot()
        lines = [
            "# 📊 Ozz Metrics Report",
            f"\n**Run ID:** {snap.run_id}",
            f"**Duration:** {time.time() - self.start_time:.1f}s",
            "",
            "## Coverage",
            f"- Units discovered: {snap.coverage.total_units_discovered}",
            f"- Unique units: {snap.coverage.unique_units}",
            f"- Coverage: {snap.coverage.coverage_pct:.1f}%",
            f"- Estimated surface: {snap.coverage.estimated_surface}",
            f"- By type: {json.dumps(snap.coverage.by_type)}",
            "",
            "## Bug Density",
            f"- Findings: {snap.bug_density.total_findings}",
            f"- Density: {snap.bug_density.density:.4f} findings/unit",
            f"- By severity: {json.dumps(snap.bug_density.by_severity)}",
            f"- By category: {json.dumps(snap.bug_density.by_category)}",
            "",
            "## Context Cost",
            f"- Total tokens: {snap.context_cost.total_tokens:,}",
            f"- Useful findings: {snap.context_cost.useful_findings}",
            f"- Cost per finding: {snap.context_cost.cost_per_finding:,.0f} tokens",
            f"- Cost per flag: {snap.context_cost.cost_per_flag:,.0f} tokens",
            f"- By phase: {json.dumps(snap.context_cost.by_phase)}",
            "",
            "## Loop Rate",
            f"- Total actions: {snap.loop_rate.total_actions}",
            f"- Repeated actions: {snap.loop_rate.repeated_actions}",
            f"- Loop rate: {snap.loop_rate.loop_rate:.1%} (target: <5%)",
            f"- Phase rates: {json.dumps(snap.loop_rate.phase_loop_rates)}",
        ]

        if snap.loop_rate.repeated_commands:
            lines.append("\n### Top Repeated Commands")
            for cmd in snap.loop_rate.repeated_commands:
                lines.append(f"  - [{cmd['tool']}] hash={cmd['command_hash']} × {cmd['count']}")

        lines.append(f"\n---\n*Metrics computed at {time.strftime('%Y-%m-%d %H:%M:%S')}*")
        return "\n".join(lines)


# ============================================================
# Integration Helper
# ============================================================


class MetricsIntegration:
    """
    Integrates metrics collection with the agent's ReAct loop.
    Provides convenience methods for recording from core.py.
    """

    def __init__(self, run_id: str = ""):
        self.collector = MetricsCollector(run_id)

    def on_tool_call(self, tool: str, command: str, target: str = "",
                     phase: str = "", output: str = "",
                     success: bool = False, tokens: int = 0):
        """Record a tool call and extract exploration units."""
        # Extract exploration units from output
        new_info = False
        if success and output:
            new_info = self._extract_exploration(tool, output, target, phase)

        self.collector.record_action(
            tool=tool,
            command=command,
            target=target,
            phase=phase,
            produced_new_info=new_info,
            tokens=tokens,
        )
        return new_info

    def on_finding(self, finding_type: str, category: str, target: str = "",
                   severity: str = "medium", description: str = ""):
        """Record a finding."""
        self.collector.record_finding(
            finding_type=finding_type,
            category=category,
            target=target,
            severity=severity,
            description=description,
        )

    def on_flag(self, flag: str, target: str = ""):
        """Record a flag capture."""
        self.collector.record_finding(
            finding_type="flag",
            category="flag",
            target=target,
            severity="critical",
            description=f"Flag captured: {flag}",
        )

    def on_tokens(self, tokens: int, phase: str = ""):
        """Record token consumption."""
        self.collector.record_tokens(tokens, phase)

    def get_snapshot(self) -> MetricsSnapshot:
        """Get current metrics snapshot."""
        return self.collector.snapshot()

    def get_summary(self) -> str:
        """Get one-line summary."""
        return self.collector.summary()

    def save_report(self, filepath: str = ""):
        """Save detailed report."""
        if not filepath:
            filepath = f"reports/{self.collector.run_id}_metrics.md"
        from pathlib import Path
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            f.write(self.collector.detailed_report())

    def _extract_exploration(self, tool: str, output: str,
                              target: str, phase: str) -> bool:
        """Extract exploration units from tool output. Returns True if new info found."""
        new = False

        # Extract ports from nmap
        if tool == "nmap":
            import re
            for m in re.finditer(r'(\d+)/(tcp|udp)\s+open\s+(\S+)', output):
                port_id = f"{m.group(1)}/{m.group(2)}"
                if self.collector.record_exploration("port", port_id, target, phase, tool):
                    new = True

        # Extract endpoints from gobuster/ffuf
        elif tool in ("gobuster", "ffuf"):
            import re
            for m in re.finditer(r'(/\S+)\s+\(Status:\s*(\d+)\)', output):
                if self.collector.record_exploration("endpoint", m.group(1), target, phase, tool):
                    new = True

        # Extract technologies from whatweb
        elif tool == "whatweb":
            import re
            for m in re.finditer(r'\[(\w[\w\s.-]+)\]', output):
                if self.collector.record_exploration("technology", m.group(1).strip(), target, phase, tool):
                    new = True

        # Extract URLs from curl
        elif tool == "curl":
            import re
            urls = re.findall(r'https?://[^\s\'"<>]+', output)
            for url in urls:
                if self.collector.record_exploration("endpoint", url, target, phase, tool):
                    new = True

        # Generic: mark as new if output has substantial content
        if not new and len(output) > 100:
            new = True

        return new
