"""
Ozz — Auto-Documentation Module
Generates real-time structured documentation of all agent actions.

Inspired by DEF CON 34 AI Village poster:
"Beyond CTFs: Engineering AI Agents for Real-World Web Pentesting" (BugBase)

Features:
- Every tool call logged with parameters and outcome
- Successful exploits documented with reproduction steps
- Failed attempts analyzed with failure reasons
- Complete attack chain reconstruction
- Structured JSON report + human-readable Markdown
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from pathlib import Path

logger = logging.getLogger("ozz.reports")


# ============================================================
# Data Structures
# ============================================================


@dataclass
class ActionEntry:
    """A single documented action."""
    sequence: int
    timestamp: float
    phase: str  # recon, enum, exploit, post_exploit
    tool: str
    command: str
    parameters: dict[str, Any] = field(default_factory=dict)
    output_summary: str = ""
    output_full: str = ""
    success: bool = False
    duration_s: float = 0.0
    error: Optional[str] = None
    flags_found: list[str] = field(default_factory=list)
    findings: dict[str, Any] = field(default_factory=dict)
    iteration: int = 0
    target: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        # Truncate output for JSON
        if len(d.get("output_full", "")) > 2000:
            d["output_full"] = d["output_full"][:2000] + f"... [{len(self.output_full)} chars]"
        return d


@dataclass
class ExploitEntry:
    """A successful exploit with reproduction steps."""
    name: str
    vulnerability: str
    target: str
    timestamp: float
    payload: str = ""
    steps: list[str] = field(default_factory=list)
    evidence: str = ""
    flags: list[str] = field(default_factory=list)
    action_indices: list[int] = field(default_factory=list)  # References to ActionEntry sequence numbers


@dataclass
class FailureEntry:
    """A failed attempt with analysis."""
    tool: str
    command: str
    target: str
    timestamp: float
    error: str = ""
    failure_reason: str = ""
    suggestion: str = ""
    action_index: int = 0


@dataclass
class AttackChain:
    """Complete attack chain from recon to flag."""
    target: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    total_duration_s: float = 0.0
    flags_captured: list[str] = field(default_factory=list)


@dataclass
class ReportSummary:
    """Summary statistics for the report."""
    run_id: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    total_duration_s: float = 0.0
    total_actions: int = 0
    successful_actions: int = 0
    failed_actions: int = 0
    flags_found: int = 0
    flags_submitted: int = 0
    exploits: int = 0
    targets_processed: int = 0
    phases_completed: list[str] = field(default_factory=list)
    tools_used: dict[str, int] = field(default_factory=dict)
    loop_detections: int = 0
    circuit_breaks: int = 0


# ============================================================
# Report Builder
# ============================================================


class ActionReportBuilder:
    """
    Real-time documentation builder.

    Accumulates actions, exploits, and failures throughout the agent's run.
    Produces structured JSON and human-readable Markdown reports.
    """

    def __init__(self, run_id: str = "", output_dir: str = "reports"):
        self.run_id = run_id or f"run-{int(time.time())}"
        self.output_dir = output_dir
        self.start_time = time.time()
        self.end_time = 0.0

        # Accumulators
        self.actions: list[ActionEntry] = []
        self.exploits: list[ExploitEntry] = []
        self.failures: list[FailureEntry] = []
        self.attack_chains: dict[str, AttackChain] = {}  # keyed by target
        self._sequence = 0
        self._tool_counts: dict[str, int] = {}
        self._phase_history: list[str] = []
        self._current_phase: str = "idle"
        self._current_target: str = ""

    def log_action(self, tool: str, command: str, parameters: dict = None,
                   output: str = "", success: bool = False, duration_s: float = 0.0,
                   error: str = None, flags: list[str] = None,
                   findings: dict = None, phase: str = "", target: str = "",
                   iteration: int = 0) -> ActionEntry:
        """Log a tool action with full details."""
        self._sequence += 1

        entry = ActionEntry(
            sequence=self._sequence,
            timestamp=time.time(),
            phase=phase or self._current_phase,
            tool=tool,
            command=command,
            parameters=parameters or {},
            output_summary=output[:500] if output else "",
            output_full=output,
            success=success,
            duration_s=duration_s,
            error=error,
            flags_found=flags or [],
            findings=findings or {},
            iteration=iteration,
            target=target or self._current_target,
        )
        self.actions.append(entry)

        # Track tool usage
        self._tool_counts[tool] = self._tool_counts.get(tool, 0) + 1

        # Log successful exploits
        if success and findings and findings.get("vulnerabilities"):
            self._record_exploit(entry, findings)

        # Log failures
        if not success and error:
            self._record_failure(entry)

        # Update attack chain
        target_key = target or self._current_target
        if target_key:
            chain = self._get_or_create_chain(target_key)
            chain.steps.append({
                "sequence": entry.sequence,
                "phase": entry.phase,
                "tool": tool,
                "command": command[:200],
                "success": success,
                "flags": flags or [],
                "timestamp": entry.timestamp,
            })
            if flags:
                chain.flags_captured.extend(flags)

        logger.debug(f"Report: logged action #{entry.sequence} [{tool}] {'✅' if success else '❌'}")
        return entry

    def set_phase(self, phase: str):
        """Update the current phase."""
        if phase != self._current_phase:
            self._current_phase = phase
            if phase not in self._phase_history:
                self._phase_history.append(phase)

    def set_target(self, target: str):
        """Update the current target."""
        self._current_target = target

    def _record_exploit(self, entry: ActionEntry, findings: dict):
        """Record a successful exploit."""
        vulns = findings.get("vulnerabilities", [])
        for vuln in vulns:
            exploit = ExploitEntry(
                name=f"{vuln} on {entry.target}",
                vulnerability=vuln,
                target=entry.target,
                timestamp=entry.timestamp,
                payload=entry.command,
                steps=[
                    f"[{entry.phase}] {entry.command}",
                    f"Output: {entry.output_summary[:200]}",
                ],
                evidence=entry.output_summary[:500],
                flags=entry.flags_found,
                action_indices=[entry.sequence],
            )
            self.exploits.append(exploit)

    def _record_failure(self, entry: ActionEntry):
        """Record a failed attempt with analysis."""
        # Analyze failure reason
        error = entry.error or ""
        reason = "unknown"
        suggestion = ""

        if "timeout" in error.lower():
            reason = "timeout"
            suggestion = "Increase timeout or use faster scan options"
        elif "not found" in error.lower() or "404" in error:
            reason = "target_not_found"
            suggestion = "Verify target URL/IP and port"
        elif "connection refused" in error.lower():
            reason = "connection_refused"
            suggestion = "Target service may not be running on this port"
        elif "permission" in error.lower() or "403" in error:
            reason = "permission_denied"
            suggestion = "Try different credentials or escalate privileges"
        elif "syntax" in error.lower():
            reason = "command_syntax"
            suggestion = "Check command syntax and arguments"
        elif "binary" in error.lower() or "not found" in error.lower():
            reason = "tool_not_available"
            suggestion = "Install the required tool or use alternative"
        else:
            reason = "execution_error"

        failure = FailureEntry(
            tool=entry.tool,
            command=entry.command,
            target=entry.target,
            timestamp=entry.timestamp,
            error=error[:500],
            failure_reason=reason,
            suggestion=suggestion,
            action_index=entry.sequence,
        )
        self.failures.append(failure)

    def _get_or_create_chain(self, target: str) -> AttackChain:
        """Get or create an attack chain for a target."""
        if target not in self.attack_chains:
            self.attack_chains[target] = AttackChain(target=target)
        return self.attack_chains[target]

    def finish(self):
        """Mark the report as complete."""
        self.end_time = time.time()

    # ============================================================
    # JSON Report Generation
    # ============================================================

    def build_json_report(self) -> dict:
        """Build the full structured JSON report."""
        self.finish()
        duration = self.end_time - self.start_time

        summary = ReportSummary(
            run_id=self.run_id,
            start_time=self.start_time,
            end_time=self.end_time,
            total_duration_s=round(duration, 2),
            total_actions=len(self.actions),
            successful_actions=sum(1 for a in self.actions if a.success),
            failed_actions=sum(1 for a in self.actions if not a.success),
            flags_found=sum(len(a.flags_found) for a in self.actions),
            exploits=len(self.exploits),
            targets_processed=len(self.attack_chains),
            phases_completed=self._phase_history,
            tools_used=self._tool_counts,
        )

        report = {
            "meta": {
                "run_id": self.run_id,
                "agent": "Ozz",
                "version": "0.2.0",
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            },
            "summary": asdict(summary),
            "actions": [a.to_dict() for a in self.actions],
            "exploits": [asdict(e) for e in self.exploits],
            "failures": [asdict(f) for f in self.failures],
            "attack_chains": {
                target: {
                    "target": chain.target,
                    "steps": chain.steps,
                    "total_duration_s": round(chain.total_duration_s, 2),
                    "flags_captured": chain.flags_captured,
                }
                for target, chain in self.attack_chains.items()
            },
            "flags": list(set(
                flag for a in self.actions for flag in a.flags_found
            )),
        }
        return report

    def save_json(self, filepath: Optional[str] = None) -> str:
        """Save JSON report to file."""
        report = self.build_json_report()
        if filepath is None:
            filepath = os.path.join(self.output_dir, f"{self.run_id}_report.json")
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)
        logger.info(f"JSON report saved: {filepath}")
        return filepath

    # ============================================================
    # Markdown Report Generation
    # ============================================================

    def build_markdown_report(self) -> str:
        """Build human-readable Markdown report."""
        self.finish()
        duration = self.end_time - self.start_time

        lines = []
        lines.append(f"# 🏴 Ozz Pentest Report — {self.run_id}")
        lines.append(f"\n**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Duration:** {duration:.1f}s ({duration/60:.1f}m)")

        # Summary
        successful = sum(1 for a in self.actions if a.success)
        failed = sum(1 for a in self.actions if not a.success)
        flags = list(set(flag for a in self.actions for flag in a.flags_found))

        lines.append(f"\n## Summary\n")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total Actions | {len(self.actions)} |")
        lines.append(f"| Successful | {successful} ✅ |")
        lines.append(f"| Failed | {failed} ❌ |")
        lines.append(f"| Success Rate | {successful/max(len(self.actions),1)*100:.0f}% |")
        lines.append(f"| Exploits Found | {len(self.exploits)} |")
        lines.append(f"| Flags Captured | {len(flags)} 🚩 |")
        lines.append(f"| Targets Processed | {len(self.attack_chains)} |")
        lines.append(f"| Phases Completed | {', '.join(self._phase_history)} |")

        # Flags
        if flags:
            lines.append(f"\n## 🚩 Flags Captured\n")
            for flag in flags:
                lines.append(f"- `{flag}`")

        # Exploits
        if self.exploits:
            lines.append(f"\n## 💥 Successful Exploits\n")
            for i, exploit in enumerate(self.exploits, 1):
                lines.append(f"### {i}. {exploit.name}\n")
                lines.append(f"- **Vulnerability:** {exploit.vulnerability}")
                lines.append(f"- **Target:** {exploit.target}")
                lines.append(f"- **Payload:** `{exploit.payload[:200]}`")
                if exploit.flags:
                    lines.append(f"- **Flags:** {', '.join(f'`{f}`' for f in exploit.flags)}")
                lines.append(f"\n**Reproduction Steps:**")
                for j, step in enumerate(exploit.steps, 1):
                    lines.append(f"{j}. {step}")
                if exploit.evidence:
                    lines.append(f"\n**Evidence:**\n```\n{exploit.evidence[:500]}\n```")
                lines.append("")

        # Attack Chains
        if self.attack_chains:
            lines.append(f"\n## 🔗 Attack Chains\n")
            for target, chain in self.attack_chains.items():
                lines.append(f"### Target: {target}\n")
                lines.append(f"| # | Phase | Tool | Command | Result |")
                lines.append(f"|---|-------|------|---------|--------|")
                for step in chain.steps:
                    status = "✅" if step.get("success") else "❌"
                    cmd = step.get("command", "")[:60]
                    lines.append(f"| {step.get('sequence', '?')} | {step.get('phase', '?')} | {step.get('tool', '?')} | `{cmd}` | {status} |")
                if chain.flags_captured:
                    lines.append(f"\n**Flags:** {', '.join(f'`{f}`' for f in chain.flags_captured)}")
                lines.append("")

        # Failed Attempts Analysis
        if self.failures:
            lines.append(f"\n## ❌ Failed Attempts ({len(self.failures)})\n")
            # Group by failure reason
            by_reason: dict[str, list[FailureEntry]] = {}
            for f in self.failures:
                by_reason.setdefault(f.failure_reason, []).append(f)

            for reason, entries in by_reason.items():
                lines.append(f"### {reason.replace('_', ' ').title()} ({len(entries)} occurrences)\n")
                if entries:
                    lines.append(f"**Suggestion:** {entries[0].suggestion}\n")
                for entry in entries[:3]:  # Show top 3
                    lines.append(f"- `{entry.tool} {entry.command[:100]}` → {entry.error[:100]}")
                if len(entries) > 3:
                    lines.append(f"- ... and {len(entries) - 3} more")
                lines.append("")

        # Tool Usage
        lines.append(f"\n## 🔧 Tool Usage\n")
        lines.append(f"| Tool | Calls |")
        lines.append(f"|------|-------|")
        for tool, count in sorted(self._tool_counts.items(), key=lambda x: -x[1]):
            lines.append(f"| {tool} | {count} |")

        # Action Timeline (abbreviated)
        lines.append(f"\n## 📋 Action Timeline (last 20)\n")
        for action in self.actions[-20:]:
            status = "✅" if action.success else "❌"
            cmd = action.command[:80]
            lines.append(f"- `{action.phase}` [{action.tool}] `{cmd}` {status}")

        lines.append(f"\n---\n*Report generated by Ozz Autonomous Pentesting Agent*")
        return "\n".join(lines)

    def save_markdown(self, filepath: Optional[str] = None) -> str:
        """Save Markdown report to file."""
        report = self.build_markdown_report()
        if filepath is None:
            filepath = os.path.join(self.output_dir, f"{self.run_id}_report.md")
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            f.write(report)
        logger.info(f"Markdown report saved: {filepath}")
        return filepath

    # ============================================================
    # Quick Access Methods
    # ============================================================

    def get_attack_chain_summary(self) -> str:
        """Get a quick summary of attack chains for the LLM context."""
        if not self.attack_chains:
            return "No attack chains recorded yet."

        lines = []
        for target, chain in self.attack_chains.items():
            successful_steps = sum(1 for s in chain.steps if s.get("success"))
            total_steps = len(chain.steps)
            lines.append(
                f"Target {target}: {successful_steps}/{total_steps} successful steps, "
                f"{len(chain.flags_captured)} flags"
            )
        return "\n".join(lines)

    def get_exploit_summary(self) -> str:
        """Get a quick summary of exploits for the LLM context."""
        if not self.exploits:
            return "No exploits recorded yet."

        lines = []
        for e in self.exploits:
            lines.append(f"- {e.vulnerability} on {e.target}: {e.name}")
            if e.flags:
                lines.append(f"  Flags: {', '.join(e.flags)}")
        return "\n".join(lines)

    def get_failure_analysis(self) -> str:
        """Get failure analysis for the LLM context."""
        if not self.failures:
            return "No failures recorded."

        by_reason: dict[str, int] = {}
        for f in self.failures:
            by_reason[f.failure_reason] = by_reason.get(f.failure_reason, 0) + 1

        lines = ["Failure breakdown:"]
        for reason, count in sorted(by_reason.items(), key=lambda x: -x[1]):
            lines.append(f"  - {reason}: {count}")
        return "\n".join(lines)

    def to_json(self) -> str:
        """Quick JSON serialization."""
        return json.dumps(self.build_json_report(), default=str, ensure_ascii=False)
