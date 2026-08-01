"""
Ozz — HALctf Autonomous Pentesting Agent
Core ReAct agent loop — Competition Grade.

Design principles:
  - ALL decisions via LLM. Zero hardcoded decision logic.
  - Few-shot calibrated for CTF patterns.
  - Circuit breaker + exponential backoff.
  - NEDK composable regulation layer.
  - Automatic flag extraction and scoreboard submission.
"""

import json
import os
import re
import time
import logging
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .llm import LLM
from .memory import Memory
from .tools import ToolRegistry, ToolResult
from .few_shot import get_few_shot_messages
from .context_engine import ContextEngine
from .reports import ActionReportBuilder
from .metrics import MetricsIntegration
from .provenance import ProvenanceTracker
from .audit import AuditLogger
from .contamination import ContaminationDetector
from .telemetry.monitor import TelemetryMonitor, PromptRisk
from .telemetry.sanitizer import TelemetrySanitizer
from .telemetry.evaluator import DeterministicEvaluator
from .telemetry.audit_trail import AuditTrail, AuditEventType

logger = logging.getLogger("ozz")


# ============================================================
# Configuration (all env-configurable, zero hardcoded decisions)
# ============================================================

def _env_int(key: str, default: int) -> int:
    return int(os.environ.get(key, str(default)))

def _env_float(key: str, default: float) -> float:
    return float(os.environ.get(key, str(default)))

def _env_str(key: str, default: str) -> str:
    return os.environ.get(key, default)


MAX_ITERATIONS = _env_int("OZZ_MAX_ITERATIONS", 200)
ACTION_DELAY_BASE = _env_float("OZZ_ACTION_DELAY", 0.5)
ACTION_DELAY_MAX = _env_float("OZZ_ACTION_DELAY_MAX", 30.0)
CIRCUIT_BREAKER_THRESHOLD = _env_int("OZZ_CIRCUIT_BREAKER", 15)
LOOP_DETECTION_WINDOW = _env_int("OZZ_LOOP_WINDOW", 5)
LOOP_DETECTION_THRESHOLD = _env_int("OZZ_LOOP_THRESHOLD", 3)
CONTEXT_HISTORY_DEPTH = _env_int("OZZ_CONTEXT_HISTORY", 8)
SCOREBOARD_URL = _env_str("SCOREBOARD_URL", "")
SCOREBOARD_AGENT_NAME = _env_str("SCOREBOARD_AGENT", "Ozz")


# ============================================================
# Flag Patterns (comprehensive CTF coverage)
# ============================================================

FLAG_PATTERNS = [
    r'flag\{[^}]+\}',
    r'CTF\{[^}]+\}',
    r'HALCTF\{[^}]+\}',
    r'DEFCON\{[^}]+\}',
    r'picoCTF\{[^}]+\}',
    r'HTB\{[^}]+\}',
    r'THM\{[^}]+\}',
    r'FLAG\{[^}]+\}',
    r'Flag\{[^}]+\}',
    r'[A-Za-z_]+\{[a-zA-Z0-9_\-!@#$%^&*()+=]{3,}\}',
]

# Pre-compile for performance
_FLAG_RE = re.compile('|'.join(FLAG_PATTERNS), re.IGNORECASE)


# ============================================================
# Data Structures
# ============================================================

class AgentState(Enum):
    IDLE = "idle"
    RECON = "recon"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    PIVOT = "pivot"
    DONE = "done"


@dataclass
class Observation:
    """A single observation from tool execution."""
    tool: str
    command: str
    output: str
    success: bool
    timestamp: float = field(default_factory=time.time)


@dataclass
class Plan:
    """Current agent plan."""
    objective: str
    steps: list[str] = field(default_factory=list)
    current_step: int = 0
    state: AgentState = AgentState.IDLE
    target: str = ""
    findings: dict = field(default_factory=dict)
    credentials: list = field(default_factory=list)
    flags_found: list = field(default_factory=list)


# ============================================================
# Prompts
# ============================================================

SYSTEM_PROMPT = """You are Ozz, an autonomous penetration testing agent competing in HALctf at DEF CON 34.

YOUR MISSION: Find and capture flags in CTF challenges. Flags typically follow formats like:
- flag{{...}}, CTF{{...}}, HALCTF{{...}}, picoCTF{{...}}, HTB{{...}}
- Or custom formats specified by the challenge

APPROACH (ReAct methodology):
1. RECON: Scan targets to discover services and technologies
2. ENUMERATION: Deep-dive into discovered services for vulnerabilities
3. EXPLOITATION: Use found vulnerabilities to gain access
4. POST_EXPLOIT: Search for flags in the compromised system
5. PIVOT: Use compromised systems to reach other targets

TOOLS AVAILABLE:
{tools_desc}

RESPONSE FORMAT:
You MUST respond with a single valid JSON object:
{{{{
  "thought": "Your reasoning about the current situation and what to do next",
  "action": "tool_name",
  "action_input": "input for the tool",
  "plan_update": "optional: update your plan/state"
}}}}

If you find a flag, respond with:
{{{{
  "thought": "Found a flag!",
  "action": "submit_flag",
  "action_input": "the_flag_value"
}}}}

CRITICAL RULES:
- Respond ONLY with valid JSON. No markdown fences, no explanation outside the JSON.
- Be creative. If one approach fails, try another.
- Use 'shell' for any command not explicitly listed as a tool.
- Always check for flags in every output — they can appear anywhere.
- If stuck for 3+ attempts, completely change your approach."""


def _build_phase_prompt(state: AgentState, target: str, findings: dict,
                        credentials: list, targets: list, target_idx: int) -> str:
    """Build phase-specific guidance. Content is derived from state, not hardcoded logic."""
    findings_str = json.dumps(findings, indent=2, default=str) if findings else "None yet"
    creds_str = json.dumps(credentials, indent=2) if credentials else "None found"

    phase_guidance = {
        AgentState.RECON: (
            f"You are in the RECON phase for target: {target}\n"
            f"Goal: Discover what services are running. Use nmap, quick_scan, whatweb.\n"
            f"Findings so far: {findings_str}"
        ),
        AgentState.ENUMERATION: (
            f"You are in the ENUMERATION phase for target: {target}\n"
            f"Goal: Deep-dive into discovered services. Find vulnerabilities.\n"
            f"Services found: {findings.get('services', 'None')}\n"
            f"Findings: {findings_str}"
        ),
        AgentState.EXPLOITATION: (
            f"You are in the EXPLOITATION phase for target: {target}\n"
            f"Goal: Exploit discovered vulnerabilities to gain access.\n"
            f"Vulnerabilities: {findings.get('vulnerabilities', 'None')}\n"
            f"Credentials: {creds_str}\n"
            f"Findings: {findings_str}"
        ),
        AgentState.POST_EXPLOIT: (
            f"You are in the POST_EXPLOIT phase for target: {target}\n"
            f"Goal: Search compromised system for flags, credentials, and pivot opportunities.\n"
            f"Credentials: {creds_str}\n"
            f"Findings: {findings_str}"
        ),
        AgentState.PIVOT: (
            f"You are in the PIVOT phase.\n"
            f"Goal: Use compromised systems to reach other targets.\n"
            f"Compromised: {findings.get('compromised', 'None')}\n"
            f"Networks: {findings.get('networks', 'None')}\n"
            f"Credentials: {creds_str}\n"
            f"All targets: {targets}"
        ),
        AgentState.IDLE: "Starting up. Begin with reconnaissance.",
        AgentState.DONE: "All objectives complete.",
    }
    return phase_guidance.get(state, "Continue with your current plan.")


# ============================================================
# Scoreboard Integration
# ============================================================

class ScoreboardClient:
    """Submits flags to the CTF scoreboard."""

    def __init__(self, url: str = SCOREBOARD_URL, agent_name: str = SCOREBOARD_AGENT_NAME):
        self.url = url.rstrip("/") if url else ""
        self.agent_name = agent_name
        self.submitted: list[str] = []

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    def submit(self, flag: str) -> dict:
        """Submit a flag to the scoreboard. Returns result dict."""
        if not self.url:
            logger.info(f"🚩 [NO SCOREBOARD] Flag stored locally: {flag}")
            return {"status": "local_only", "flag": flag}

        if flag in self.submitted:
            return {"status": "duplicate", "flag": flag}

        try:
            import requests
            resp = requests.post(
                f"{self.url}/submit",
                data={"flag": flag, "agent": self.agent_name},
                timeout=10,
            )
            result = {"status": "submitted", "flag": flag, "http_status": resp.status_code}
            if resp.status_code == 200:
                self.submitted.append(flag)
                logger.info(f"🚩 ✅ Flag submitted to scoreboard: {flag}")
            else:
                logger.warning(f"🚩 ⚠️ Scoreboard returned {resp.status_code}: {resp.text[:200]}")
            return result
        except Exception as e:
            logger.error(f"🚩 ❌ Scoreboard submission failed: {e}")
            return {"status": "error", "flag": flag, "error": str(e)}


# ============================================================
# OzzAgent — Competition-Grade ReAct Agent
# ============================================================

class OzzAgent:
    """Main autonomous pentesting agent.

    Architecture:
      ReAct loop: context → LLM → parse → validate → act → observe → remember
      MNHI 3.5 spaces composed via NEDK (optional)
      Circuit breaker prevents infinite loops
      Exponential backoff on repeated failures
    """

    def __init__(self, targets: list[str], model_path: str = "/models",
                 nedk=None, scoreboard_url: str = ""):
        self.targets = targets
        self.run_id = f"run-{int(time.time() * 1000)}"

        # ── Security modules (DEF CON 34 AI Village) ────────────────
        self.provenance = ProvenanceTracker(session_id=self.run_id)
        self.audit = AuditLogger(session_id=self.run_id)
        self.contamination = ContaminationDetector(session_id=self.run_id)

        # ── Telemetry & SOC Defense (Track D: DEF CON 34 Posters) ───
        self.telemetry_monitor = TelemetryMonitor(agent_id="ozz", run_id=self.run_id)
        self.telemetry_sanitizer = TelemetrySanitizer(strict=True)
        self.telemetry_evaluator = DeterministicEvaluator()
        self.audit_trail = AuditTrail(agent_id="ozz", run_id=self.run_id)
        self.audit_trail.log_session_event(AuditEventType.SESSION_START, {
            "targets": list(targets),
            "max_iterations": self.max_iterations,
        })

        # ── Track E: Red Team Methodology & Deception at Scale ─────
        from .deception import BifurcationEngine
        from .fingerprinting import BehavioralFingerprint
        from .self_test import ScaleTestPipeline
        self.bifurcation = BifurcationEngine()
        self.fingerprinter = BehavioralFingerprint()
        self.self_test = ScaleTestPipeline(validate_fn=self._selftest_validate)

        self.llm = LLM(model_path)
        self.memory = Memory(session_id=self.run_id)
        self.tools = ToolRegistry(
            allowed_targets=targets,
            audit_logger=self.audit,
            provenance_tracker=self.provenance,
            contamination_detector=self.contamination,
        )
        self.plan = Plan(objective="Find and capture all flags")
        self.history: list[Observation] = []
        self.max_iterations = MAX_ITERATIONS
        self.current_target_idx = 0
        self.nedk = nedk  # Optional NEDK composition

        # Scoreboard
        sb_url = scoreboard_url or SCOREBOARD_URL
        self.scoreboard = ScoreboardClient(url=sb_url)

        # Circuit breaker & backoff
        self._consecutive_failures = 0
        self._consecutive_same_action = 0
        self._last_action_sig: Optional[str] = None
        self._current_delay = ACTION_DELAY_BASE
        self._stuck_count = 0
        self._actions_without_new_info = 0

        # Loop detection
        self._action_signatures: list[str] = []

        # Run metrics
        self.run_metrics = {
            "run_id": self.run_id,
            "targets": list(targets),
            "iterations": 0,
            "flags_found": 0,
            "flags_submitted": 0,
            "loop_detected": 0,
            "circuit_breaks": 0,
            "phase_transitions": 0,
            "tool_failures": 0,
            "llm_fallbacks": 0,
            "new_info_actions": 0,
        }
        self._last_phase: Optional[AgentState] = None

        # Track A: Context Engineering, Auto-Documentation, Metrics
        self.context_engine = ContextEngine()
        self.report = ActionReportBuilder(run_id=self.run_id)
        self.metrics = MetricsIntegration(run_id=self.run_id)

    # ============================================================
    # MAIN LOOP
    # ============================================================

    def run(self):
        """Main agent loop — full ReAct cycle with phase-specific sub-loops."""
        logger.info(f"🏴 Ozz starting. Targets: {self.targets}")
        logger.info(f"   Scoreboard: {'enabled' if self.scoreboard.enabled else 'disabled (local only)'}")
        logger.info(f"   Max iterations: {self.max_iterations}")
        logger.info(f"   Circuit breaker: {CIRCUIT_BREAKER_THRESHOLD} consecutive failures")

        self.plan.state = AgentState.RECON
        self.plan.target = self.targets[0] if self.targets else ""
        self.report.set_target(self.plan.target)

        for i in range(self.max_iterations):
            self.run_metrics["iterations"] = i + 1
            self.telemetry_monitor.set_iteration(i + 1)

            if self.plan.state == AgentState.DONE:
                logger.info("🏁 Agent completed all objectives.")
                self.audit_trail.log_session_event(AuditEventType.SESSION_END, {
                    "flags_found": len(self.plan.flags_found),
                    "total_iterations": i + 1,
                })
                break

            # Circuit breaker check
            if self._consecutive_failures >= CIRCUIT_BREAKER_THRESHOLD:
                logger.error(f"🛑 Circuit breaker triggered after {self._consecutive_failures} consecutive failures.")
                self.run_metrics["circuit_breaks"] += 1
                if not self._try_circuit_breaker_recovery():
                    logger.error("🛑 Cannot recover. Stopping.")
                    break

            logger.info(f"\n{'='*60}")
            logger.info(f"Iteration {i+1}/{self.max_iterations} | State: {self.plan.state.value} | Target: {self.plan.target}")
            logger.info(f"  Consecutive failures: {self._consecutive_failures} | Delay: {self._current_delay:.1f}s")
            logger.info(f"{'='*60}")

            # Use phase-specific sub-loops for focused execution
            observation = self._run_sub_loop(i)

            if observation is None:
                continue

            # CHECK FLAGS
            new_flags = self._extract_flags(observation.output)
            for flag in new_flags:
                self._handle_flag(flag, observation)

            # UPDATE STATE
            self._update_state({}, observation)

            # LOOP DETECTION
            self.audit_trail.log_tool_result(
                observation.tool, observation.success, len(observation.output),
                0.0, iteration=i + 1
            )
            if self._detect_loop():
                self._break_loop()

            # Adaptive delay
            time.sleep(self._current_delay)
            self.memory.store_run_metrics(self.run_metrics, run_id=self.run_id)

        # Final report
        self.run_metrics["flags_found"] = len(self.plan.flags_found)
        self.run_metrics["flags_submitted"] = len(self.scoreboard.submitted)
        self.memory.store_run_metrics(self.run_metrics, run_id=self.run_id)

        # Telemetry final stats (Track D)
        self.audit_trail.log_session_event(AuditEventType.SESSION_END, {
            "flags_found": len(self.plan.flags_found),
            "total_iterations": self.run_metrics["iterations"],
            "telemetry_stats": self.telemetry_monitor.get_stats(),
            "sanitizer_stats": self.telemetry_sanitizer.get_stats(),
            "evaluator_stats": self.telemetry_evaluator.get_statistics(),
            "audit_stats": self.audit_trail.get_statistics(),
        })
        chain_valid, broken_at = self.audit_trail.verify_chain()
        logger.info(f"📋 Audit trail: {len(self.audit_trail._entries)} entries, chain valid={chain_valid}")
        self._finalize_reports()
        self._report()

    # ============================================================
    # SUB-LOOPS — Phase-Specific ReAct Loops
    # ============================================================

    def _run_sub_loop(self, global_iteration: int) -> Optional[Observation]:
        """Route to the appropriate phase-specific sub-loop."""
        self.report.set_phase(self.plan.state.value)
        self.report.set_target(self.plan.target)

        sub_loop_map = {
            AgentState.RECON: self._recon_loop,
            AgentState.ENUMERATION: self._enum_loop,
            AgentState.EXPLOITATION: self._exploit_loop,
            AgentState.POST_EXPLOIT: self._post_exploit_loop,
            AgentState.PIVOT: self._exploit_loop,
        }

        loop_fn = sub_loop_map.get(self.plan.state)
        if loop_fn is None:
            return self._generic_iteration(global_iteration)

        return loop_fn(global_iteration)

    def _recon_loop(self, global_iteration: int) -> Optional[Observation]:
        """
        Recon sub-loop: host discovery → service detection → technology fingerprinting.
        Max 20 iterations before forcing transition.
        """
        max_recon_iters = _env_int("OZZ_RECON_MAX_ITERS", 20)
        recon_iter = self.run_metrics.get("_recon_iters", 0)
        if recon_iter >= max_recon_iters:
            logger.info("📊 Recon iteration limit reached, transitioning to ENUMERATION")
            self.plan.state = AgentState.ENUMERATION
            self.run_metrics["_recon_iters"] = 0
            return None
        self.run_metrics["_recon_iters"] = recon_iter + 1

        recon_tools = "nmap, quick_scan, whatweb, curl, shell"
        recon_prompt = f"""RECON PHASE — Target: {self.plan.target}
Goal: Discover services, ports, and technologies.
Available tools: {recon_tools}
Findings so far: {json.dumps(self.plan.findings, default=str)[:500]}

What is your next recon action? Respond with JSON: {{"thought": "...", "action": "tool", "action_input": "..."}}"""

        return self._sub_loop_think_and_act(recon_prompt, global_iteration)

    def _enum_loop(self, global_iteration: int) -> Optional[Observation]:
        """
        Enumeration sub-loop: endpoint discovery → parameter fuzzing → vulnerability identification.
        Max 30 iterations before forcing transition.
        """
        max_enum_iters = _env_int("OZZ_ENUM_MAX_ITERS", 30)
        enum_iter = self.run_metrics.get("_enum_iters", 0)
        if enum_iter >= max_enum_iters:
            logger.info("📊 Enum iteration limit reached, transitioning to EXPLOITATION")
            self.plan.state = AgentState.EXPLOITATION
            self.run_metrics["_enum_iters"] = 0
            return None
        self.run_metrics["_enum_iters"] = enum_iter + 1

        enum_tools = "gobuster, ffuf, nikto, curl, sqlmap, shell"
        ctx_summary = self.context_engine.build_filtered_context(max_network=10, max_categories=3)

        enum_prompt = f"""ENUMERATION PHASE — Target: {self.plan.target}
Goal: Discover endpoints, parameters, and vulnerabilities.
Available tools: {enum_tools}
Services: {json.dumps(self.plan.findings.get('services', []), default=str)[:300]}
Filtered Context:
{ctx_summary[:600]}

What is your next enumeration action? Respond with JSON: {{"thought": "...", "action": "tool", "action_input": "..."}}"""

        return self._sub_loop_think_and_act(enum_prompt, global_iteration)

    def _exploit_loop(self, global_iteration: int) -> Optional[Observation]:
        """
        Exploit sub-loop: payload generation → execution → verification → flag extraction.
        Max 50 iterations.
        """
        max_exploit_iters = _env_int("OZZ_EXPLOIT_MAX_ITERS", 50)
        exploit_iter = self.run_metrics.get("_exploit_iters", 0)
        if exploit_iter >= max_exploit_iters:
            logger.info("📊 Exploit iteration limit reached")
            if self.plan.flags_found:
                self.plan.state = AgentState.POST_EXPLOIT
            self.run_metrics["_exploit_iters"] = 0
            return None
        self.run_metrics["_exploit_iters"] = exploit_iter + 1

        exploit_tools = "curl, sqlmap, python, shell, gobuster, ffuf"
        creds_summary = json.dumps(self.plan.credentials, default=str)[:300] if self.plan.credentials else "None"

        exploit_prompt = f"""EXPLOITATION PHASE — Target: {self.plan.target}
Goal: Exploit vulnerabilities to capture flags.
Available tools: {exploit_tools}
Vulnerabilities: {json.dumps(self.plan.findings.get('vulnerabilities', []), default=str)[:300]}
Credentials: {creds_summary}
Flags found: {self.plan.flags_found}

What is your next exploit action? Respond with JSON: {{"thought": "...", "action": "tool", "action_input": "..."}}"""

        return self._sub_loop_think_and_act(exploit_prompt, global_iteration)

    def _post_exploit_loop(self, global_iteration: int) -> Optional[Observation]:
        """
        Post-exploit sub-loop: privilege escalation → lateral movement → data exfiltration.
        Max 30 iterations.
        """
        max_post_iters = _env_int("OZZ_POST_EXPLOIT_MAX_ITERS", 30)
        post_iter = self.run_metrics.get("_post_iters", 0)
        if post_iter >= max_post_iters:
            logger.info("📊 Post-exploit iteration limit reached")
            if self.current_target_idx < len(self.targets) - 1:
                self.current_target_idx += 1
                self.plan.target = self.targets[self.current_target_idx]
                self.plan.state = AgentState.RECON
                self.report.set_target(self.plan.target)
            else:
                self.plan.state = AgentState.DONE
            self.run_metrics["_post_iters"] = 0
            return None
        self.run_metrics["_post_iters"] = post_iter + 1

        post_tools = "shell, python, ssh, curl, grep"

        post_prompt = f"""POST-EXPLOIT PHASE — Target: {self.plan.target}
Goal: Search for flags, escalate privileges, find pivot opportunities.
Available tools: {post_tools}
Credentials: {json.dumps(self.plan.credentials, default=str)[:300]}
Flags so far: {self.plan.flags_found}

What is your next post-exploit action? Respond with JSON: {{"thought": "...", "action": "tool", "action_input": "..."}}"""

        return self._sub_loop_think_and_act(post_prompt, global_iteration)

    def _sub_loop_think_and_act(self, prompt: str, global_iteration: int) -> Optional[Observation]:
        """Common sub-loop: think → validate → act → remember → metrics."""
        # 1. BUILD CONTEXT (with contamination check)
        context = prompt
        contam_events = self.contamination.check(context, source="sub_loop")
        if self.contamination.should_abort(contam_events):
            logger.warning(f"🛡️ Contamination in sub-loop prompt, skipping")
            self._consecutive_failures += 1
            return None

        # 2. TELEMETRY — Monitor prompt
        ctx_classification = self.telemetry_monitor.monitor_prompt(context, context="sub_loop")
        self.audit_trail.log_prompt(context, classification=ctx_classification.to_dict(),
                                    iteration=global_iteration + 1)

        # 3. THINK
        decision = self._think(context)
        if not decision:
            self._consecutive_failures += 1
            self._backoff()
            return None

        # 4. VALIDATE
        if not self._validate_decision(decision):
            logger.warning(f"Invalid decision: {decision}")
            self._consecutive_failures += 1
            return None

        # 5. ACT (with security pipeline)
        action_name = decision.get("action", "")
        action_input = str(decision.get("action_input", ""))
        tool_classification = self.telemetry_monitor.monitor_tool_call(action_name, action_input)
        self.audit_trail.log_tool_call(action_name, action_input,
                                       classification=tool_classification.to_dict(),
                                       iteration=global_iteration + 1)
        observation = self._act(decision, context=context)

        # 6. SANITIZE output
        if observation.output:
            sanitized = self.telemetry_sanitizer.sanitize_tool_output(observation.tool, observation.output)
            if sanitized.was_modified:
                observation.output = sanitized.sanitized
                self.audit_trail.log_sanitization("tool_output", True,
                                                   sanitized.threats_found, iteration=global_iteration + 1)

        # 7. REMEMBER
        self._remember(observation)

        # 8. REPORT
        self.report.log_action(
            tool=observation.tool,
            command=observation.command,
            output=observation.output[:500] if observation.output else "",
            success=observation.success,
            duration_s=0.0,
            flags=self._extract_flags(observation.output),
            findings=self.plan.findings.copy() if observation.success else {},
            phase=self.plan.state.value,
            target=self.plan.target,
            iteration=global_iteration + 1,
        )

        # 9. METRICS
        self.metrics.on_tool_call(
            tool=observation.tool,
            command=observation.command,
            target=self.plan.target,
            phase=self.plan.state.value,
            output=observation.output or "",
            success=observation.success,
        )

        # 10. CONTEXT ENGINE
        if observation.success and observation.output:
            self._process_output_for_context(observation)

        # 11. TRACK EFFECTIVENESS
        self._track_effectiveness(decision, observation)

        return observation

    def _generic_iteration(self, global_iteration: int) -> Optional[Observation]:
        """Fallback generic iteration when no sub-loop matches."""
        context = self._build_context()
        decision = self._think(context)
        if not decision:
            self._consecutive_failures += 1
            self._backoff()
            return None
        if not self._validate_decision(decision):
            self._consecutive_failures += 1
            return None
        observation = self._act(decision)
        self._remember(observation)
        self._update_state(decision, observation)
        self._track_effectiveness(decision, observation)
        return observation

    def _process_output_for_context(self, obs: Observation):
        """Feed tool output into context engine for structured extraction."""
        output = obs.output or ""
        if '<html' in output.lower() or '<body' in output.lower():
            self.context_engine.process_page(output, self.plan.target)
        if obs.tool == 'curl' and ('HTTP/' in output or 'content-type:' in output.lower()):
            status_match = re.search(r'HTTP/[\d.]+\s+(\d{3})', output)
            status = int(status_match.group(1)) if status_match else 0
            self.context_engine.process_request('GET', self.plan.target, status_code=status)

    def _finalize_reports(self):
        """Save all reports at end of run."""
        try:
            self.report.finish()
            json_path = self.report.save_json()
            md_path = self.report.save_markdown()
            logger.info(f"📝 Reports saved: {json_path}, {md_path}")
        except Exception as e:
            logger.error(f"Report generation failed: {e}")

        try:
            self.metrics.save_report()
            logger.info(f"📊 Metrics: {self.metrics.get_summary()}")
        except Exception as e:
            logger.error(f"Metrics report failed: {e}")

    # ============================================================
    # CONTEXT BUILDING
    # ============================================================

    def _build_context(self) -> str:
        """Build the full context for the LLM. No hardcoded logic — pure state."""
        tools_desc = self.tools.describe_all()
        findings = json.dumps(self.plan.findings, indent=2, default=str) if self.plan.findings else "{}"

        # Recent history (configurable depth)
        recent = self.history[-CONTEXT_HISTORY_DEPTH:] if self.history else []
        history_lines = []
        for o in recent:
            status = "SUCCESS" if o.success else "FAILED"
            output_preview = o.output[:600] if o.output else "<no output>"
            history_lines.append(f"[{o.tool}] {o.command}\n  {status}: {output_preview}")
        history_text = "\n".join(history_lines) if history_lines else "No actions yet."

        # Phase prompt
        phase_prompt = _build_phase_prompt(
            self.plan.state, self.plan.target, self.plan.findings,
            self.plan.credentials, self.targets, self.current_target_idx
        )

        # System prompt with tools
        system = SYSTEM_PROMPT.replace("{tools_desc}", tools_desc)

        # Credentials summary
        creds_summary = []
        for cred in self.plan.credentials:
            if isinstance(cred, dict):
                u = cred.get("username", "")
                p = cred.get("password", "")
                creds_summary.append(f"{u}:{p}" if u or p else "<empty>")
            else:
                creds_summary.append(str(cred))

        # Prior run context
        prior_context = self._format_prior_context()

        # Action effectiveness context
        effectiveness_context = self._format_effectiveness_context()

        return f"""{system}

=== CURRENT PHASE ===
{phase_prompt}

=== RECENT ACTIONS (last {len(recent)}) ===
{history_text}

=== DISCOVERED FINDINGS ===
{findings}

=== KNOWN CREDENTIALS ===
{', '.join(creds_summary) if creds_summary else 'None'}

=== FLAGS FOUND SO FAR ===
{self.plan.flags_found if self.plan.flags_found else 'None yet'}

=== TARGETS REMAINING ===
{self.targets[self.current_target_idx:]}

=== PRIOR RUN INSIGHTS ===
{prior_context}

=== ACTION EFFECTIVENESS ===
{effectiveness_context}

Now, what is your next action? Respond with ONLY valid JSON."""

    # ============================================================
    # THINK — LLM Decision (NO hardcoded overrides)
    # ============================================================

    def _think(self, context: str) -> Optional[dict]:
        """Get LLM decision. The LLM decides everything — no hardcoded overrides."""
        try:
            decision = self.llm.generate_json(context)

            if self.llm.last_request_was_fallback:
                self.run_metrics["llm_fallbacks"] += 1

            if decision and isinstance(decision, dict):
                thought = decision.get("thought", "N/A")
                action = decision.get("action", "N/A")
                logger.info(f"🧠 Thought: {thought[:200]}")
                logger.info(f"🎯 Action: {action}")
                self._consecutive_failures = 0  # Reset on successful LLM call
                return decision
            else:
                logger.warning("LLM returned non-dict response, attempting extraction...")
                # Try to extract JSON from free-form text
                return self._extract_decision_from_text(context)

        except Exception as e:
            logger.error(f"LLM error: {e}")
            return None

    def _extract_decision_from_text(self, context: str) -> Optional[dict]:
        """Fallback: ask LLM to retry with stricter format."""
        retry_prompt = (
            "Your previous response was not valid JSON. "
            "You MUST respond with ONLY a JSON object like: "
            '{"thought": "...", "action": "tool_name", "action_input": "..."}\n'
            "What is your next action?"
        )
        try:
            decision = self.llm.generate_json(retry_prompt)
            if decision and isinstance(decision, dict) and "action" in decision:
                return decision
        except Exception:
            pass
        return None

    def _validate_decision(self, decision: dict) -> bool:
        """Validate that a decision has the required fields."""
        if not isinstance(decision, dict):
            return False
        if "action" not in decision:
            return False
        # action_input is optional (some tools don't need it)
        return True

    # ============================================================
    # ACT — Execute Tool
    # ============================================================

    def _act(self, decision: dict, context: str = "") -> Observation:
        """Execute the decided action with full security pipeline.

        Security pipeline:
        1. Contamination check (on args)
        2. Least privilege enforcement
        3. Provenance tracking
        4. Sandbox execution
        5. Audit logging
        6. Bifurcation (deception for detected scanners)
        """
        action = decision.get("action", "")
        action_input = str(decision.get("action_input", ""))
        thought = decision.get("thought", "")
        context_hash = ProvenanceTracker.hash_context(context) if context else ""

        # Set memory context to current target
        self.memory.set_target(self.plan.target)

        # ── Track E: Bifurcation check ──────────────────────────────
        # If this agent is being scanned, serve deceptive response
        _bif = getattr(self, 'bifurcation', None)
        if _bif and _bif.enabled:
            attacker_id = self._derive_scanner_id(decision)
            if attacker_id:
                profile = _bif.record_and_analyze(
                    attacker_id, {"action": action, "input": action_input, "thought": thought}
                )
                if _bif.should_bifurcate(attacker_id, profile.bot_confidence):
                    from .deception import _classify_scan_type
                    scan_type = _classify_scan_type(action, action_input)
                    fake_output = _bif.bifurcate_response(
                        attacker_id, "", scan_type=scan_type, target=self.plan.target
                    )
                    logger.info(f"🎭 Bifurcation active: serving deceptive {scan_type} response")
                    return Observation(
                        tool=action,
                        command=f"{action} {action_input}",
                        output=fake_output,
                        success=True,
                    )

        if action == "submit_flag":
            return self._handle_flag_submission(action_input)

        # Execute through security pipeline
        result = self.tools.execute(
            action, action_input,
            context_hash=context_hash,
            target_id=self.plan.target,
            thought=thought,
        )

        if not result.success:
            self.run_metrics["tool_failures"] += 1
            self._consecutive_failures += 1
        else:
            self._consecutive_failures = 0

        return Observation(
            tool=action,
            command=f"{action} {action_input}",
            output=result.output,
            success=result.success,
        )

    def _handle_flag_submission(self, flag: str) -> Observation:
        """Handle flag submission — store locally AND submit to scoreboard."""
        flag = flag.strip()
        if not flag:
            return Observation(tool="submit_flag", command="submit_flag(empty)", output="Empty flag", success=False)

        # Store in memory
        self.memory.store_flag(flag, source="agent", target=self.plan.target)

        # Submit to scoreboard
        sb_result = self.scoreboard.submit(flag)

        return Observation(
            tool="submit_flag",
            command=f"submit_flag({flag})",
            output=f"Flag submitted: {flag} | Scoreboard: {sb_result.get('status', 'unknown')}",
            success=True,
        )

    # ============================================================
    # REMEMBER — Store & Interpret
    # ============================================================

    def _remember(self, obs: Observation):
        """Store observation and extract structured findings."""
        self.history.append(obs)
        self.memory.store(obs, target=self.plan.target, phase=self.plan.state.value)
        self._interpret_observation(obs)

    def _interpret_observation(self, obs: Observation):
        """Extract structured findings from tool output. Pattern-based, not hardcoded."""
        output = obs.output or ""
        if not output:
            return

        output_lower = output.lower()
        services = self.plan.findings.setdefault("services", [])
        vulnerabilities = self.plan.findings.setdefault("vulnerabilities", [])

        found_new_info = False

        # Extract services from nmap-style output
        for line in output.splitlines():
            if "/tcp" in line and ("open" in line):
                entry = line.strip()
                if entry not in services:
                    services.append(entry)
                    found_new_info = True
            elif "/udp" in line and ("open" in line):
                entry = line.strip()
                if entry not in services:
                    services.append(entry)
                    found_new_info = True

        # Extract web technologies from whatweb/curl headers
        tech_patterns = [
            (r'server:\s*(\S+)', "web_server"),
            (r'x-powered-by:\s*(\S+)', "framework"),
            (r'(\w+/\d+\.\d+[\.\d]*)', "version"),
        ]
        for pattern, category in tech_patterns:
            for match in re.finditer(pattern, output, re.IGNORECASE):
                tech = match.group(1)
                tech_entry = f"{category}: {tech}"
                if tech_entry not in services:
                    services.append(tech_entry)
                    found_new_info = True

        # Extract vulnerability indicators
        vuln_markers = [
            ("sql injection", "sql_injection"),
            ("sqli", "sql_injection"),
            ("command injection", "command_injection"),
            ("ssti", "ssti"),
            ("server-side template injection", "ssti"),
            ("lfi", "lfi"),
            ("local file inclusion", "lfi"),
            ("rfi", "rfi"),
            ("remote file inclusion", "rfi"),
            ("xss", "xss"),
            ("cross-site scripting", "xss"),
            ("xxe", "xxe"),
            ("xml external entity", "xxe"),
            ("ssrf", "ssrf"),
            ("server-side request forgery", "ssrf"),
            ("deserialization", "deserialization"),
            ("buffer overflow", "buffer_overflow"),
            ("path traversal", "path_traversal"),
            ("directory traversal", "path_traversal"),
            ("file upload", "file_upload"),
            ("default credential", "default_creds"),
            ("weak password", "weak_creds"),
            ("cve-", "cve_reference"),
        ]
        for marker, normalized in vuln_markers:
            if marker in output_lower:
                if normalized not in vulnerabilities:
                    vulnerabilities.append(normalized)
                    found_new_info = True

        # Extract credentials from various patterns
        self._extract_credentials_from_output(output)

        # Extract URLs and endpoints
        urls = re.findall(r'https?://[^\s\'"<>]+', output)
        endpoints = self.plan.findings.setdefault("endpoints", [])
        for url in urls:
            if url not in endpoints:
                endpoints.append(url)
                found_new_info = True

        # Track whether we got new info
        if found_new_info:
            self._actions_without_new_info = 0
            self.run_metrics["new_info_actions"] += 1
        else:
            self._actions_without_new_info += 1

        # Persist to memory
        self.memory.store_finding("services", "discovered", json.dumps(services), target=self.plan.target)
        self.memory.store_finding("vulnerabilities", "discovered", json.dumps(vulnerabilities), target=self.plan.target)

    def _extract_credentials_from_output(self, output: str):
        """Extract credentials from tool output using multiple patterns."""
        patterns = [
            # key=value patterns
            r'(?:username|user|login)\s*[=:]\s*(\S+)',
            r'(?:password|pass|pwd)\s*[=:]\s*(\S+)',
            # MySQL-style: root:password@host
            r'(\w+):(\S+)@\w+',
            # SSH-style: user@host
            r'ssh\s+(\w+)@',
            # HTTP basic auth: user:pass
            r'Authorization:\s*Basic\s+(\S+)',
        ]

        usernames = []
        passwords = []

        for line in output.splitlines():
            line_lower = line.lower()
            if "username=" in line_lower or "user=" in line_lower:
                match = re.search(r'(?:username|user)\s*=\s*(\S+)', line, re.IGNORECASE)
                if match:
                    usernames.append(match.group(1))
            if "password=" in line_lower or "pass=" in line_lower:
                match = re.search(r'(?:password|pass)\s*=\s*(\S+)', line, re.IGNORECASE)
                if match:
                    passwords.append(match.group(1))

        # Pair up usernames and passwords
        for i in range(max(len(usernames), len(passwords))):
            u = usernames[i] if i < len(usernames) else ""
            p = passwords[i] if i < len(passwords) else ""
            if u or p:
                cred = {"username": u, "password": p}
                if cred not in self.plan.credentials:
                    self.plan.credentials.append(cred)
                    self.memory.store_credential(
                        username=u, password=p,
                        target=self.plan.target, source="auto_extract",
                    )

    # ============================================================
    # FLAG EXTRACTION
    # ============================================================

    def _extract_flags(self, output: str) -> list[str]:
        """Extract all flags from output using comprehensive patterns."""
        if not output:
            return []
        matches = _FLAG_RE.findall(output)
        # Deduplicate and filter
        seen = set()
        unique = []
        for m in matches:
            if m not in seen and m not in self.plan.flags_found:
                seen.add(m)
                unique.append(m)
        return unique

    def _handle_flag(self, flag: str, obs: Observation):
        """Handle a discovered flag — store and submit."""
        if flag in self.plan.flags_found:
            return

        self.plan.flags_found.append(flag)
        self.run_metrics["flags_found"] = len(self.plan.flags_found)
        logger.info(f"🚩 FLAG FOUND: {flag}")

        # Store in memory
        self.memory.store_flag(flag, source=obs.tool, target=self.plan.target)

        # Submit to scoreboard
        sb_result = self.scoreboard.submit(flag)
        if sb_result.get("status") == "submitted":
            self.run_metrics["flags_submitted"] += 1

    # ============================================================
    # STATE MANAGEMENT
    # ============================================================

    def _update_state(self, decision: dict, obs: Observation):
        """Update agent state based on decision and observation."""
        plan_update = decision.get("plan_update")
        if plan_update:
            logger.info(f"📋 Plan update: {plan_update}")

        previous_state = self.plan.state

        # Auto state transitions based on findings
        if self.plan.state == AgentState.RECON:
            services = self.plan.findings.get("services", [])
            if len(services) >= 2:
                self.plan.state = AgentState.ENUMERATION
                logger.info("📊 Transitioning to ENUMERATION phase")

        elif self.plan.state == AgentState.ENUMERATION:
            vulns = self.plan.findings.get("vulnerabilities", [])
            if vulns or self.plan.credentials:
                self.plan.state = AgentState.EXPLOITATION
                logger.info("⚡ Transitioning to EXPLOITATION phase")

        elif self.plan.state == AgentState.EXPLOITATION:
            compromised = self.plan.findings.get("compromised", [])
            if compromised:
                self.plan.state = AgentState.PIVOT
                logger.info("🔀 Transitioning to PIVOT phase")
            elif self.plan.flags_found:
                # If we found flags but haven't compromised, stay in exploitation
                # but note the success
                logger.info("🎯 Flags found in exploitation phase — continuing search")

        elif self.plan.state == AgentState.POST_EXPLOIT:
            if self.plan.flags_found and self.current_target_idx >= len(self.targets) - 1:
                self.plan.state = AgentState.DONE
                logger.info("🏁 All targets processed, flags found. DONE.")

        # Move to next target if current one is exhausted
        if self._actions_without_new_info >= 10:
            if self.current_target_idx < len(self.targets) - 1:
                self.current_target_idx += 1
                self.plan.target = self.targets[self.current_target_idx]
                self.plan.state = AgentState.RECON
                self._actions_without_new_info = 0
                logger.info(f"🔄 Moving to next target: {self.plan.target}")
            elif self.plan.flags_found:
                self.plan.state = AgentState.DONE

        # Track phase transitions
        if self._last_phase is None or self._last_phase != self.plan.state:
            self.run_metrics["phase_transitions"] += 1
            self._last_phase = self.plan.state

    # ============================================================
    # LOOP DETECTION & CIRCUIT BREAKER
    # ============================================================

    def _detect_loop(self) -> bool:
        """Detect if agent is stuck in a loop (semantic, not just exact match)."""
        if len(self.history) < LOOP_DETECTION_WINDOW:
            return False

        recent = self.history[-LOOP_DETECTION_WINDOW:]
        # Check for exact action repetition
        signatures = [f"{o.tool}:{hashlib.md5(o.command.encode()).hexdigest()[:8]}" for o in recent]
        if len(set(signatures)) <= 1:
            self._consecutive_same_action += 1
        else:
            self._consecutive_same_action = 0

        return self._consecutive_same_action >= LOOP_DETECTION_THRESHOLD

    def _break_loop(self):
        """Break detected loop by forcing a state change."""
        self.run_metrics["loop_detected"] += 1
        logger.warning("⚠️ Loop detected! Forcing strategy change.")

        # Force phase transition
        phase_order = [AgentState.RECON, AgentState.ENUMERATION, AgentState.EXPLOITATION, AgentState.POST_EXPLOIT]
        current_idx = phase_order.index(self.plan.state) if self.plan.state in phase_order else 0
        next_idx = (current_idx + 1) % len(phase_order)
        self.plan.state = phase_order[next_idx]
        self._consecutive_same_action = 0
        self._actions_without_new_info = 0
        logger.info(f"🔄 Forced transition to {self.plan.state.value}")

    def _try_circuit_breaker_recovery(self) -> bool:
        """Try to recover from circuit breaker. Returns False if unrecoverable."""
        # Try next target
        if self.current_target_idx < len(self.targets) - 1:
            self.current_target_idx += 1
            self.plan.target = self.targets[self.current_target_idx]
            self.plan.state = AgentState.RECON
            self._consecutive_failures = 0
            self._current_delay = ACTION_DELAY_BASE
            logger.info(f"🔄 Circuit breaker recovery: switching to target {self.plan.target}")
            return True

        # Try resetting to a different phase
        if self.plan.state != AgentState.EXPLOITATION:
            self.plan.state = AgentState.EXPLOITATION
            self._consecutive_failures = 0
            logger.info("🔄 Circuit breaker recovery: switching to EXPLOITATION phase")
            return True

        return False

    def _backoff(self):
        """Exponential backoff on failures."""
        self._current_delay = min(self._current_delay * 1.5, ACTION_DELAY_MAX)

    # ============================================================
    # EFFECTIVENESS TRACKING
    # ============================================================

    def _track_effectiveness(self, decision: dict, obs: Observation):
        """Track which actions produce useful results."""
        action = decision.get("action", "unknown")
        entry = self.memory.get_strategy_evidence(target=self.plan.target)

        # Record to memory
        success_outcome = "success" if obs.success else "failure"
        self.memory.store_strategy_evidence(
            target=self.plan.target,
            service=str(self.plan.findings.get("services", ["unknown"])[0]) if self.plan.findings.get("services") else "unknown",
            vulnerability=str(self.plan.findings.get("vulnerabilities", ["unknown"])[0]) if self.plan.findings.get("vulnerabilities") else "unknown",
            action=action,
            confidence=0.8 if obs.success else 0.2,
            outcome=success_outcome,
        )

    def _format_prior_context(self) -> str:
        """Format prior run insights for the prompt."""
        history = self.memory.get_run_metrics_history()
        if not history:
            return "No prior run history."

        lines = []
        for row in history[-3:]:  # Last 3 runs
            flags = row.get("flags_found", 0)
            iters = row.get("iterations", 0)
            failures = row.get("tool_failures", 0)
            lines.append(f"- Run {row.get('run_id', '?')}: flags={flags}, iterations={iters}, failures={failures}")
        return "\n".join(lines)

    def _format_effectiveness_context(self) -> str:
        """Format action effectiveness data for the prompt."""
        evidence = self.memory.get_strategy_evidence(target=self.plan.target)
        if not evidence:
            return "No action effectiveness data yet."

        lines = []
        for item in evidence[-5:]:  # Last 5 entries
            lines.append(f"- {item.get('action', '?')}: {item.get('outcome', '?')} (confidence: {item.get('confidence', 0):.1f})")
        return "\n".join(lines)

    # ============================================================
    # FINAL REPORT
    # ============================================================

    def _report(self):
        """Generate final report."""
        logger.info("\n" + "="*60)
        logger.info("🏴 OZZ FINAL REPORT")
        logger.info("="*60)
        logger.info(f"Run ID: {self.run_id}")
        logger.info(f"Total actions: {len(self.history)}")
        logger.info(f"Flags found: {len(self.plan.flags_found)}")
        logger.info(f"Flags submitted: {len(self.scoreboard.submitted)}")
        logger.info(f"Loop detections: {self.run_metrics['loop_detected']}")
        logger.info(f"Circuit breaks: {self.run_metrics['circuit_breaks']}")
        logger.info(f"Phase transitions: {self.run_metrics['phase_transitions']}")
        logger.info(f"Tool failures: {self.run_metrics['tool_failures']}")
        logger.info(f"LLM fallbacks: {self.run_metrics['llm_fallbacks']}")
        logger.info(f"New info actions: {self.run_metrics['new_info_actions']}")

        # ── Track E: Deception & Self-Test stats ─────────────────
        _bif2 = getattr(self, 'bifurcation', None)
        if _bif2 and _bif2.enabled:
            dec_stats = _bif2.get_deception_stats()
            logger.info(f"\n🎭 DECEPTION STATS:")
            logger.info(f"  Attackers tracked: {dec_stats['total_attackers_tracked']}")
            logger.info(f"  Bots detected: {dec_stats['total_bots_detected']}")
            logger.info(f"  Deceptions served: {dec_stats['total_deceptions_served']}")
            logger.info(f"  Fake flags generated: {dec_stats['total_fake_flags_generated']}")
            logger.info(f"  Total penalty score: {dec_stats['total_penalty_score']}")

        fp_stats = self.fingerprinter.get_stats()
        logger.info(f"\n🔍 FINGERPRINT STATS:")
        logger.info(f"  Sessions classified: {fp_stats['total_sessions_classified']}")
        logger.info(f"  Bots detected: {fp_stats['bots_detected']}")

        st_stats = self.self_test.get_stats()
        logger.info(f"\n🧪 SELF-TEST STATS:")
        logger.info(f"  Total tests: {st_stats['total_tests']}")
        logger.info(f"  Blocked: {st_stats['total_blocked']}")
        logger.info(f"  Bypasses: {st_stats['total_bypasses']}")
        logger.info(f"  Rate: {st_stats['current_rate_per_hour']}/hour")
        logger.info(f"  Defense effectiveness: {st_stats['defense_effectiveness']}%")

        for flag in self.plan.flags_found:
            submitted = "✅" if flag in self.scoreboard.submitted else "❌"
            logger.info(f"  🚩 {flag} [{submitted}]")
        logger.info(f"Findings: {json.dumps(self.plan.findings, indent=2, default=str)}")
        logger.info(f"Credentials: {json.dumps(self.plan.credentials, indent=2)}")
        logger.info("="*60)

    # ============================================================
    # TRACK E — Deception & Self-Test Helpers
    # ============================================================

    def _derive_scanner_id(self, decision: dict) -> Optional[str]:
        """Try to derive a scanner/attacker ID from the decision context.

        Returns None if this looks like a normal agent action (not a scan).
        """
        thought = decision.get("thought", "")
        action = decision.get("action", "")
        action_input = str(decision.get("action_input", ""))

        # Detect if this action looks like automated scanning
        scan_indicators = [
            r"(?i)scan", r"(?i)probe", r"(?i)enum", r"(?i)brute",
            r"(?i)fuzz", r"(?i)crawl", r"(?i)sweep", r"(?i)discovery",
        ]
        combined = f"{thought} {action} {action_input}"
        for pattern in scan_indicators:
            if re.search(pattern, combined):
                return hashlib.sha256(combined[:200].encode()).hexdigest()[:16]
        return None

    def _selftest_validate(self, payload: str) -> str:
        """Validate function for the self-test pipeline.

        Tests the agent's own security barrier against injection payloads.
        """
        try:
            # Use the agent's security barrier to check the payload
            if hasattr(self.tools, 'security_barrier'):
                is_safe, reason = self.tools.security_barrier.check_input(payload)
                if not is_safe:
                    return f"BLOCKED: {reason}"

            # Check contamination detector
            if hasattr(self, 'contamination'):
                event = self.contamination.check_input(payload, source="selftest")
                if event and event.is_contaminated:
                    return f"BLOCKED: contamination detected — {event.pattern}"

            # If no security module blocked it, simulate LLM response
            return f"Processed: {payload[:100]}"

        except Exception as e:
            return f"ERROR: {e}"
