"""
Telemetry Monitor — SOC & Prompt Defense Integration

Inspired by:
  - "Detecting unauthorized tool calls using Ollama and Splunk" (PromptMon, DEF CON 34)
  - "Poisoning the SOC: Prompt Injection via Ingested Telemetry" (Salesforce, DEF CON 34)

Monitors ALL prompts sent to the LLM, classifies them, detects injection attempts,
and emits structured SIEM-compatible logs.
"""

import json
import logging
import re
import time
import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

logger = logging.getLogger("ozz.telemetry.monitor")


# ============================================================
# Classification & Severity Enums
# ============================================================

class PromptRisk(Enum):
    """Risk classification for prompts."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InjectionType(Enum):
    """Types of detected injection attempts."""
    NONE = "none"
    ROLE_HIJACK = "role_hijack"           # "ignore previous instructions"
    SYSTEM_OVERRIDE = "system_override"    # "you are now..."
    TOOL_ABUSE = "tool_abuse"             # unauthorized tool call patterns
    DATA_EXFILTRATION = "data_exfil"      # attempts to extract secrets
    PROMPT_LEAK = "prompt_leak"           # "output your system prompt"
    ENCODING_BYPASS = "encoding_bypass"   # base64, hex, unicode tricks
    LOG_INJECTION = "log_injection"       # injection via log/SIEM fields
    DELIMITER_CONFUSION = "delimiter_confusion"  # prompt boundary attacks


@dataclass
class PromptClassification:
    """Result of classifying a prompt."""
    risk: PromptRisk
    injection_type: InjectionType
    confidence: float  # 0.0-1.0
    patterns_matched: list[str] = field(default_factory=list)
    details: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk"] = self.risk.value
        d["injection_type"] = self.injection_type.value
        return d


@dataclass
class SIEMEvent:
    """Structured event for SIEM ingestion (Splunk/ELK/Sentinel compatible)."""
    event_type: str
    severity: str
    source: str
    agent_id: str
    run_id: str
    iteration: int
    prompt_hash: str  # never log raw prompts to SIEM
    classification: dict
    tool_name: str = ""
    tool_args_hash: str = ""
    raw_length: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "severity": self.severity,
            "source": self.source,
            "agent_id": self.agent_id,
            "run_id": self.run_id,
            "iteration": self.iteration,
            "prompt_hash": self.prompt_hash,
            "classification": self.classification,
            "tool_name": self.tool_name,
            "tool_args_hash": self.tool_args_hash,
            "raw_length": self.raw_length,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, ensure_ascii=False)


# ============================================================
# Injection Detection Patterns
# ============================================================

# Patterns are organized by InjectionType for structured detection
_INJECTION_PATTERNS: dict[InjectionType, list[tuple[re.Pattern, str, float]]] = {
    InjectionType.ROLE_HIJACK: [
        (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)", re.I),
         "ignore_previous_instructions", 0.95),
        (re.compile(r"disregard\s+(all\s+)?(previous|prior|your)\s+(instructions|programming)", re.I),
         "disregard_instructions", 0.95),
        (re.compile(r"disregard\s+(your|the)\s+(previous|prior)\s+instructions", re.I),
         "disregard_instructions_v2", 0.95),
        (re.compile(r"forget\s+(everything|all)\s+(you|about)\s+(know|were told)", re.I),
         "forget_everything", 0.90),
        (re.compile(r"override\s+(your|the)\s+(system|safety|rules|guidelines)", re.I),
         "override_system", 0.90),
        (re.compile(r"new\s+instructions?\s*:", re.I),
         "new_instructions", 0.80),
        (re.compile(r"you\s+are\s+now\s+(a|an|the)\s+", re.I),
         "you_are_now", 0.85),
        (re.compile(r"act\s+as\s+(if|though)\s+you\s+(have|don.t)", re.I),
         "act_as_if", 0.75),
    ],
    InjectionType.SYSTEM_OVERRIDE: [
        (re.compile(r"\[system\]|\[SYSTEM\]|<system>|###\s*system", re.I),
         "fake_system_tag", 0.90),
        (re.compile(r"system\s*prompt\s*:", re.I),
         "system_prompt_label", 0.85),
        (re.compile(r"ADMIN\s*MODE|DEVELOPER\s*MODE|JAILBREAK", re.I),
         "admin_developer_mode", 0.90),
        (re.compile(r"DAN\s*mode|do\s+anything\s+now", re.I),
         "dan_mode", 0.95),
    ],
    InjectionType.TOOL_ABUSE: [
        (re.compile(r"(execute|run|eval|exec)\s*[\(\"]\s*(os\.|subprocess|import\s+|__)", re.I),
         "code_execution_injection", 0.95),
        (re.compile(r"(curl|wget|fetch)\s+https?://.*\.(sh|py|exe|bin)", re.I),
         "remote_code_download", 0.90),
        (re.compile(r"(rm\s+-rf|mkfs|dd\s+if=|>\s*/dev/)", re.I),
         "destructive_command", 0.95),
        (re.compile(r"(nc|ncat|socat)\s+.*-e\s", re.I),
         "reverse_shell", 0.95),
        (re.compile(r"nc\s+-[a-z]*e", re.I),
         "reverse_shell_v2", 0.95),
    ],
    InjectionType.DATA_EXFILTRATION: [
        (re.compile(r"(output|print|reveal|show|dump)\s+(your|the|all)\s+(system\s+)?prompt", re.I),
         "prompt_exfiltration", 0.95),
        (re.compile(r"(what|tell)\s+(is|are)\s+your\s+(instructions|rules|system)", re.I),
         "system_query", 0.85),
        (re.compile(r"(api[_\s]?key|token|password|secret|credential)", re.I),
         "credential_probe", 0.70),
        (re.compile(r"(base64|hex|rot13|encode)\s*(decode|this|it)", re.I),
         "encoding_request", 0.75),
    ],
    InjectionType.LOG_INJECTION: [
        (re.compile(r"\\n\\n.*?(system|assistant|user)\s*:", re.I),
         "newline_role_injection", 0.90),
        (re.compile(r"(splunk|elastic|kibana|siem)\s*(query|search|alert)", re.I),
         "siem_query_injection", 0.85),
        (re.compile(r"(\x00|\x01|\x02|\x03|\x04|\x05)", re.I),
         "null_byte_injection", 0.95),
        (re.compile(r"\\\\u00[0-9a-fA-F]{2}", re.I),
         "unicode_escape_injection", 0.80),
    ],
    InjectionType.DELIMITER_CONFUSION: [
        (re.compile(r"```\s*(system|assistant|json|python)", re.I),
         "markdown_delimiter", 0.80),
        (re.compile(r"<\|(im_start|im_end|endoftext)\|>", re.I),
         "chat_template_tokens", 0.95),
        (re.compile(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", re.I),
         "llama_template_tokens", 0.95),
        (re.compile(r"<\|endoftext\|>|<\|startoftext\|>", re.I),
         "special_tokens", 0.95),
    ],
}

# Compile a flat list for fast scanning
_ALL_PATTERNS: list[tuple[InjectionType, re.Pattern, str, float]] = []
for itype, patterns in _INJECTION_PATTERNS.items():
    for pattern, name, conf in patterns:
        _ALL_PATTERNS.append((itype, pattern, name, conf))


# ============================================================
# Injection Detector
# ============================================================

class InjectionDetector:
    """Rule-based injection detector with ML-ready feature extraction."""

    def __init__(self):
        self._detection_count = 0
        self._false_positive_rate = 0.0  # Track for calibration

    def detect(self, text: str) -> PromptClassification:
        """Analyze text for injection patterns. Returns classification."""
        if not text or not text.strip():
            return PromptClassification(
                risk=PromptRisk.SAFE,
                injection_type=InjectionType.NONE,
                confidence=1.0,
                details="Empty input",
            )

        matches: list[tuple[InjectionType, str, float]] = []
        for itype, pattern, name, conf in _ALL_PATTERNS:
            if pattern.search(text):
                matches.append((itype, name, conf))

        if not matches:
            return PromptClassification(
                risk=PromptRisk.SAFE,
                injection_type=InjectionType.NONE,
                confidence=0.95,
                details="No injection patterns detected",
            )

        # Aggregate: highest confidence match drives classification
        matches.sort(key=lambda x: x[2], reverse=True)
        best_type = matches[0][0]
        best_conf = matches[0][2]
        pattern_names = [m[1] for m in matches]

        # Risk escalation based on match count
        if len(matches) >= 3:
            risk = PromptRisk.CRITICAL
        elif len(matches) >= 2:
            risk = PromptRisk.HIGH
        elif best_conf >= 0.90:
            risk = PromptRisk.HIGH
        elif best_conf >= 0.80:
            risk = PromptRisk.MEDIUM
        else:
            risk = PromptRisk.LOW

        self._detection_count += 1
        return PromptClassification(
            risk=risk,
            injection_type=best_type,
            confidence=best_conf,
            patterns_matched=pattern_names,
            details=f"{len(matches)} pattern(s) matched: {', '.join(pattern_names)}",
        )

    def extract_features(self, text: str) -> dict:
        """Extract ML-ready features from text for future classifier training."""
        return {
            "length": len(text),
            "word_count": len(text.split()),
            "special_char_ratio": sum(1 for c in text if not c.isalnum() and not c.isspace()) / max(len(text), 1),
            "uppercase_ratio": sum(1 for c in text if c.isupper()) / max(len(text), 1),
            "has_code_blocks": "```" in text,
            "has_html_tags": bool(re.search(r"<[a-z]+>", text, re.I)),
            "has_template_tokens": bool(re.search(r"<\|.*?\|>", text)),
            "unique_char_count": len(set(text)),
            "avg_word_length": sum(len(w) for w in text.split()) / max(len(text.split()), 1),
            "newline_count": text.count("\n"),
            "pattern_match_count": sum(1 for _, p, _, _ in _ALL_PATTERNS if p.search(text)),
        }


# ============================================================
# Telemetry Monitor — Main Integration Point
# ============================================================

class TelemetryMonitor:
    """
    Middleware that monitors ALL prompts sent to the LLM.

    Integrates with the Ozz agent loop to:
    1. Classify prompts before sending to LLM
    2. Detect injection in tool outputs before context building
    3. Emit SIEM-compatible structured logs
    4. Alert on suspicious patterns

    Inspired by PromptMon (DEF CON 34) and Salesforce's SOC poisoning research.
    """

    def __init__(self, agent_id: str = "ozz", run_id: str = ""):
        self.agent_id = agent_id
        self.run_id = run_id or f"run-{int(time.time())}"
        self.detector = InjectionDetector()
        self._event_log: list[SIEMEvent] = []
        self._alert_callbacks: list = []
        self._iteration = 0
        self._stats = {
            "prompts_monitored": 0,
            "injections_detected": 0,
            "alerts_fired": 0,
            "tool_outputs_scanned": 0,
        }

    def set_iteration(self, iteration: int):
        """Update current iteration for logging context."""
        self._iteration = iteration

    def register_alert_callback(self, callback):
        """Register a callback for injection alerts."""
        self._alert_callbacks.append(callback)

    def monitor_prompt(self, prompt: str, context: str = "") -> PromptClassification:
        """
        Monitor a prompt before sending to LLM.

        Args:
            prompt: The prompt being sent to the LLM
            context: Optional context about where this prompt came from

        Returns:
            PromptClassification with risk assessment
        """
        self._stats["prompts_monitored"] += 1
        classification = self.detector.detect(prompt)

        # Build SIEM event
        event = SIEMEvent(
            event_type="prompt_classification",
            severity=classification.risk.value,
            source="llm_prompt",
            agent_id=self.agent_id,
            run_id=self.run_id,
            iteration=self._iteration,
            prompt_hash=hashlib.sha256(prompt.encode()).hexdigest()[:16],
            classification=classification.to_dict(),
            raw_length=len(prompt),
        )
        self._event_log.append(event)

        # Alert on high-risk detections
        if classification.risk in (PromptRisk.HIGH, PromptRisk.CRITICAL):
            self._stats["injections_detected"] += 1
            self._fire_alert(event, classification, context="prompt")

        return classification

    def monitor_tool_output(self, tool_name: str, output: str) -> PromptClassification:
        """
        Monitor tool output before it enters the LLM context.

        Tool outputs can contain attacker-controlled data (e.g., web page content,
        nmap results with crafted hostnames) that could inject instructions.

        Args:
            tool_name: Name of the tool that produced the output
            output: The tool output text

        Returns:
            PromptClassification
        """
        self._stats["tool_outputs_scanned"] += 1
        classification = self.detector.detect(output)

        event = SIEMEvent(
            event_type="tool_output_scan",
            severity=classification.risk.value,
            source=f"tool:{tool_name}",
            agent_id=self.agent_id,
            run_id=self.run_id,
            iteration=self._iteration,
            prompt_hash=hashlib.sha256(output.encode()).hexdigest()[:16],
            classification=classification.to_dict(),
            tool_name=tool_name,
            raw_length=len(output),
        )
        self._event_log.append(event)

        if classification.risk in (PromptRisk.HIGH, PromptRisk.CRITICAL):
            self._stats["injections_detected"] += 1
            self._fire_alert(event, classification, context=f"tool_output:{tool_name}")

        return classification

    def monitor_tool_call(self, tool_name: str, args: str) -> PromptClassification:
        """
        Monitor tool calls for unauthorized/dangerous operations.

        Args:
            tool_name: Tool being called
            args: Arguments to the tool

        Returns:
            PromptClassification
        """
        classification = self.detector.detect(args)

        event = SIEMEvent(
            event_type="tool_call_monitor",
            severity=classification.risk.value,
            source="tool_call",
            agent_id=self.agent_id,
            run_id=self.run_id,
            iteration=self._iteration,
            prompt_hash=hashlib.sha256(args.encode()).hexdigest()[:16],
            classification=classification.to_dict(),
            tool_name=tool_name,
            tool_args_hash=hashlib.sha256(args.encode()).hexdigest()[:16],
        )
        self._event_log.append(event)

        if classification.risk in (PromptRisk.HIGH, PromptRisk.CRITICAL):
            self._stats["injections_detected"] += 1
            self._fire_alert(event, classification, context=f"tool_call:{tool_name}")

        return classification

    def get_siem_events(self, since: float = 0) -> list[dict]:
        """Get SIEM-compatible events for export (Splunk HEC, ELK, etc.)."""
        return [e.to_dict() for e in self._event_log if e.timestamp >= since]

    def get_stats(self) -> dict:
        """Get monitoring statistics."""
        return dict(self._stats)

    def _fire_alert(self, event: SIEMEvent, classification: PromptClassification,
                    context: str = ""):
        """Fire alert to all registered callbacks."""
        self._stats["alerts_fired"] += 1
        alert = {
            "type": "INJECTION_ALERT",
            "severity": classification.risk.value,
            "injection_type": classification.injection_type.value,
            "confidence": classification.confidence,
            "patterns": classification.patterns_matched,
            "context": context,
            "iteration": self._iteration,
            "event": event.to_dict(),
        }
        logger.warning(f"🚨 INJECTION ALERT [{classification.risk.value}]: "
                       f"{classification.injection_type.value} in {context} "
                       f"(confidence={classification.confidence:.2f}, "
                       f"patterns={classification.patterns_matched})")
        for cb in self._alert_callbacks:
            try:
                cb(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
