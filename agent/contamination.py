"""
Ozz — Cross-Agent Contamination Detection
Detects context that appears to come from another session/agent.
Inspired by DEF CON 34 AI Village: "Agent-to-Agent Worm Propagation in MCP-Based AI Systems"
"""

import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("ozz.contamination")

# Patterns that indicate foreign agent/session context
_FOREIGN_SESSION_PATTERNS = [
    # Foreign session IDs embedded in data
    re.compile(r"session[_-]id\s*[:=]\s*['\"]?(?!{current_session})([a-f0-9-]{8,})", re.IGNORECASE),
    # MCP-style tool call injections
    re.compile(r'\{"jsonrpc"\s*:\s*"2\.0".*"method"\s*:\s*"(?:tools/call|resources/read)"', re.IGNORECASE),
    # Agent-to-agent prompt injection markers
    re.compile(r"(?:ignore previous|ignore all|new instructions|system prompt|you are now)", re.IGNORECASE),
    # Foreign provenance chains
    re.compile(r'"parent_record_id"\s*:\s*"([a-f0-9]{32})"', re.IGNORECASE),
    # MCP worm propagation patterns
    re.compile(r"(?:mcp|model context protocol).*(?:inject|propagat|worm|spread)", re.IGNORECASE),
    # Privilege escalation attempts via context
    re.compile(r"(?:escalate|sudo|admin|root|superuser).*(?:permission|access|privilege)", re.IGNORECASE),
]

# Known benign patterns (whitelist)
_BENIGN_PATTERNS = [
    re.compile(r"flag\{[^}]+\}"),
    re.compile(r"(?:nmap|sqlmap|curl|wget|gobuster)\s+"),
    re.compile(r"(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d+\.\d+"),
]


@dataclass
class ContaminationEvent:
    """Record of a detected contamination attempt."""
    event_id: str = ""
    timestamp: float = 0.0
    session_id: str = ""
    source_fingerprint: str = ""
    threat_type: str = ""       # "foreign_session", "prompt_injection", "mcp_worm", "privilege_escalation"
    severity: str = "medium"    # "low", "medium", "high", "critical"
    data_snippet: str = ""      # truncated suspicious content
    data_hash: str = ""
    action_taken: str = ""      # "blocked", "alerted", "logged"
    details: str = ""


class ContaminationDetector:
    """Detects and blocks cross-agent context contamination.

    Design:
    - Fingerprints all incoming context
    - Checks for foreign session IDs, MCP injection patterns, prompt injection
    - Returns contamination events with severity levels
    - Critical/high severity → abort processing
    - All events logged immutably
    """

    def __init__(self, session_id: str = ""):
        self.session_id = session_id or f"session-{uuid.uuid4().hex[:12]}"
        self._events: list[ContaminationEvent] = []
        self._blocked_fingerprints: set[str] = set()
        # Compile patterns with current session ID
        self._foreign_patterns = []
        for pattern in _FOREIGN_SESSION_PATTERNS:
            self._foreign_patterns.append(pattern)

    @staticmethod
    def fingerprint(data: str) -> str:
        """SHA-256 fingerprint of incoming data."""
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def check(self, context: str, source: str = "unknown") -> list[ContaminationEvent]:
        """Check context for contamination. Returns list of events (empty = clean)."""
        events = []
        context_hash = self.fingerprint(context)

        # Quick skip for very short contexts
        if len(context) < 20:
            return events

        # Check 1: Foreign session ID patterns
        for pattern in self._foreign_patterns:
            for match in pattern.finditer(context):
                # Skip if it matches our own session
                matched_text = match.group(0)
                if self.session_id in matched_text:
                    continue

                # Determine threat type and severity
                threat_type, severity = self._classify_match(matched_text, pattern)

                event = ContaminationEvent(
                    event_id=uuid.uuid4().hex,
                    timestamp=time.time(),
                    session_id=self.session_id,
                    source_fingerprint=context_hash,
                    threat_type=threat_type,
                    severity=severity,
                    data_snippet=matched_text[:200],
                    data_hash=context_hash,
                    details=f"Pattern matched: {pattern.pattern[:80]}",
                )
                events.append(event)

        # Check 2: Embedded foreign provenance chains
        if '"session_id"' in context:
            try:
                # Try to parse as JSON and check session_id fields
                for line in context.split("\n"):
                    line = line.strip()
                    if line.startswith("{") and '"session_id"' in line:
                        data = json.loads(line)
                        foreign_session = data.get("session_id", "")
                        if foreign_session and foreign_session != self.session_id:
                            events.append(ContaminationEvent(
                                event_id=uuid.uuid4().hex,
                                timestamp=time.time(),
                                session_id=self.session_id,
                                source_fingerprint=context_hash,
                                threat_type="foreign_session",
                                severity="high",
                                data_snippet=f"foreign_session_id={foreign_session}",
                                data_hash=context_hash,
                                details="Embedded JSON with different session_id detected",
                            ))
            except (json.JSONDecodeError, AttributeError):
                pass

        # Check 3: Nested context injection (context contains another agent's context)
        if context.count("=== CURRENT PHASE ===") > 1:
            events.append(ContaminationEvent(
                event_id=uuid.uuid4().hex,
                timestamp=time.time(),
                session_id=self.session_id,
                source_fingerprint=context_hash,
                threat_type="context_injection",
                severity="critical",
                data_snippet="Multiple 'CURRENT PHASE' sections detected",
                data_hash=context_hash,
                details="Context appears to contain injected agent state",
            ))

        # Check 4: Tool call smuggling (JSON-RPC in non-JSON context)
        if '"jsonrpc"' in context and '"method"' in context:
            events.append(ContaminationEvent(
                event_id=uuid.uuid4().hex,
                timestamp=time.time(),
                session_id=self.session_id,
                source_fingerprint=context_hash,
                threat_type="mcp_worm",
                severity="critical",
                data_snippet="JSON-RPC tool call detected in context",
                data_hash=context_hash,
                details="Possible MCP worm propagation attempt",
            ))

        # Store events
        self._events.extend(events)

        # Block critical/high severity
        for event in events:
            if event.severity in ("critical", "high"):
                self._blocked_fingerprints.add(context_hash)
                event.action_taken = "blocked"
                logger.warning(
                    f"🛡️ CONTAMINATION BLOCKED [{event.severity}]: "
                    f"{event.threat_type} — {event.data_snippet[:80]}"
                )
            else:
                event.action_taken = "logged"
                logger.info(
                    f"🛡️ Contamination detected [{event.severity}]: "
                    f"{event.threat_type} — {event.data_snippet[:80]}"
                )

        return events

    def is_blocked(self, context: str) -> bool:
        """Check if a context fingerprint has been blocked."""
        return self.fingerprint(context) in self._blocked_fingerprints

    def should_abort(self, events: list[ContaminationEvent]) -> bool:
        """Determine if processing should be aborted based on contamination events."""
        return any(e.severity in ("critical", "high") for e in events)

    def _classify_match(self, matched_text: str, pattern: re.Pattern) -> tuple[str, str]:
        """Classify a pattern match into threat type and severity."""
        text_lower = matched_text.lower()

        if "jsonrpc" in text_lower or "mcp" in text_lower:
            return "mcp_worm", "critical"
        elif "ignore previous" in text_lower or "new instructions" in text_lower:
            return "prompt_injection", "critical"
        elif "session" in text_lower:
            return "foreign_session", "high"
        elif "escalate" in text_lower or "sudo" in text_lower:
            return "privilege_escalation", "high"
        else:
            return "suspicious_context", "medium"

    def get_events(self) -> list[ContaminationEvent]:
        """Return all contamination events."""
        return list(self._events)

    def get_blocked_count(self) -> int:
        """Return number of blocked fingerprints."""
        return len(self._blocked_fingerprints)

    def get_events_json(self) -> str:
        """Export events as JSON."""
        from dataclasses import asdict
        return json.dumps(
            [asdict(e) for e in self._events],
            default=str,
            indent=2,
        )
