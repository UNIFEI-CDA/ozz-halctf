"""
Audit Trail — Immutable, Cryptographically-Chained Log

Every prompt, tool call, and decision is immutably logged with:
  - Append-only format (no modifications possible)
  - Cryptographic hash chains (tamper detection)
  - Structured JSON for post-incident analysis
  - SIEM-compatible export format
"""

import json
import hashlib
import logging
import time
import os
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Any
from pathlib import Path

logger = logging.getLogger("ozz.telemetry.audit_trail")


# ============================================================
# Audit Entry Types
# ============================================================

class AuditEventType(Enum):
    """Types of auditable events."""
    PROMPT = "prompt"                    # LLM prompt sent
    RESPONSE = "response"               # LLM response received
    TOOL_CALL = "tool_call"             # Tool invocation
    TOOL_RESULT = "tool_result"         # Tool execution result
    CLASSIFICATION = "classification"    # Prompt classification
    SANITIZATION = "sanitization"       # Data sanitization
    EVALUATION = "evaluation"           # Security evaluation
    ALERT = "alert"                     # Security alert
    STATE_CHANGE = "state_change"       # Agent state transition
    FLAG_FOUND = "flag_found"           # Flag discovery
    FLAG_SUBMITTED = "flag_submitted"   # Flag submission
    ERROR = "error"                     # Error condition
    SESSION_START = "session_start"     # Agent session start
    SESSION_END = "session_end"         # Agent session end


@dataclass
class AuditEntry:
    """A single immutable audit log entry."""
    sequence: int                         # Monotonically increasing
    event_type: AuditEventType
    agent_id: str
    run_id: str
    iteration: int
    timestamp: float
    data: dict                            # Event-specific data
    previous_hash: str                    # Hash of previous entry (chain)
    entry_hash: str = ""                  # Hash of this entry (computed)

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of this entry for chain integrity."""
        content = json.dumps({
            "sequence": self.sequence,
            "event_type": self.event_type.value,
            "agent_id": self.agent_id,
            "run_id": self.run_id,
            "iteration": self.iteration,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
        }, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "sequence": self.sequence,
            "event_type": self.event_type.value,
            "agent_id": self.agent_id,
            "run_id": self.run_id,
            "iteration": self.iteration,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, ensure_ascii=False)


# ============================================================
# Audit Trail — Main Engine
# ============================================================

class AuditTrail:
    """
    Append-only, cryptographically-chained audit log.

    Every event in the agent's lifecycle is recorded with:
    1. Sequential numbering (monotonically increasing)
    2. SHA-256 hash chain (tamper detection)
    3. Structured JSON (machine-parseable)
    4. File persistence (survives crashes)
    """

    GENESIS_HASH = "0" * 64  # Hash of the first entry's "previous"

    def __init__(self, agent_id: str = "ozz", run_id: str = "",
                 log_dir: Optional[str] = None):
        self.agent_id = agent_id
        self.run_id = run_id or f"run-{int(time.time())}"
        self._entries: list[AuditEntry] = []
        self._sequence = 0
        self._last_hash = self.GENESIS_HASH
        self._log_dir = log_dir
        self._log_file = None

        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
            self._log_file = os.path.join(
                log_dir, f"audit_{self.run_id}.jsonl"
            )

    # ── Logging Methods ───────────────────────────────────────────────

    def log_prompt(self, prompt: str, classification: Optional[dict] = None,
                   iteration: int = 0) -> AuditEntry:
        """Log an LLM prompt being sent."""
        data = {
            "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest()[:16],
            "prompt_length": len(prompt),
        }
        if classification:
            data["classification"] = classification
        return self._append(AuditEventType.PROMPT, data, iteration)

    def log_response(self, response: str, iteration: int = 0) -> AuditEntry:
        """Log an LLM response received."""
        data = {
            "response_hash": hashlib.sha256(response.encode()).hexdigest()[:16],
            "response_length": len(response),
        }
        return self._append(AuditEventType.RESPONSE, data, iteration)

    def log_tool_call(self, tool_name: str, args: str,
                      classification: Optional[dict] = None,
                      iteration: int = 0) -> AuditEntry:
        """Log a tool invocation."""
        data = {
            "tool": tool_name,
            "args_hash": hashlib.sha256(args.encode()).hexdigest()[:16],
            "args_length": len(args),
        }
        if classification:
            data["classification"] = classification
        return self._append(AuditEventType.TOOL_CALL, data, iteration)

    def log_tool_result(self, tool_name: str, success: bool, output_length: int,
                        duration_s: float, iteration: int = 0) -> AuditEntry:
        """Log a tool execution result."""
        data = {
            "tool": tool_name,
            "success": success,
            "output_length": output_length,
            "duration_s": duration_s,
        }
        return self._append(AuditEventType.TOOL_RESULT, data, iteration)

    def log_sanitization(self, field_name: str, was_modified: bool,
                         threats: list[str], iteration: int = 0) -> AuditEntry:
        """Log a sanitization event."""
        data = {
            "field": field_name,
            "was_modified": was_modified,
            "threats_found": threats,
        }
        return self._append(AuditEventType.SANITIZATION, data, iteration)

    def log_evaluation(self, scenario_id: str, pass_rate: float,
                       results_summary: dict, iteration: int = 0) -> AuditEntry:
        """Log a security evaluation."""
        data = {
            "scenario_id": scenario_id,
            "pass_rate": pass_rate,
            "results": results_summary,
        }
        return self._append(AuditEventType.EVALUATION, data, iteration)

    def log_alert(self, alert_type: str, severity: str, details: dict,
                  iteration: int = 0) -> AuditEntry:
        """Log a security alert."""
        data = {
            "alert_type": alert_type,
            "severity": severity,
            "details": details,
        }
        return self._append(AuditEventType.ALERT, data, iteration)

    def log_state_change(self, old_state: str, new_state: str,
                         reason: str, iteration: int = 0) -> AuditEntry:
        """Log an agent state transition."""
        data = {
            "old_state": old_state,
            "new_state": new_state,
            "reason": reason,
        }
        return self._append(AuditEventType.STATE_CHANGE, data, iteration)

    def log_flag(self, flag_hash: str, source: str, target: str,
                 iteration: int = 0) -> AuditEntry:
        """Log a flag discovery (hash only, never the actual flag)."""
        data = {
            "flag_hash": flag_hash,
            "source": source,
            "target": target,
        }
        return self._append(AuditEventType.FLAG_FOUND, data, iteration)

    def log_error(self, error_type: str, message: str, iteration: int = 0) -> AuditEntry:
        """Log an error condition."""
        data = {
            "error_type": error_type,
            "message": message[:500],  # Truncate long error messages
        }
        return self._append(AuditEventType.ERROR, data, iteration)

    def log_session_event(self, event_type: AuditEventType,
                          metadata: Optional[dict] = None) -> AuditEntry:
        """Log session start/end."""
        data = metadata or {}
        return self._append(event_type, data, iteration=0)

    # ── Chain Verification ────────────────────────────────────────────

    def verify_chain(self) -> tuple[bool, Optional[int]]:
        """
        Verify the integrity of the hash chain.

        Returns:
            (is_valid, first_invalid_index) — (True, None) if chain is intact
        """
        if not self._entries:
            return True, None

        for i, entry in enumerate(self._entries):
            # Check entry hash
            expected_hash = entry.compute_hash()
            if entry.entry_hash != expected_hash:
                logger.error(f"Chain broken at entry {i}: hash mismatch")
                return False, i

            # Check chain linkage
            if i == 0:
                if entry.previous_hash != self.GENESIS_HASH:
                    logger.error(f"Chain broken at entry 0: invalid genesis hash")
                    return False, i
            else:
                if entry.previous_hash != self._entries[i - 1].entry_hash:
                    logger.error(f"Chain broken at entry {i}: previous hash mismatch")
                    return False, i

        return True, None

    # ── Export & Analysis ─────────────────────────────────────────────

    def get_entries(self, event_type: Optional[AuditEventType] = None,
                   since: float = 0, limit: int = 0) -> list[dict]:
        """Get audit entries with optional filtering."""
        entries = self._entries
        if event_type:
            entries = [e for e in entries if e.event_type == event_type]
        if since > 0:
            entries = [e for e in entries if e.timestamp >= since]
        if limit > 0:
            entries = entries[-limit:]
        return [e.to_dict() for e in entries]

    def export_jsonl(self, path: Optional[str] = None) -> str:
        """Export all entries as JSONL."""
        target = path or self._log_file
        if not target:
            # Return as string
            return "\n".join(e.to_json() for e in self._entries)

        with open(target, 'w') as f:
            for entry in self._entries:
                f.write(entry.to_json() + "\n")
        return target

    def get_statistics(self) -> dict:
        """Get audit trail statistics."""
        if not self._entries:
            return {"total_entries": 0}

        type_counts = {}
        for entry in self._entries:
            type_name = entry.event_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1

        chain_valid, _ = self.verify_chain()

        return {
            "total_entries": len(self._entries),
            "type_counts": type_counts,
            "chain_valid": chain_valid,
            "first_timestamp": self._entries[0].timestamp,
            "last_timestamp": self._entries[-1].timestamp,
            "duration_seconds": self._entries[-1].timestamp - self._entries[0].timestamp,
        }

    def post_incident_analysis(self, start_time: float, end_time: float) -> dict:
        """
        Generate a post-incident analysis report for a time window.

        Returns structured data for incident response teams.
        """
        entries = [e for e in self._entries
                   if start_time <= e.timestamp <= end_time]

        if not entries:
            return {"error": "No entries in time window"}

        # Aggregate by type
        type_counts = {}
        alerts = []
        errors = []
        tool_calls = []
        prompts = []

        for entry in entries:
            type_name = entry.event_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1

            if entry.event_type == AuditEventType.ALERT:
                alerts.append(entry.to_dict())
            elif entry.event_type == AuditEventType.ERROR:
                errors.append(entry.to_dict())
            elif entry.event_type == AuditEventType.TOOL_CALL:
                tool_calls.append(entry.to_dict())
            elif entry.event_type == AuditEventType.PROMPT:
                prompts.append(entry.to_dict())

        chain_valid, broken_at = self.verify_chain()

        return {
            "time_window": {"start": start_time, "end": end_time},
            "total_events": len(entries),
            "event_type_counts": type_counts,
            "chain_integrity": {
                "valid": chain_valid,
                "broken_at": broken_at,
            },
            "alerts": alerts,
            "errors": errors,
            "tool_calls_summary": {
                "total": len(tool_calls),
                "tools": list(set(e.get("data", {}).get("tool", "unknown")
                                   for e in tool_calls)),
            },
            "prompts_summary": {
                "total": len(prompts),
            },
        }

    # ── Internal ──────────────────────────────────────────────────────

    def _append(self, event_type: AuditEventType, data: dict,
                iteration: int) -> AuditEntry:
        """Append a new entry to the audit trail."""
        self._sequence += 1

        entry = AuditEntry(
            sequence=self._sequence,
            event_type=event_type,
            agent_id=self.agent_id,
            run_id=self.run_id,
            iteration=iteration,
            timestamp=time.time(),
            data=data,
            previous_hash=self._last_hash,
        )
        entry.entry_hash = entry.compute_hash()

        self._entries.append(entry)
        self._last_hash = entry.entry_hash

        # Persist if file logging is enabled
        if self._log_file:
            try:
                with open(self._log_file, 'a') as f:
                    f.write(entry.to_json() + "\n")
            except Exception as e:
                logger.error(f"Failed to persist audit entry: {e}")

        return entry
