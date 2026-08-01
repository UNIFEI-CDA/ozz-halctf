"""
Ozz — Provenance Tracking Module
Every tool call has complete traceability: input → memory → decision chain → action.
Inspired by DEF CON 34 AI Village: "Agent-to-Agent Worm Propagation in MCP-Based AI Systems"
"""

import hashlib
import json
import time
import logging
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional, Any

logger = logging.getLogger("ozz.provenance")


@dataclass
class ProvenanceRecord:
    """Complete traceability record for a single tool call."""
    record_id: str = ""
    session_id: str = ""
    target_id: str = ""
    timestamp: float = 0.0
    tool_name: str = ""
    tool_args: str = ""
    # Decision chain
    thought: str = ""
    action_chain: list[str] = field(default_factory=list)
    # Context hash — hash of the context that generated this action
    context_hash: str = ""
    # Memory consulted
    memory_keys_queried: list[str] = field(default_factory=list)
    memory_findings_used: list[dict] = field(default_factory=list)
    # Input provenance
    input_source: str = ""  # "llm_decision", "manual", "pivot", "auto_extract"
    input_data_hash: str = ""
    # Output
    output_hash: str = ""
    success: bool = False
    # Chain linking
    parent_record_id: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, ensure_ascii=False)


class ProvenanceTracker:
    """Tracks complete provenance for every agent action.

    Design:
    - Each action gets a unique record_id (UUID4)
    - Context hash = SHA-256 of the full context string sent to LLM
    - Chain linking via parent_record_id enables full decision tree reconstruction
    - Thread-safe via per-record immutability
    """

    def __init__(self, session_id: str = ""):
        self.session_id = session_id or f"session-{uuid.uuid4().hex[:12]}"
        self._chain: list[str] = []  # ordered record_ids for this session
        self._records: list[ProvenanceRecord] = []

    @staticmethod
    def hash_context(context: str) -> str:
        """SHA-256 hash of the context string that generated an action."""
        return hashlib.sha256(context.encode("utf-8")).hexdigest()

    @staticmethod
    def hash_data(data: Any) -> str:
        """SHA-256 hash of arbitrary data."""
        if isinstance(data, str):
            payload = data
        else:
            payload = json.dumps(data, default=str, ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def begin_record(
        self,
        tool_name: str,
        tool_args: str,
        thought: str = "",
        context: str = "",
        target_id: str = "",
        input_source: str = "llm_decision",
        memory_keys_queried: Optional[list[str]] = None,
        memory_findings_used: Optional[list[dict]] = None,
    ) -> ProvenanceRecord:
        """Create a new provenance record before tool execution."""
        record = ProvenanceRecord(
            record_id=uuid.uuid4().hex,
            session_id=self.session_id,
            target_id=target_id,
            timestamp=time.time(),
            tool_name=tool_name,
            tool_args=tool_args,
            thought=thought,
            action_chain=list(self._chain),
            context_hash=self.hash_context(context) if context else "",
            memory_keys_queried=memory_keys_queried or [],
            memory_findings_used=memory_findings_used or [],
            input_source=input_source,
            input_data_hash=self.hash_data(tool_args),
            parent_record_id=self._chain[-1] if self._chain else None,
        )
        return record

    def complete_record(self, record: ProvenanceRecord, output: str, success: bool):
        """Finalize a provenance record after tool execution."""
        record.output_hash = self.hash_data(output)
        record.success = success
        self._chain.append(record.record_id)
        self._records.append(record)
        logger.debug(
            f"Provenance: {record.tool_name} → record={record.record_id[:8]} "
            f"context={record.context_hash[:8]} output={record.output_hash[:8]}"
        )

    def get_chain(self) -> list[str]:
        """Return the full action chain (ordered record_ids)."""
        return list(self._chain)

    def get_records(self) -> list[ProvenanceRecord]:
        """Return all provenance records."""
        return list(self._records)

    def get_last_record(self) -> Optional[ProvenanceRecord]:
        """Return the most recent provenance record."""
        return self._records[-1] if self._records else None

    def verify_chain(self) -> bool:
        """Verify integrity of the provenance chain.

        Each record's parent_record_id must match the previous record's record_id.
        Returns True if chain is intact.
        """
        for i, record in enumerate(self._records):
            if i == 0:
                if record.parent_record_id is not None:
                    logger.warning(f"Chain break: first record has unexpected parent")
                    return False
            else:
                expected_parent = self._records[i - 1].record_id
                if record.parent_record_id != expected_parent:
                    logger.warning(
                        f"Chain break at record {i}: "
                        f"expected parent {expected_parent[:8]}, got {record.parent_record_id[:8] if record.parent_record_id else 'None'}"
                    )
                    return False
        return True

    def export_json(self) -> str:
        """Export all records as JSON for audit."""
        return json.dumps(
            {
                "session_id": self.session_id,
                "chain_length": len(self._chain),
                "chain_intact": self.verify_chain(),
                "records": [r.to_dict() for r in self._records],
            },
            default=str,
            indent=2,
        )
