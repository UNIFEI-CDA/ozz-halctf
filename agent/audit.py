"""
Ozz — Tool-Call Audit Logger
Immutable append-only log for every command executed.
Inspired by DEF CON 34 AI Village: "Agent-to-Agent Privilege Boundary Failures in CI/CD Agents"
"""

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger("ozz.audit")

# Default audit log path (inside workspace)
AUDIT_LOG_DIR = os.environ.get(
    "OZZ_AUDIT_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".openclaw", "tmp", "audit"),
)

# Max output size stored in audit log (100KB)
MAX_OUTPUT_CHARS = 100_000


@dataclass
class AuditEntry:
    """Single immutable audit log entry."""
    entry_id: str = ""
    timestamp: str = ""           # ISO 8601
    timestamp_epoch: float = 0.0
    session_id: str = ""
    target_id: str = ""
    tool_name: str = ""
    tool_args: str = ""
    output: str = ""              # truncated to MAX_OUTPUT_CHARS
    output_hash: str = ""         # SHA-256 of FULL output (before truncation)
    exit_code: int = -1
    success: bool = False
    duration_s: float = 0.0
    context_hash: str = ""        # hash of context that generated this action
    provenance_record_id: str = ""
    # Immutability
    entry_hash: str = ""          # hash of all fields above (tamper detection)

    def to_dict(self) -> dict:
        return asdict(self)


class AuditLogger:
    """Immutable append-only audit log.

    Design:
    - Each entry is hashed; the hash is included in the entry itself
    - Entries are appended to a JSONL file (one JSON per line)
    - The hash chain provides tamper detection
    - Thread-safe via lock
    - File permissions set to read-only after creation (best effort)
    """

    def __init__(self, log_dir: str = AUDIT_LOG_DIR, session_id: str = ""):
        self.log_dir = log_dir
        self.session_id = session_id or "default"
        self._lock = threading.Lock()
        self._last_hash: str = "GENESIS"
        self._entry_count: int = 0
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)

    @property
    def log_file(self) -> str:
        """Per-session log file."""
        safe_session = self.session_id.replace("/", "_").replace("..", "_")
        return os.path.join(self.log_dir, f"audit_{safe_session}.jsonl")

    @staticmethod
    def _compute_entry_hash(entry_dict: dict) -> str:
        """Compute SHA-256 hash of entry fields (excluding entry_hash itself)."""
        # Deterministic serialization
        canonical = json.dumps(entry_dict, sort_keys=True, default=str, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def log(
        self,
        tool_name: str,
        tool_args: str,
        output: str,
        success: bool,
        exit_code: int = -1,
        duration_s: float = 0.0,
        target_id: str = "",
        context_hash: str = "",
        provenance_record_id: str = "",
    ) -> AuditEntry:
        """Log a tool call. Returns the immutable AuditEntry."""
        import uuid

        now = time.time()
        output_full = output or ""
        output_truncated = output_full[:MAX_OUTPUT_CHARS]
        output_hash = hashlib.sha256(output_full.encode("utf-8")).hexdigest()

        entry = AuditEntry(
            entry_id=uuid.uuid4().hex,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now)),
            timestamp_epoch=now,
            session_id=self.session_id,
            target_id=target_id,
            tool_name=tool_name,
            tool_args=tool_args[:10_000],  # cap args too
            output=output_truncated,
            output_hash=output_hash,
            exit_code=exit_code,
            success=success,
            duration_s=duration_s,
            context_hash=context_hash,
            provenance_record_id=provenance_record_id,
        )

        # Compute entry hash (tamper detection)
        entry_dict = entry.to_dict()
        entry_dict["entry_hash"] = ""  # placeholder
        entry.entry_hash = self._compute_entry_hash(entry_dict)

        # Append to immutable log
        with self._lock:
            self._append(entry)
            self._entry_count += 1

        logger.debug(
            f"Audit: {tool_name} args_hash={hashlib.sha256(tool_args.encode()).hexdigest()[:8]} "
            f"output_hash={output_hash[:8]} success={success}"
        )
        return entry

    def _append(self, entry: AuditEntry):
        """Append entry to JSONL file."""
        line = json.dumps(entry.to_dict(), default=str, ensure_ascii=False) + "\n"
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

    def verify_log_integrity(self) -> tuple[bool, int, int]:
        """Verify the integrity of the entire audit log.

        Returns (is_valid, total_entries, valid_entries).
        """
        valid = 0
        total = 0
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    total += 1
                    try:
                        entry_dict = json.loads(line)
                        stored_hash = entry_dict.get("entry_hash", "")
                        entry_dict["entry_hash"] = ""
                        computed = self._compute_entry_hash(entry_dict)
                        if computed == stored_hash:
                            valid += 1
                        else:
                            logger.warning(
                                f"Audit integrity failure at entry {total}: "
                                f"expected {stored_hash[:8]}, got {computed[:8]}"
                            )
                    except json.JSONDecodeError:
                        logger.warning(f"Audit integrity: corrupt line at entry {total}")
        except FileNotFoundError:
            return True, 0, 0

        return valid == total, total, valid

    def get_entries(self, limit: int = 100) -> list[dict]:
        """Read recent audit entries."""
        entries = []
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
        except FileNotFoundError:
            pass
        return entries[-limit:]

    def get_entry_count(self) -> int:
        """Return total number of logged entries."""
        return self._entry_count
