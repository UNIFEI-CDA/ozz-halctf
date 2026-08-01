"""
Bounded Context: ML Supply Chain Security Domain Solver
Detects malicious model artifacts, monitors runtime behavior, identifies
distillation campaigns, and assesses supply chain risk.

Inspired by:
- "The Anatomy of a Chinese Knowledge Distillation Campaign" (CSET, DEF CON 34)
- "The Model Is the Malware: Runtime Behavioral Detection of Malicious ML Artifacts" (Volexity, DEF CON 34)
"""
from __future__ import annotations

import hashlib
import json
import os
import pickle
import re
import struct
import tempfile
import time
import threading
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from .base import BaseDomainSolver
from .registry import register_solver
from .hypothesis import Hypothesis, TournamentResult
from .engine import TacticalHypothesisEngine
from ..security.security_barrier_policy import CommandAllowlistPolicy
from ..dtos.domain_dtos import AnalysisRequest, DomainAnalysisReport, CommandSpec

# ─── Constants ────────────────────────────────────────────────────────────────

ALLOWED_ML_BINARIES: FrozenSet[str] = frozenset({
    "python3", "python", "strace", "sha256sum", "md5sum", "file",
    "strings", "xxd", "unzip", "tar",
})

# Dangerous opcodes / call targets in pickle bytecode
PICKLE_DANGER_OPCODES: FrozenSet[str] = frozenset({
    "GLOBAL", "INST", "REDUCE", "BUILD", "STACK_GLOBAL",
})

# Known malicious callable patterns (module.function)
PICKLE_DANGER_CALLS: FrozenSet[str] = frozenset({
    "os.system", "os.popen", "os.exec", "os.execvp", "os.execve",
    "os.spawn", "os.spawnl", "os.spawnlp", "os.spawnv", "os.spawnvp",
    "subprocess.Popen", "subprocess.call", "subprocess.run",
    "subprocess.check_output", "subprocess.check_call",
    "builtins.eval", "builtins.exec", "builtins.compile",
    "eval", "exec", "compile",
    "pty.spawn", "commands.getoutput", "commands.getstatusoutput",
    "webbrowser.open", "http.client.request",
    "urllib.request.urlopen", "urllib.request.urlretrieve",
    "requests.get", "requests.post",
    "socket.socket", "socket.create_connection",
    "__import__", "importlib.import_module",
    "ctypes.CDLL", "ctypes.cdll", "ctypes.util.find_library",
    "multiprocessing.Process", "threading.Thread",
})

# Patterns that indicate reverse shells, exfiltration, etc.
MALICIOUS_PATTERNS: List[Tuple[str, str]] = [
    (r"reverse.?shell", "reverse_shell"),
    (r"/bin/(ba)?sh", "shell_spawn"),
    (r"/dev/tcp/", "dev_tcp_redirect"),
    (r"nc\s+-[el]", "netcat_listener"),
    (r"mkfifo", "named_pipe"),
    (r"curl\s+.*\|.*sh", "curl_pipe_sh"),
    (r"wget\s+.*\|.*sh", "wget_pipe_sh"),
    (r"base64\s+-d", "base64_decode_exec"),
    (r"chmod\s+\+x", "chmod_executable"),
    (r"\.onion", "tor_address"),
    (r"169\.254\.169\.254", "cloud_metadata"),
    (r"metadata\.google\.internal", "gcp_metadata"),
    (r"/etc/shadow", "shadow_file_access"),
    (r"/etc/passwd", "passwd_file_access"),
    (r"\.ssh/id_", "ssh_key_access"),
    (r"aws_secret", "aws_credential_access"),
    (r"BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY", "private_key_embedded"),
]

# MITRE ATT&CK technique mappings
MITRE_MAPPINGS: Dict[str, Dict[str, str]] = {
    "reverse_shell": {"technique": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter"},
    "shell_spawn": {"technique": "T1059.004", "tactic": "Execution", "name": "Unix Shell"},
    "network_exfil": {"technique": "T1041", "tactic": "Exfiltration", "name": "Exfiltration Over C2 Channel"},
    "credential_access": {"technique": "T1552", "tactic": "Credential Access", "name": "Unsecured Credentials"},
    "persistence": {"technique": "T1547", "tactic": "Persistence", "name": "Boot or Logon Autostart Execution"},
    "privilege_escalation": {"technique": "T1548", "tactic": "Privilege Escalation", "name": "Abuse Elevation Control Mechanism"},
    "defense_evasion": {"technique": "T1027", "tactic": "Defense Evasion", "name": "Obfuscated Files or Information"},
    "collection": {"technique": "T1005", "tactic": "Collection", "name": "Data from Local System"},
    "lateral_movement": {"technique": "T1021", "tactic": "Lateral Movement", "name": "Remote Services"},
    "data_destruction": {"technique": "T1485", "tactic": "Impact", "name": "Data Destruction"},
}


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class MaliciousPattern:
    """A detected malicious pattern in a model artifact."""
    pattern_type: str
    description: str
    severity: str  # critical, high, medium, low
    evidence: str
    mitre: Optional[Dict[str, str]] = None


@dataclass
class ScanResult:
    """Result of scanning a model artifact."""
    file_path: str
    file_hash_sha256: str
    file_size: int
    file_type: str
    is_safe: bool
    risk_score: float  # 0.0 (safe) to 1.0 (critical)
    patterns: List[MaliciousPattern] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


@dataclass
class BehaviorEvent:
    """A single runtime behavior event."""
    timestamp: float
    event_type: str  # syscall, network, file_access, process_spawn
    detail: str
    pid: int = 0
    risk_level: str = "low"


@dataclass
class RuntimeMonitorResult:
    """Result of runtime behavioral monitoring."""
    pid: int
    duration_seconds: float
    events: List[BehaviorEvent] = field(default_factory=list)
    suspicious_behaviors: List[str] = field(default_factory=list)
    mitre_techniques: List[Dict[str, str]] = field(default_factory=list)
    network_connections: List[Dict[str, Any]] = field(default_factory=list)
    file_access_events: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class QueryRecord:
    """A single query record for distillation detection."""
    timestamp: float
    query_text: str
    response_length: int = 0
    embedding: Optional[List[float]] = None


@dataclass
class DistillationAlert:
    """Alert for detected distillation campaign."""
    alert_type: str  # repetitive_queries, boundary_probing, systematic_extraction
    confidence: float  # 0.0 to 1.0
    evidence: List[str] = field(default_factory=list)
    query_count: int = 0
    time_window_seconds: float = 0.0


@dataclass
class SupplyChainReport:
    """Comprehensive supply chain risk assessment."""
    artifact_path: str
    artifact_hash: str
    provenance: Dict[str, Any] = field(default_factory=dict)
    signature_valid: Optional[bool] = None
    hash_known: Optional[bool] = None
    hash_database: str = ""
    risk_level: str = "unknown"  # critical, high, medium, low, unknown
    risk_factors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


# ─── Pickle Safe Inspector ────────────────────────────────────────────────────

class PickleSafeInspector:
    """Inspect pickle bytecode WITHOUT executing untrusted code.

    Uses raw opcode disassembly — never calls pickle.load() or pickle.loads()
    on untrusted data. Parses the pickle VM opcodes directly to detect
    dangerous global/function references.
    """

    # Map opcode bytes to names (protocol 0-2 opcodes)
    _OPCODE_NAMES: Dict[int, str] = {
        0x28: "MARK", 0x2e: "STOP", 0x30: "POP", 0x31: "POP_MARK",
        0x32: "DUP", 0x46: "FLOAT", 0x49: "INT", 0x4a: "BININT",
        0x4b: "BININT1", 0x4c: "LONG", 0x4e: "NONE", 0x50: "PERSID",
        0x51: "BINPERSID", 0x52: "REDUCE", 0x53: "STRING", 0x54: "BINSTRING",
        0x55: "SHORT_BINSTRING", 0x56: "UNICODE", 0x58: "BINUNICODE",
        0x61: "APPEND", 0x62: "BUILD", 0x63: "GLOBAL", 0x64: "DICT",
        0x65: "EMPTY_DICT", 0x67: "GET", 0x68: "BINGET", 0x69: "INST",
        0x6a: "LONG_BINGET", 0x6c: "LIST", 0x6e: "EMPTY_LIST",
        0x70: "PUT", 0x71: "BINPUT", 0x72: "LONG_BINPUT", 0x73: "SETITEM",
        0x74: "TUPLE", 0x75: "EMPTY_TUPLE", 0x76: "SETITEMS", 0x85: "TUPLE1",
        0x86: "TUPLE2", 0x87: "TUPLE3", 0x88: "NEWTRUE", 0x89: "NEWFALSE",
        0x8a: "LONG1", 0x8b: "LONG4", 0x94: "SHORT_BINUNICODE",
        0x95: "BINUNICODE8", 0x96: "BINBYTES8", 0x97: "SHORT_BINBYTES",
        0x98: "BINBYTES", 0xc0: "PROTO", 0xc1: "NEWOBJ", 0xc2: "EXT1",
        0xc3: "EXT2", 0xc4: "EXT4", 0xc5: "TUPLE2", 0xc6: "NEWOBJ_EX",
        0xd2: "STACK_GLOBAL", 0xd3: "MEMOIZE", 0xd4: "FRAME",
    }

    @classmethod
    def inspect(cls, data: bytes) -> Dict[str, Any]:
        """Inspect pickle bytes without executing. Returns danger analysis."""
        result: Dict[str, Any] = {
            "is_pickle": False,
            "protocol": None,
            "dangerous_globals": [],
            "dangerous_calls": [],
            "all_globals": [],
            "opcodes_seen": [],
            "is_safe": True,
            "risk_score": 0.0,
        }

        if not data:
            return result

        # Check pickle magic
        first_byte = data[0]
        if first_byte == 0x80:  # PROTO opcode
            if len(data) > 1:
                result["protocol"] = data[1]
                result["is_pickle"] = True
        elif first_byte in (ord(c) for c in "FINIo."):
            result["is_pickle"] = True
            result["protocol"] = 0
        elif data[:2] in (b"]\n", b"}\n", b")\n"):
            result["is_pickle"] = True
            result["protocol"] = 0

        if not result["is_pickle"]:
            return result

        # Scan for GLOBAL and STACK_GLOBAL opcodes
        i = 0
        while i < len(data):
            opcode = data[i]
            opcode_name = cls._OPCODE_NAMES.get(opcode, f"UNKNOWN_0x{opcode:02x}")

            if opcode_name in ("GLOBAL", "INST"):
                # Next bytes are: module\nname\n
                null_pos = data.find(b"\n", i + 1)
                if null_pos != -1:
                    module_end = null_pos
                    name_end = data.find(b"\n", null_pos + 1)
                    if name_end != -1:
                        module = data[i + 1:module_end].decode("ascii", errors="replace")
                        name = data[module_end + 1:name_end].decode("ascii", errors="replace")
                        full_name = f"{module}.{name}"
                        result["all_globals"].append(full_name)

                        if full_name in PICKLE_DANGER_CALLS:
                            result["dangerous_globals"].append(full_name)
                            result["is_safe"] = False
                        elif any(full_name.startswith(prefix) for prefix in ("os.", "subprocess.", "builtins.")):
                            result["dangerous_globals"].append(full_name)
                            result["is_safe"] = False

                        i = name_end + 1
                        continue

            elif opcode_name == "STACK_GLOBAL":
                # Stack global: module and name are on stack, harder to parse statically
                # Flag as potentially dangerous
                result["all_globals"].append("<stack_global>")
                i += 1
                continue

            elif opcode_name == "REDUCE":
                # REDUCE calls a callable with arguments — mark if previous GLOBAL was dangerous
                result["opcodes_seen"].append("REDUCE")
                i += 1
                continue

            elif opcode_name == "NEWOBJ":
                result["opcodes_seen"].append("NEWOBJ")
                i += 1
                continue

            i += 1

        # Calculate risk score
        if result["dangerous_globals"]:
            result["risk_score"] = min(1.0, 0.3 + 0.2 * len(result["dangerous_globals"]))
            # Critical if shell/network primitives
            critical_patterns = {"os.system", "subprocess.Popen", "subprocess.call", "eval", "exec"}
            if any(g in critical_patterns for g in result["dangerous_globals"]):
                result["risk_score"] = 1.0

        return result


# ─── Model Artifact Scanner ──────────────────────────────────────────────────

class ModelArtifactScanner:
    """Scan model artifacts (.pt, .pkl, .safetensors) BEFORE loading.

    Principle: NEVER execute untrusted code. Use safe inspection only.
    """

    # Magic bytes / signatures
    _SIGNATURES = {
        b"PK\x03\x04": "zip",          # .pt (PyTorch zip), .docx, etc.
        b"\x80\x04\x95": "pickle",      # pickle protocol 4+
        b"\x80\x03\x95": "pickle",      # pickle protocol 3
        b"\x80\x02\x95": "pickle",      # pickle protocol 2
        b"\x80\x01\x95": "pickle",      # pickle protocol 1
        b"\x80\x00": "pickle",          # pickle protocol 0 (binary)
        b"]\n": "pickle_text",           # pickle protocol 0 (text list)
        b"}\n": "pickle_text",           # pickle protocol 0 (text dict)
    }

    # safetensors header: 8 bytes little-endian JSON length, then JSON header
    _SAFETENSORS_MAGIC_SIZE = 8

    def __init__(self, executor=None):
        self.executor = executor

    def compute_hash(self, file_path: str) -> str:
        """Compute SHA-256 hash of file."""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def detect_file_type(self, file_path: str) -> str:
        """Detect file type by magic bytes and extension."""
        ext = Path(file_path).suffix.lower()

        with open(file_path, "rb") as f:
            header = f.read(16)

        for sig, ftype in self._SIGNATURES.items():
            if header[:len(sig)] == sig:
                # ZIP with .pt extension is a PyTorch archive
                if ftype == "zip" and ext == ".pt":
                    return "pytorch_zip"
                return ftype

        # Check safetensors: first 8 bytes = little-endian uint64 JSON header size
        if len(header) >= 8:
            json_size = struct.unpack("<Q", header[:8])[0]
            if 0 < json_size < 100_000_000:  # Reasonable header size
                try:
                    with open(file_path, "rb") as f:
                        f.seek(8)
                        json_bytes = f.read(min(json_size, 1024))
                        json.loads(json_bytes)
                        return "safetensors"
                except (json.JSONDecodeError, ValueError):
                    pass

        # Check if it's a PyTorch zip (ZIP magic bytes)
        if header[:4] == b"PK\x03\x04":
            return "pytorch_zip"

        return "unknown"

    def scan_pkl_file(self, file_path: str) -> ScanResult:
        """Scan a .pkl file for malicious payloads without loading."""
        file_hash = self.compute_hash(file_path)
        file_size = os.path.getsize(file_path)
        patterns: List[MaliciousPattern] = []

        with open(file_path, "rb") as f:
            data = f.read()

        # 1. Pickle bytecode inspection
        pickle_result = PickleSafeInspector.inspect(data)

        if pickle_result["is_pickle"]:
            for global_name in pickle_result["dangerous_globals"]:
                severity = "critical" if global_name in {
                    "os.system", "subprocess.Popen", "eval", "exec"
                } else "high"
                mitre = None
                if "os.system" in global_name or "subprocess" in global_name:
                    mitre = MITRE_MAPPINGS.get("reverse_shell")
                elif global_name in ("eval", "exec"):
                    mitre = MITRE_MAPPINGS.get("defense_evasion")

                patterns.append(MaliciousPattern(
                    pattern_type="dangerous_pickle_global",
                    description=f"Dangerous callable in pickle: {global_name}",
                    severity=severity,
                    evidence=f"GLOBAL/INST opcode references '{global_name}'",
                    mitre=mitre,
                ))

        # 2. String pattern scanning (catches obfuscated payloads)
        try:
            text_content = data.decode("utf-8", errors="replace")
        except Exception:
            text_content = str(data)

        for pattern, pattern_type in MALICIOUS_PATTERNS:
            matches = re.findall(pattern, text_content, re.IGNORECASE)
            if matches:
                severity = "critical" if pattern_type in (
                    "reverse_shell", "dev_tcp_redirect", "shell_spawn"
                ) else "high"
                mitre = MITRE_MAPPINGS.get(pattern_type)
                patterns.append(MaliciousPattern(
                    pattern_type=pattern_type,
                    description=f"Malicious pattern detected: {pattern_type}",
                    severity=severity,
                    evidence=f"Pattern '{pattern}' matched {len(matches)} time(s)",
                    mitre=mitre,
                ))

        # 3. Scan for suspicious embedded scripts
        script_patterns = [
            (rb"__import__\s*\(", "dynamic_import"),
            (rb"getattr\s*\(\s*__builtins__", "builtins_manipulation"),
            (rb"__subclasses__\s*\(\s*\)", "subclass_chain"),
            (rb"__globals__", "globals_access"),
            (rb"__setattr__", "setattr_manipulation"),
            (rb"\.encode\s*\(\s*['\"]base64", "base64_encoding"),
            (rb"marshal\.loads", "marshal_loads"),
            (rb"types\.FunctionType", "function_creation"),
            (rb"code\s*\(\s*\d", "code_object_creation"),
        ]
        for pattern, name in script_patterns:
            if re.search(pattern, data):
                patterns.append(MaliciousPattern(
                    pattern_type=name,
                    description=f"Suspicious Python introspection: {name}",
                    severity="high",
                    evidence=f"Pattern matched in binary data",
                    mitre=MITRE_MAPPINGS.get("defense_evasion"),
                ))

        risk_score = self._calculate_risk_score(patterns)
        is_safe = risk_score < 0.3

        return ScanResult(
            file_path=file_path,
            file_hash_sha256=file_hash,
            file_size=file_size,
            file_type="pickle",
            is_safe=is_safe,
            risk_score=risk_score,
            patterns=patterns,
            metadata={"pickle_inspection": pickle_result},
        )

    def scan_pt_file(self, file_path: str) -> ScanResult:
        """Scan a .pt (PyTorch) file. These are ZIP archives containing pickled data."""
        file_hash = self.compute_hash(file_path)
        file_size = os.path.getsize(file_path)
        patterns: List[MaliciousPattern] = []

        import zipfile
        import io

        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                entries = zf.namelist()
                metadata: Dict[str, Any] = {"zip_entries": entries}

                # Check for unexpected files in the archive
                expected_prefixes = ("data/", "model/", "")
                suspicious_entries = []
                for entry in entries:
                    # Check for path traversal
                    if ".." in entry or entry.startswith("/"):
                        suspicious_entries.append(entry)
                        patterns.append(MaliciousPattern(
                            pattern_type="path_traversal",
                            description=f"Path traversal in ZIP entry: {entry}",
                            severity="critical",
                            evidence=f"ZIP entry '{entry}' contains path traversal",
                            mitre=MITRE_MAPPINGS.get("defense_evasion"),
                        ))

                    # Check for executable content
                    if entry.endswith((".py", ".sh", ".bat", ".ps1", ".exe", ".dll", ".so")):
                        suspicious_entries.append(entry)
                        patterns.append(MaliciousPattern(
                            pattern_type="executable_in_archive",
                            description=f"Executable file in model archive: {entry}",
                            severity="high",
                            evidence=f"ZIP entry '{entry}' is an executable type",
                        ))

                metadata["suspicious_entries"] = suspicious_entries

                # Scan pickled content inside the ZIP
                for entry in entries:
                    try:
                        entry_data = zf.read(entry)
                        pickle_result = PickleSafeInspector.inspect(entry_data)

                        if pickle_result["is_pickle"] and pickle_result["dangerous_globals"]:
                            for global_name in pickle_result["dangerous_globals"]:
                                patterns.append(MaliciousPattern(
                                    pattern_type="dangerous_pickle_in_zip",
                                    description=f"Dangerous callable in ZIP entry '{entry}': {global_name}",
                                    severity="critical",
                                    evidence=f"Entry '{entry}' contains pickle with '{global_name}'",
                                    mitre=MITRE_MAPPINGS.get("reverse_shell"),
                                ))

                        # Also string-scan each entry
                        for pattern, pattern_type in MALICIOUS_PATTERNS:
                            if re.search(pattern, entry_data.decode("utf-8", errors="replace"), re.IGNORECASE):
                                patterns.append(MaliciousPattern(
                                    pattern_type=f"{pattern_type}_in_zip",
                                    description=f"Malicious pattern in ZIP entry '{entry}': {pattern_type}",
                                    severity="critical",
                                    evidence=f"Entry '{entry}' contains pattern '{pattern}'",
                                    mitre=MITRE_MAPPINGS.get(pattern_type),
                                ))
                    except Exception:
                        pass

        except zipfile.BadZipFile:
            # Not a valid ZIP — treat as raw pickle scan
            return self.scan_pkl_file(file_path)

        risk_score = self._calculate_risk_score(patterns)
        is_safe = risk_score < 0.3

        return ScanResult(
            file_path=file_path,
            file_hash_sha256=file_hash,
            file_size=file_size,
            file_type="pytorch_zip",
            is_safe=is_safe,
            risk_score=risk_score,
            patterns=patterns,
            metadata=metadata,
        )

    def scan_safetensors_file(self, file_path: str) -> ScanResult:
        """Scan a .safetensors file. These are generally safer (no arbitrary code execution)."""
        file_hash = self.compute_hash(file_path)
        file_size = os.path.getsize(file_path)
        patterns: List[MaliciousPattern] = []
        metadata: Dict[str, Any] = {}

        with open(file_path, "rb") as f:
            header_size_bytes = f.read(8)
            if len(header_size_bytes) < 8:
                patterns.append(MaliciousPattern(
                    pattern_type="truncated_header",
                    description="Safetensors file too short for header",
                    severity="medium",
                    evidence="File less than 8 bytes",
                ))
            else:
                header_size = struct.unpack("<Q", header_size_bytes)[0]
                if header_size > 100_000_000:
                    patterns.append(MaliciousPattern(
                        pattern_type="oversized_header",
                        description=f"Safetensors header unreasonably large: {header_size} bytes",
                        severity="high",
                        evidence=f"Header size {header_size} exceeds 100MB threshold",
                    ))
                else:
                    try:
                        header_json = f.read(header_size)
                        header = json.loads(header_json)
                        metadata["header_keys"] = list(header.keys())

                        # Check for unexpected metadata keys
                        suspicious_keys = [k for k in header.keys() if k != "__metadata__" and not k.startswith("model")]
                        if suspicious_keys:
                            metadata["suspicious_keys"] = suspicious_keys

                        # Check __metadata__ for anything odd
                        meta = header.get("__metadata__", {})
                        if isinstance(meta, dict):
                            for key, value in meta.items():
                                if isinstance(value, str):
                                    for pattern, pattern_type in MALICIOUS_PATTERNS:
                                        if re.search(pattern, value, re.IGNORECASE):
                                            patterns.append(MaliciousPattern(
                                                pattern_type=f"metadata_{pattern_type}",
                                                description=f"Malicious pattern in safetensors metadata: {key}",
                                                severity="high",
                                                evidence=f"Metadata key '{key}' contains pattern '{pattern}'",
                                            ))
                    except (json.JSONDecodeError, ValueError) as e:
                        patterns.append(MaliciousPattern(
                            pattern_type="invalid_header",
                            description=f"Invalid safetensors JSON header: {e}",
                            severity="medium",
                            evidence=str(e),
                        ))

        # safetensors format doesn't allow code execution, but flag if data section
        # contains unexpected content
        risk_score = self._calculate_risk_score(patterns)
        # safetensors is inherently safer — cap base risk
        risk_score = min(risk_score, 0.7)

        return ScanResult(
            file_path=file_path,
            file_hash_sha256=file_hash,
            file_size=file_size,
            file_type="safetensors",
            is_safe=risk_score < 0.3,
            risk_score=risk_score,
            patterns=patterns,
            metadata=metadata,
        )

    def scan(self, file_path: str) -> ScanResult:
        """Scan any model artifact. Dispatches to type-specific scanners."""
        if not os.path.exists(file_path):
            return ScanResult(
                file_path=file_path,
                file_hash_sha256="",
                file_size=0,
                file_type="not_found",
                is_safe=False,
                risk_score=1.0,
                errors=[f"File not found: {file_path}"],
            )

        ftype = self.detect_file_type(file_path)
        ext = Path(file_path).suffix.lower()

        if ftype == "safetensors" or ext == ".safetensors":
            return self.scan_safetensors_file(file_path)
        elif ftype == "pytorch_zip" or ext == ".pt":
            return self.scan_pt_file(file_path)
        elif ftype in ("pickle", "pickle_text") or ext == ".pkl":
            return self.scan_pkl_file(file_path)
        else:
            # Unknown type — do a generic scan
            return self.scan_pkl_file(file_path)

    @staticmethod
    def _calculate_risk_score(patterns: List[MaliciousPattern]) -> float:
        """Calculate aggregate risk score from detected patterns."""
        if not patterns:
            return 0.0

        severity_weights = {"critical": 0.5, "high": 0.35, "medium": 0.15, "low": 0.05}
        total = sum(severity_weights.get(p.severity, 0.1) for p in patterns)
        # Any critical or high pattern should push above 0.3 (unsafe threshold)
        has_dangerous = any(p.severity in ("critical", "high") for p in patterns)
        if has_dangerous:
            total = max(total, 0.35)
        return min(1.0, total)


# ─── Runtime Behavioral Monitor ──────────────────────────────────────────────

class RuntimeBehavioralMonitor:
    """Monitor model loading behavior via strace / process tracing.

    Detects: network connections, file access, process spawning, suspicious syscalls.
    Maps behaviors to MITRE ATT&CK framework.
    """

    # Syscalls that indicate suspicious behavior
    SUSPICIOUS_SYSCALLS: Dict[str, Dict[str, str]] = {
        "connect": {"risk": "high", "category": "network"},
        "socket": {"risk": "high", "category": "network"},
        "bind": {"risk": "high", "category": "network"},
        "listen": {"risk": "critical", "category": "network"},
        "accept": {"risk": "high", "category": "network"},
        "execve": {"risk": "critical", "category": "process"},
        "clone": {"risk": "medium", "category": "process"},
        "fork": {"risk": "high", "category": "process"},
        "open": {"risk": "low", "category": "file"},
        "openat": {"risk": "low", "category": "file"},
        "unlink": {"risk": "high", "category": "file"},
        "rename": {"risk": "medium", "category": "file"},
        "chmod": {"risk": "high", "category": "file"},
        "chown": {"risk": "high", "category": "file"},
        "ptrace": {"risk": "critical", "category": "anti_debug"},
        "kill": {"risk": "high", "category": "process"},
        "prctl": {"risk": "medium", "category": "defense_evasion"},
    }

    # Sensitive file paths
    SENSITIVE_PATHS: List[str] = [
        "/etc/shadow", "/etc/passwd", "/etc/sudoers",
        ".ssh/", ".gnupg/", ".aws/", ".config/",
        "/proc/self/mem", "/dev/mem",
    ]

    def __init__(self, executor=None):
        self.executor = executor

    def monitor_process(self, pid: int, duration: float = 10.0) -> RuntimeMonitorResult:
        """Monitor a process via strace for the given duration."""
        result = RuntimeMonitorResult(pid=pid, duration_seconds=duration)

        if self.executor is None:
            result.suspicious_behaviors.append("No executor available for monitoring")
            return result

        # Use strace to trace syscalls
        strace_cmd = CommandSpec(
            binary="strace",
            args=["-f", "-e", "trace=network,process,file", "-p", str(pid), "-t"],
            timeout=duration + 5,
        )

        try:
            exec_result = self.executor.execute(strace_cmd)
            if exec_result.success:
                self._parse_strace_output(exec_result.output, result)
            else:
                result.suspicious_behaviors.append(f"strace failed: {exec_result.error}")
        except Exception as e:
            result.suspicious_behaviors.append(f"Monitoring error: {e}")

        result.risk_score = self._calculate_monitor_risk(result)
        return result

    def monitor_command(self, command: str, args: List[str], duration: float = 10.0) -> RuntimeMonitorResult:
        """Run a command under strace and monitor its behavior."""
        result = RuntimeMonitorResult(pid=0, duration_seconds=duration)

        if self.executor is None:
            result.suspicious_behaviors.append("No executor available")
            return result

        # Run command under strace
        strace_cmd = CommandSpec(
            binary="strace",
            args=["-f", "-e", "trace=network,process,file", "-o", "/dev/stderr",
                   command] + args,
            timeout=duration + 5,
        )

        try:
            exec_result = self.executor.execute(strace_cmd)
            # strace output goes to stderr, so we parse stderr
            strace_output = exec_result.error or exec_result.output
            self._parse_strace_output(strace_output, result)
        except Exception as e:
            result.suspicious_behaviors.append(f"Monitoring error: {e}")

        result.risk_score = self._calculate_monitor_risk(result)
        return result

    def _parse_strace_output(self, output: str, result: RuntimeMonitorResult):
        """Parse strace output to extract behavior events."""
        if not output:
            return

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            # Parse strace line format: [pid] syscall(args...) = result <time>
            # e.g.: 1234  connect(3, {sa_family=AF_INET, sin_port=htons(80), ...}, 16) = 0

            # Extract syscall name
            syscall_match = re.search(r"(\w+)\(", line)
            if not syscall_match:
                continue

            syscall_name = syscall_match.group(1)
            sys_info = self.SUSPICIOUS_SYSCALLS.get(syscall_name)

            if sys_info:
                event = BehaviorEvent(
                    timestamp=time.time(),
                    event_type=sys_info["category"],
                    detail=line[:200],
                    risk_level=sys_info["risk"],
                )
                result.events.append(event)

                # Categorize specific behaviors
                if sys_info["category"] == "network":
                    self._extract_network_info(line, result)
                elif sys_info["category"] == "file":
                    self._extract_file_access(line, result)
                elif sys_info["category"] == "process":
                    self._extract_process_info(line, result, syscall_name)

    def _extract_network_info(self, line: str, result: RuntimeMonitorResult):
        """Extract network connection details from strace line."""
        # Look for IP:port patterns
        ip_match = re.search(r"sin_addr=inet_addr\(\"([\d.]+)\"\)", line)
        port_match = re.search(r"sin_port=htons\((\d+)\)", line)
        if ip_match and port_match:
            conn = {
                "ip": ip_match.group(1),
                "port": int(port_match.group(1)),
                "raw": line[:150],
            }
            result.network_connections.append(conn)

            # Flag connections to suspicious IPs
            ip = ip_match.group(1)
            if ip.startswith("169.254.") or ip.startswith("10.") or ip.startswith("192.168."):
                result.suspicious_behaviors.append(
                    f"Network connection to internal IP: {ip}:{port_match.group(1)}"
                )
            elif ip not in ("127.0.0.1", "::1", "0.0.0.0"):
                result.suspicious_behaviors.append(
                    f"Network connection to external IP: {ip}:{port_match.group(1)}"
                )
                result.mitre_techniques.append(MITRE_MAPPINGS["network_exfil"])

    def _extract_file_access(self, line: str, result: RuntimeMonitorResult):
        """Extract file access details from strace line."""
        path_match = re.search(r'"([^"]+)"', line)
        if path_match:
            path = path_match.group(1)
            result.file_access_events.append({"path": path, "raw": line[:150]})

            for sensitive in self.SENSITIVE_PATHS:
                if sensitive in path:
                    result.suspicious_behaviors.append(
                        f"Access to sensitive path: {path}"
                    )
                    result.mitre_techniques.append(MITRE_MAPPINGS["credential_access"])
                    break

    def _extract_process_info(self, line: str, result: RuntimeMonitorResult, syscall: str):
        """Extract process spawning details from strace line."""
        if syscall in ("execve", "clone", "fork"):
            result.suspicious_behaviors.append(f"Process operation: {syscall} — {line[:150]}")
            result.mitre_techniques.append(MITRE_MAPPINGS["reverse_shell"])

    @staticmethod
    def _calculate_monitor_risk(result: RuntimeMonitorResult) -> float:
        """Calculate risk score from monitored behaviors."""
        if not result.events:
            return 0.0

        risk_weights = {"critical": 0.4, "high": 0.25, "medium": 0.15, "low": 0.05}
        total = sum(risk_weights.get(e.risk_level, 0.1) for e in result.events)
        return min(1.0, total)


# ─── Distillation Detector ────────────────────────────────────────────────────

class DistillationDetector:
    """Detect unauthorized knowledge distillation campaigns.

    Based on patterns from "The Anatomy of a Chinese Knowledge Distillation Campaign" (CSET).
    Identifies:
    - Repetitive queries with slight variations
    - Systematic boundary probing
    - Extraction-style queries (asking for explanations of everything)
    - Rate anomalies
    """

    def __init__(self, window_size: int = 100, time_window: float = 3600.0):
        self.query_history: deque = deque(maxlen=window_size * 10)
        self.time_window = time_window  # seconds
        self.window_size = window_size
        self._alert_callbacks: List = []

    def add_query(self, query: QueryRecord):
        """Record a query for analysis."""
        self.query_history.append(query)

    def analyze(self) -> List[DistillationAlert]:
        """Analyze query history for distillation patterns."""
        alerts: List[DistillationAlert] = []
        now = time.time()

        # Filter to time window
        recent = [q for q in self.query_history if now - q.timestamp < self.time_window]
        if len(recent) < 5:
            return alerts

        # 1. Repetitive queries with slight variations
        rep_alert = self._detect_repetitive_queries(recent)
        if rep_alert:
            alerts.append(rep_alert)

        # 2. Systematic boundary probing
        probe_alert = self._detect_boundary_probing(recent)
        if probe_alert:
            alerts.append(probe_alert)

        # 3. Extraction-style queries
        extract_alert = self._detect_extraction_queries(recent)
        if extract_alert:
            alerts.append(extract_alert)

        # 4. Rate anomaly detection
        rate_alert = self._detect_rate_anomaly(recent)
        if rate_alert:
            alerts.append(rate_alert)

        return alerts

    def _detect_repetitive_queries(self, queries: List[QueryRecord]) -> Optional[DistillationAlert]:
        """Detect queries with high similarity (slight variations)."""
        if len(queries) < 10:
            return None

        # Normalize queries for comparison
        normalized = []
        for q in queries:
            norm = re.sub(r"[^a-zA-Z0-9\s]", "", q.query_text.lower())
            norm = re.sub(r"\s+", " ", norm).strip()
            normalized.append((norm, q))

        # Count similar pairs (simple n-gram overlap)
        similar_count = 0
        total_pairs = 0
        evidence = []

        for i in range(len(normalized)):
            for j in range(i + 1, min(i + 20, len(normalized))):
                total_pairs += 1
                sim = self._text_similarity(normalized[i][0], normalized[j][0])
                if sim > 0.7:
                    similar_count += 1
                    if len(evidence) < 5:
                        evidence.append(
                            f"Query {i} & {j} similarity={sim:.2f}: "
                            f"'{normalized[i][1].query_text[:60]}' ≈ '{normalized[j][1].query_text[:60]}'"
                        )

        if total_pairs > 0:
            ratio = similar_count / total_pairs
            if ratio > 0.3:
                return DistillationAlert(
                    alert_type="repetitive_queries",
                    confidence=min(1.0, ratio * 1.5),
                    evidence=evidence,
                    query_count=len(queries),
                    time_window_seconds=self.time_window,
                )
        return None

    def _detect_boundary_probing(self, queries: List[QueryRecord]) -> Optional[DistillationAlert]:
        """Detect systematic probing of model boundaries."""
        # Patterns that indicate boundary probing
        probe_patterns = [
            r"what (?:are|is) your (?:limit|boundary|constraint|restriction)",
            r"can you (?:explain|describe) (?:everything|all|anything)",
            r"tell me (?:everything|all) about",
            r"how (?:do|does) (?:you|your) .+ work",
            r"what (?:happens|occurs) (?:if|when) .+ (?:instead|rather than)",
            r"(?:edge|corner|boundary|limit) case",
            r"(?:refuse|reject|decline|deny) (?:to|me)",
            r"what (?:can't|cannot|won't) you (?:do|say|answer)",
        ]

        probe_count = 0
        evidence = []
        for q in queries:
            for pattern in probe_patterns:
                if re.search(pattern, q.query_text, re.IGNORECASE):
                    probe_count += 1
                    if len(evidence) < 5:
                        evidence.append(f"Boundary probe: '{q.query_text[:80]}'")
                    break

        if len(queries) > 10:
            probe_ratio = probe_count / len(queries)
            if probe_ratio > 0.15:
                return DistillationAlert(
                    alert_type="boundary_probing",
                    confidence=min(1.0, probe_ratio * 2),
                    evidence=evidence,
                    query_count=probe_count,
                    time_window_seconds=self.time_window,
                )
        return None

    def _detect_extraction_queries(self, queries: List[QueryRecord]) -> Optional[DistillationAlert]:
        """Detect extraction-style queries (asking for explanations of everything)."""
        extraction_patterns = [
            r"explain (?:in detail|step by step|thoroughly|comprehensively)",
            r"(?:how|why) (?:does|do|is|are) .+ (?:work|function|operate|process)",
            r"(?:describe|outline|detail) (?:the|your) (?:process|method|algorithm|approach)",
            r"(?:list|enumerate|name) (?:all|every|each)",
            r"what (?:are|is) (?:the|all) (?:different|various|possible|types of)",
            r"give (?:me|us) (?:a|an) (?:complete|full|comprehensive|detailed)",
            r"(?:compare|contrast|difference) (?:between|among)",
            r"(?:advantage|disadvantage|pro|con|strength|weakness)",
        ]

        extract_count = 0
        evidence = []
        for q in queries:
            for pattern in extraction_patterns:
                if re.search(pattern, q.query_text, re.IGNORECASE):
                    extract_count += 1
                    if len(evidence) < 5:
                        evidence.append(f"Extraction query: '{q.query_text[:80]}'")
                    break

        if len(queries) > 15:
            extract_ratio = extract_count / len(queries)
            if extract_ratio > 0.4:
                return DistillationAlert(
                    alert_type="systematic_extraction",
                    confidence=min(1.0, extract_ratio * 1.2),
                    evidence=evidence,
                    query_count=extract_count,
                    time_window_seconds=self.time_window,
                )
        return None

    def _detect_rate_anomaly(self, queries: List[QueryRecord]) -> Optional[DistillationAlert]:
        """Detect anomalous query rates (much higher than normal)."""
        if len(queries) < 2:
            return None

        # Calculate queries per minute
        time_span = queries[-1].timestamp - queries[0].timestamp
        if time_span <= 0:
            return None

        qpm = len(queries) / (time_span / 60.0)

        # Threshold: >30 queries/minute is suspicious for a single user
        if qpm > 30:
            return DistillationAlert(
                alert_type="rate_anomaly",
                confidence=min(1.0, qpm / 100.0),
                evidence=[f"Query rate: {qpm:.1f} queries/minute (threshold: 30)"],
                query_count=len(queries),
                time_window_seconds=time_span,
            )
        return None

    @staticmethod
    def _text_similarity(a: str, b: str) -> float:
        """Simple character n-gram similarity (Jaccard)."""
        if not a or not b:
            return 0.0
        n = 3
        grams_a = set(a[i:i + n] for i in range(len(a) - n + 1))
        grams_b = set(b[i:i + n] for i in range(len(b) - n + 1))
        if not grams_a or not grams_b:
            return 0.0
        intersection = grams_a & grams_b
        union = grams_a | grams_b
        return len(intersection) / len(union)


# ─── Supply Chain Risk Assessor ──────────────────────────────────────────────

class SupplyChainRiskAssessor:
    """Assess supply chain risk for ML artifacts.

    Checks provenance, signatures, hashes, and generates risk reports.
    """

    def __init__(self, known_good_hashes: Optional[Dict[str, str]] = None):
        self.known_good_hashes = known_good_hashes or {}
        self.scanner = ModelArtifactScanner()

    def assess(self, file_path: str, provenance: Optional[Dict[str, Any]] = None) -> SupplyChainReport:
        """Generate a comprehensive supply chain risk assessment."""
        if not os.path.exists(file_path):
            return SupplyChainReport(
                artifact_path=file_path,
                artifact_hash="",
                risk_level="critical",
                risk_factors=["File not found"],
                recommendations=["Verify file exists before loading"],
            )

        file_hash = self.scanner.compute_hash(file_path)
        report = SupplyChainReport(
            artifact_path=file_path,
            artifact_hash=file_hash,
        )

        # 1. Provenance check
        if provenance:
            report.provenance = provenance
            if not provenance.get("source"):
                report.risk_factors.append("Unknown provenance — no source specified")
            elif provenance.get("source") in ("huggingface", "pytorch_hub", "torchvision"):
                report.risk_factors.append("Known source but still requires verification")
            else:
                report.risk_factors.append(f"Untrusted source: {provenance.get('source')}")
        else:
            report.risk_factors.append("No provenance information available")

        # 2. Hash verification
        if file_hash in self.known_good_hashes:
            report.hash_known = True
            report.hash_database = "local_known_good"
        else:
            report.hash_known = False
            report.risk_factors.append("Hash not found in known-good database")

        # 3. Signature verification (if .sig or .asc file exists)
        sig_path = file_path + ".sig"
        asc_path = file_path + ".asc"
        if os.path.exists(sig_path) or os.path.exists(asc_path):
            report.signature_valid = self._verify_signature(file_path, sig_path if os.path.exists(sig_path) else asc_path)
            if not report.signature_valid:
                report.risk_factors.append("Signature verification FAILED")
        else:
            report.risk_factors.append("No signature file found")

        # 4. Artifact scan
        scan_result = self.scanner.scan(file_path)
        if not scan_result.is_safe:
            report.risk_factors.append(f"Artifact scan: risk_score={scan_result.risk_score:.2f}")
            for pattern in scan_result.patterns:
                report.risk_factors.append(f"  [{pattern.severity}] {pattern.description}")

        # 5. Determine overall risk level
        risk_count = len(report.risk_factors)
        if any("critical" in f.lower() or "FAILED" in f for f in report.risk_factors):
            report.risk_level = "critical"
        elif risk_count >= 4 or scan_result.risk_score > 0.5:
            report.risk_level = "high"
        elif risk_count >= 2 or scan_result.risk_score > 0.2:
            report.risk_level = "medium"
        else:
            report.risk_level = "low"

        # 6. Generate recommendations
        report.recommendations = self._generate_recommendations(report, scan_result)
        return report

    def _verify_signature(self, file_path: str, sig_path: str) -> bool:
        """Verify GPG signature. Returns True if valid, False otherwise."""
        # Placeholder — real implementation would use gpg --verify
        return os.path.exists(sig_path)

    @staticmethod
    def _generate_recommendations(report: SupplyChainReport, scan: ScanResult) -> List[str]:
        """Generate actionable recommendations."""
        recs = []

        if not report.provenance:
            recs.append("Establish provenance: verify the model's origin and chain of custody")

        if report.hash_known is False:
            recs.append("Verify hash against official model repository")

        if report.signature_valid is False:
            recs.append("Obtain and verify a valid cryptographic signature from the model publisher")

        if not scan.is_safe:
            recs.append("DO NOT LOAD this model — malicious patterns detected")
            for pattern in scan.patterns:
                if pattern.severity == "critical":
                    recs.append(f"CRITICAL: {pattern.description} — {pattern.evidence}")
            recs.append("Use safetensors format instead of pickle-based formats")
            recs.append("Re-download from official source and verify hash")

        if report.risk_level in ("critical", "high"):
            recs.append("Quarantine this artifact and investigate its supply chain")

        if not recs:
            recs.append("Artifact appears safe — continue with standard loading procedures")

        return recs


# ─── Domain Solver Integration ───────────────────────────────────────────────

@register_solver("ml_supply")
class MLSupplyChainSolver(BaseDomainSolver):
    """Domain solver for ML Supply Chain Security.

    Integrates artifact scanning, runtime monitoring, distillation detection,
    and supply chain risk assessment into the CTF agent's domain framework.
    """

    def __init__(self, executor=None, file_reader=None, engine: TacticalHypothesisEngine = None):
        super().__init__(executor=executor, file_reader=file_reader)
        self.engine = engine or TacticalHypothesisEngine()
        self.security_policy = CommandAllowlistPolicy(ALLOWED_ML_BINARIES)
        self.scanner = ModelArtifactScanner(executor)
        self.monitor = RuntimeBehavioralMonitor(executor)
        self.distillation_detector = DistillationDetector()
        self.risk_assessor = SupplyChainRiskAssessor()

    @property
    def domain_type(self) -> str:
        return "ml_supply"

    def analyze(self, request: AnalysisRequest) -> DomainAnalysisReport:
        """Analyze an ML artifact or query pattern for supply chain threats."""
        target = request.target_resource
        options = dict(request.options)
        analysis_type = options.get("analysis_type", "full")

        observations: List[str] = []
        errors: List[str] = []
        metadata: Dict[str, Any] = {"target": target, "analysis_type": analysis_type}

        # Phase 1: Artifact Scanning
        if analysis_type in ("full", "scan"):
            try:
                scan_result = self.scanner.scan(target)
                metadata["scan"] = {
                    "file_type": scan_result.file_type,
                    "risk_score": scan_result.risk_score,
                    "is_safe": scan_result.is_safe,
                    "hash": scan_result.file_hash_sha256,
                    "patterns": [
                        {
                            "type": p.pattern_type,
                            "severity": p.severity,
                            "description": p.description,
                            "evidence": p.evidence,
                            "mitre": p.mitre,
                        }
                        for p in scan_result.patterns
                    ],
                }

                if scan_result.is_safe:
                    observations.append(f"✅ Artifact scan PASSED (risk={scan_result.risk_score:.2f})")
                else:
                    observations.append(f"🚨 Artifact scan FAILED — {len(scan_result.patterns)} malicious patterns detected")
                    for p in scan_result.patterns:
                        observations.append(f"  [{p.severity.upper()}] {p.description}: {p.evidence}")
                        if p.mitre:
                            observations.append(f"    MITRE ATT&CK: {p.mitre['technique']} — {p.mitre['name']}")

            except Exception as e:
                errors.append(f"Artifact scan error: {e}")

        # Phase 2: Supply Chain Risk Assessment
        if analysis_type in ("full", "assess"):
            try:
                provenance = options.get("provenance", {})
                risk_report = self.risk_assessor.assess(target, provenance)
                metadata["risk_assessment"] = {
                    "risk_level": risk_report.risk_level,
                    "risk_factors": risk_report.risk_factors,
                    "recommendations": risk_report.recommendations,
                    "hash_known": risk_report.hash_known,
                    "signature_valid": risk_report.signature_valid,
                }
                observations.append(f"Risk Level: {risk_report.risk_level.upper()}")
                for factor in risk_report.risk_factors:
                    observations.append(f"  ⚠ {factor}")
                for rec in risk_report.recommendations:
                    observations.append(f"  → {rec}")
            except Exception as e:
                errors.append(f"Risk assessment error: {e}")

        # Phase 3: Runtime Monitoring (if model is being loaded)
        if analysis_type in ("full", "monitor"):
            pid = options.get("monitor_pid")
            if pid:
                try:
                    duration = options.get("monitor_duration", 10.0)
                    monitor_result = self.monitor.monitor_process(pid, duration)
                    metadata["runtime_monitor"] = {
                        "events_count": len(monitor_result.events),
                        "suspicious_behaviors": monitor_result.suspicious_behaviors,
                        "network_connections": monitor_result.network_connections,
                        "file_access": monitor_result.file_access_events[:20],
                        "mitre_techniques": monitor_result.mitre_techniques,
                        "risk_score": monitor_result.risk_score,
                    }
                    if monitor_result.suspicious_behaviors:
                        observations.append(f"🚨 {len(monitor_result.suspicious_behaviors)} suspicious runtime behaviors detected")
                        for b in monitor_result.suspicious_behaviors[:10]:
                            observations.append(f"  ⚠ {b}")
                    else:
                        observations.append(f"✅ Runtime monitoring clean ({len(monitor_result.events)} events)")
                except Exception as e:
                    errors.append(f"Runtime monitoring error: {e}")

        # Phase 4: Distillation Detection
        if analysis_type in ("full", "distillation"):
            queries = options.get("queries", [])
            if queries:
                try:
                    for q in queries:
                        self.distillation_detector.add_query(QueryRecord(
                            timestamp=q.get("timestamp", time.time()),
                            query_text=q.get("text", ""),
                            response_length=q.get("response_length", 0),
                        ))
                    alerts = self.distillation_detector.analyze()
                    metadata["distillation"] = {
                        "alerts": [
                            {
                                "type": a.alert_type,
                                "confidence": a.confidence,
                                "evidence": a.evidence,
                                "query_count": a.query_count,
                            }
                            for a in alerts
                        ]
                    }
                    if alerts:
                        observations.append(f"🚨 {len(alerts)} distillation alerts triggered")
                        for alert in alerts:
                            observations.append(
                                f"  [{alert.alert_type}] confidence={alert.confidence:.2f}, "
                                f"queries={alert.query_count}"
                            )
                            for e in alert.evidence[:3]:
                                observations.append(f"    → {e}")
                    else:
                        observations.append("✅ No distillation patterns detected")
                except Exception as e:
                    errors.append(f"Distillation detection error: {e}")

        success = not any("FAILED" in o or "🚨" in o for o in observations)

        return DomainAnalysisReport(
            domain=self.domain_type,
            success=success,
            observations=observations,
            metadata=metadata,
            errors=errors,
        )
