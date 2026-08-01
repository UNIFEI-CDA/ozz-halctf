"""
Telemetry Sanitizer — Defense Against Poisoning via Ingested Telemetry

Inspired by:
  - "Poisoning the SOC: Prompt Injection via Ingested Telemetry" (Salesforce, DEF CON 34)

Before any tool processes logs/SIEM data, this module:
  - Sanitizes attacker-controlled fields
  - Escapes special characters that could enable prompt injection
  - Validates data structure before processing
  - Detects and neutralizes injection payloads in log data
"""

import json
import re
import logging
import html
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("ozz.telemetry.sanitizer")


# ============================================================
# Sanitization Result
# ============================================================

@dataclass
class SanitizationResult:
    """Result of sanitizing a value."""
    original: str
    sanitized: str
    was_modified: bool
    threats_found: list[str] = field(default_factory=list)
    fields_sanitized: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "original_length": len(self.original),
            "sanitized_length": len(self.sanitized),
            "was_modified": self.was_modified,
            "threats_found": self.threats_found,
            "fields_sanitized": self.fields_sanitized,
        }


# ============================================================
# Dangerous Patterns in Log/SIEM Data
# ============================================================

# Patterns that could be used to inject instructions via log fields
_LOG_INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Prompt injection via log fields
    (re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+(instructions|prompts)", re.I),
     "prompt_injection_ignore"),
    (re.compile(r"you\s+are\s+now\s+", re.I),
     "prompt_injection_role"),
    (re.compile(r"system\s*:\s*", re.I),
     "fake_system_role"),
    (re.compile(r"assistant\s*:\s*", re.I),
     "fake_assistant_role"),
    (re.compile(r"<\|(im_start|im_end)\|>", re.I),
     "chat_template_injection"),
    (re.compile(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", re.I),
     "llama_template_injection"),
    (re.compile(r"```\s*(system|json|python)", re.I),
     "markdown_injection"),

    # Control character injection
    (re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"),
     "control_characters"),

    # ANSI escape sequences (could manipulate terminal output)
    (re.compile(r"\x1b\[[0-9;]*[a-zA-Z]"),
     "ansi_escape_sequence"),

    # Unicode direction overrides (RTL/LTR attacks)
    (re.compile(r"[\u202a-\u202e\u2066-\u2069]"),
     "unicode_direction_override"),

    # Null bytes
    (re.compile(r"\\x00|%00"),
     "null_byte"),

    # Log format injection (fake log entries)
    (re.compile(r"(ERROR|WARN|INFO|DEBUG|CRITICAL)\s*[-:]\s*", re.I),
     "fake_log_level"),
]

# Characters that need escaping in log fields
_ESCAPE_MAP = {
    '\n': '\\n',
    '\r': '\\r',
    '\t': '\\t',
    '\0': '\\0',
    '\\': '\\\\',
    '"': '\\"',
    "'": "\\'",
    '`': '\\`',
    '{': '\\{',
    '}': '\\}',
    '<': '&lt;',
    '>': '&gt;',
}

# Maximum safe field lengths
_MAX_FIELD_LENGTHS = {
    "hostname": 253,
    "username": 64,
    "command": 4096,
    "output": 100000,
    "path": 4096,
    "url": 8192,
    "default": 10000,
}


# ============================================================
# Telemetry Sanitizer
# ============================================================

class TelemetrySanitizer:
    """
    Sanitizes attacker-controlled data before it enters the LLM context.

    Defense against "Poisoning the SOC" attacks where malicious data
    in SIEM/log fields contains prompt injection payloads.
    """

    def __init__(self, strict: bool = True):
        """
        Args:
            strict: If True, aggressively neutralize suspicious patterns.
                    If False, only escape control characters.
        """
        self.strict = strict
        self._sanitization_count = 0
        self._threat_count = 0

    def sanitize_value(self, value: Any, field_name: str = "default") -> SanitizationResult:
        """
        Sanitize a single value.

        Args:
            value: The value to sanitize (will be converted to string)
            field_name: Field name for length limits

        Returns:
            SanitizationResult with original and sanitized values
        """
        if value is None:
            return SanitizationResult(
                original="", sanitized="", was_modified=False
            )

        original = str(value)
        threats = []
        sanitized = original

        # 1. Remove control characters
        sanitized = self._strip_control_chars(sanitized)

        # 2. Detect injection patterns
        for pattern, threat_name in _LOG_INJECTION_PATTERNS:
            if pattern.search(sanitized):
                threats.append(threat_name)

        # 3. Escape dangerous characters
        if self.strict:
            sanitized = self._escape_dangerous_chars(sanitized)

        # 4. Neutralize detected injections
        if threats and self.strict:
            sanitized = self._neutralize_injections(sanitized)

        # 5. Enforce length limits
        max_len = _MAX_FIELD_LENGTHS.get(field_name, _MAX_FIELD_LENGTHS["default"])
        if len(sanitized) > max_len:
            sanitized = sanitized[:max_len] + "...[TRUNCATED]"
            threats.append("field_truncated")

        self._sanitization_count += 1
        if threats:
            self._threat_count += 1

        was_modified = sanitized != original
        return SanitizationResult(
            original=original,
            sanitized=sanitized,
            was_modified=was_modified,
            threats_found=threats,
            fields_sanitized=[field_name] if was_modified else [],
        )

    def sanitize_dict(self, data: dict, field_prefix: str = "") -> SanitizationResult:
        """
        Recursively sanitize all values in a dictionary.

        Args:
            data: Dictionary to sanitize
            field_prefix: Prefix for field name tracking

        Returns:
            SanitizationResult with sanitized dict as sanitized field
        """
        all_threats = []
        all_fields = []
        sanitized_dict = {}

        for key, value in data.items():
            full_key = f"{field_prefix}.{key}" if field_prefix else key

            if isinstance(value, dict):
                result = self.sanitize_dict(value, full_key)
                sanitized_dict[key] = json.loads(result.sanitized) if result.sanitized else {}
                all_threats.extend(result.threats_found)
                all_fields.extend(result.fields_sanitized)
            elif isinstance(value, list):
                sanitized_list = []
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        result = self.sanitize_dict(item, f"{full_key}[{i}]")
                        sanitized_list.append(json.loads(result.sanitized) if result.sanitized else {})
                    else:
                        result = self.sanitize_value(item, full_key)
                        sanitized_list.append(result.sanitized)
                    all_threats.extend(result.threats_found)
                    all_fields.extend(result.fields_sanitized)
                sanitized_dict[key] = sanitized_list
            else:
                result = self.sanitize_value(value, key)
                sanitized_dict[key] = result.sanitized
                all_threats.extend(result.threats_found)
                all_fields.extend(result.fields_sanitized)

        return SanitizationResult(
            original=json.dumps(data, default=str, ensure_ascii=False),
            sanitized=json.dumps(sanitized_dict, default=str, ensure_ascii=False),
            was_modified=len(all_threats) > 0 or len(all_fields) > 0,
            threats_found=all_threats,
            fields_sanitized=all_fields,
        )

    def sanitize_log_entry(self, log_entry: str) -> SanitizationResult:
        """
        Sanitize a raw log entry (syslog, JSON log, etc.).

        Handles both structured (JSON) and unstructured log formats.
        """
        stripped = log_entry.strip()

        # Try JSON parsing first
        if stripped.startswith('{'):
            try:
                data = json.loads(stripped)
                return self.sanitize_dict(data)
            except json.JSONDecodeError:
                pass

        # Unstructured log — sanitize the raw text
        return self.sanitize_value(stripped, "log_entry")

    def sanitize_tool_output(self, tool_name: str, output: str) -> SanitizationResult:
        """
        Sanitize tool output before it enters the LLM context.

        This is the critical defense against log/SIEM poisoning attacks.
        Tool outputs can contain attacker-controlled data (hostnames,
        web content, etc.) that embeds prompt injection payloads.
        """
        result = self.sanitize_value(output, "output")

        # Additional tool-specific sanitization
        if tool_name in ("nmap", "whatweb", "nikto"):
            # These tools may include attacker-controlled hostnames/content
            result = self._sanitize_network_output(result)
        elif tool_name in ("curl", "wget", "ffuf", "gobuster"):
            # Web responses can contain arbitrary content
            result = self._sanitize_web_output(result)
        elif tool_name in ("grep", "strings"):
            # File content can contain anything
            result = self._sanitize_file_content(result)

        return result

    def get_stats(self) -> dict:
        """Get sanitization statistics."""
        return {
            "total_sanitizations": self._sanitization_count,
            "threats_detected": self._threat_count,
            "detection_rate": (
                self._threat_count / self._sanitization_count
                if self._sanitization_count > 0 else 0.0
            ),
        }

    # ── Internal Methods ──────────────────────────────────────────────

    def _strip_control_chars(self, text: str) -> str:
        """Remove dangerous control characters while preserving readable ones."""
        return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)

    def _escape_dangerous_chars(self, text: str) -> str:
        """Escape characters that could be used for injection."""
        for char, replacement in _ESCAPE_MAP.items():
            text = text.replace(char, replacement)
        return text

    def _neutralize_injections(self, text: str) -> str:
        """Neutralize detected injection patterns by wrapping in quotes."""
        # Wrap suspicious segments in neutralizing markers
        for pattern, threat_name in _LOG_INJECTION_PATTERNS:
            if pattern.search(text):
                # Replace with quoted/escaped version
                text = pattern.sub(lambda m: f"[NEUTRALIZED:{m.group(0)}]", text)
        return text

    def _sanitize_network_output(self, result: SanitizationResult) -> SanitizationResult:
        """Additional sanitization for network tool output."""
        text = result.sanitized
        # Remove ANSI escape codes from nmap output
        text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
        # Neutralize service info that might contain injection
        text = re.sub(r'(?i)(service\s*info\s*:)', r'[SANITIZED]\1', text)
        result.sanitized = text
        return result

    def _sanitize_web_output(self, result: SanitizationResult) -> SanitizationResult:
        """Additional sanitization for web tool output."""
        text = result.sanitized
        # Strip HTML tags that could hide injection
        text = re.sub(r'<script[^>]*>.*?</script>', '[SCRIPT_REMOVED]', text, flags=re.S | re.I)
        text = re.sub(r'<[^>]+on\w+\s*=', '[EVENT_REMOVED]<', text, flags=re.I)
        # Remove data URIs that could encode payloads
        text = re.sub(r'data:[^,]+;base64,[A-Za-z0-9+/=]+', '[DATA_URI_REMOVED]', text)
        result.sanitized = text
        return result

    def _sanitize_file_content(self, result: SanitizationResult) -> SanitizationResult:
        """Additional sanitization for file content tool output."""
        text = result.sanitized
        # Encode any remaining non-printable characters
        text = ''.join(c if c.isprintable() or c in '\n\t' else f'\\x{ord(c):02x}' for c in text)
        result.sanitized = text
        return result
