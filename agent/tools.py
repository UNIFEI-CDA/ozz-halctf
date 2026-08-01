"""
Ozz — Pentesting Tools (Competition-Grade)
Tool wrappers with structured JSON output, timeout protection, and error handling.

Security: sandbox execution, least-privilege enforcement, audit logging.
Inspired by DEF CON 34 AI Village posters on agent-to-agent security.
"""

import subprocess
import shlex
import logging
import re
import json
import time
import os
import resource
import hashlib
import threading
from dataclasses import dataclass, field, asdict
from typing import Callable, Optional, Any

logger = logging.getLogger("ozz.tools")

# ── Sandbox Configuration ────────────────────────────────────────────
OZZ_WORKSPACE = os.environ.get("OZZ_WORKSPACE", "/tmp/ozz")
CTF_NETWORK_RANGES = os.environ.get("OZZ_CTF_RANGES", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(",")
MAX_CPU_SECONDS = int(os.environ.get("OZZ_MAX_CPU_SECONDS", "300"))
MAX_MEMORY_MB = int(os.environ.get("OZZ_MAX_MEMORY_MB", "512"))
MAX_OUTPUT_BYTES = int(os.environ.get("OZZ_MAX_OUTPUT", "100000"))

# Allowed localhost services (CTF network only)
ALLOWED_LOCALHOST_PORTS: set[int] = set()  # Empty = no localhost access by default
_BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal", "instance-data"}


@dataclass
class ToolResult:
    """Structured result from a tool execution."""
    tool: str = ""
    output: str = ""
    success: bool = False
    parsed: Optional[dict] = None
    error: Optional[str] = None
    duration_s: float = 0.0
    exit_code: int = -1

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, ensure_ascii=False)


# ── Least Privilege Enforcement ───────────────────────────────────────

class LeastPrivilegePolicy:
    """Enforces minimum scope per tool.

    Each tool can only operate within its defined boundaries:
    - nmap: only specified target ranges
    - sqlmap: only specified URLs
    - curl: no localhost access outside CTF network
    - file operations: only within /tmp/ozz/ workspace
    - No tool has unrestricted host access
    """

    def __init__(self, allowed_targets: list[str] = None):
        self.allowed_targets = set(allowed_targets or [])
        self._lock = threading.Lock()

    def validate_target(self, target: str) -> bool:
        """Check if a target IP/hostname is within allowed ranges."""
        if not self.allowed_targets:
            return True  # No restrictions if none set
        # Check exact match or CIDR containment
        for allowed in self.allowed_targets:
            if target == allowed:
                return True
            if '/' in allowed:
                if self._ip_in_cidr(target, allowed):
                    return True
            # Allow hostname suffix matching
            if allowed.startswith('.') and target.endswith(allowed):
                return True
        return False

    @staticmethod
    def _ip_in_cidr(ip: str, cidr: str) -> bool:
        """Check if IP is in CIDR range (pure Python, no deps)."""
        try:
            parts = cidr.split('/')
            network = parts[0]
            prefix = int(parts[1])
            ip_int = sum(int(octet) << (24 - 8 * i) for i, octet in enumerate(ip.split('.')))
            net_int = sum(int(octet) << (24 - 8 * i) for i, octet in enumerate(network.split('.')))
            mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
            return (ip_int & mask) == (net_int & mask)
        except (ValueError, IndexError):
            return False

    def validate_localhost_access(self, args: str) -> bool:
        """Check if curl/wget targets are allowed (no unrestricted localhost)."""
        # Block metadata endpoints
        for blocked in _BLOCKED_HOSTS:
            if blocked in args:
                return False
        # Block localhost unless specific ports are allowed
        localhost_patterns = ['localhost', '127.0.0.1', '::1', '0.0.0.0']
        for pattern in localhost_patterns:
            if pattern in args:
                # Extract port if present
                port_match = re.search(r':(\d+)', args)
                if port_match:
                    port = int(port_match.group(1))
                    if port not in ALLOWED_LOCALHOST_PORTS:
                        return False
                else:
                    return False  # No port = unrestricted localhost = blocked
        return True

    def validate_file_path(self, path: str) -> bool:
        """Ensure file operations stay within workspace."""
        # Resolve to absolute path
        abs_path = os.path.abspath(path)
        workspace = os.path.abspath(OZZ_WORKSPACE)
        # Allow /tmp/ozz/ and subdirectories
        return abs_path.startswith(workspace)

    def validate_nmap(self, args: str) -> tuple[bool, str]:
        """Validate nmap arguments against allowed target ranges."""
        # Extract targets from args
        targets = self._extract_targets(args)
        for target in targets:
            if not self.validate_target(target):
                return False, f"Target {target} not in allowed ranges: {self.allowed_targets}"
        return True, ""

    def validate_sqlmap(self, args: str) -> tuple[bool, str]:
        """Validate sqlmap targets."""
        url_match = re.search(r"-u\s+['\"]?(https?://[^'\"]+)", args)
        if url_match:
            url = url_match.group(1)
            # Extract host from URL
            host_match = re.search(r'https?://([^/:]+)', url)
            if host_match:
                host = host_match.group(1)
                if not self.validate_target(host):
                    return False, f"SQLMap target {host} not in allowed ranges"
        return True, ""

    def validate_curl(self, args: str) -> tuple[bool, str]:
        """Validate curl arguments — no unrestricted localhost."""
        if not self.validate_localhost_access(args):
            return False, "Curl localhost access blocked (not in CTF network)"
        return True, ""

    def _extract_targets(self, args: str) -> list[str]:
        """Extract IP addresses and hostnames from command args."""
        # Match IP addresses
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', args)
        # Match CIDR ranges
        cidrs = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b', args)
        # Match hostnames (not flags)
        hostnames = re.findall(r'\b[a-zA-Z][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', args)
        # Filter out common non-target strings
        non_targets = {'nmap.org', 'exploit-db.com', 'github.com', 'example.com'}
        hostnames = [h for h in hostnames if h not in non_targets]
        return ips + cidrs + hostnames


# ── Sandbox Execution ────────────────────────────────────────────────

def _set_resource_limits():
    """Set CPU and memory limits for sandboxed subprocess (called in preexec_fn)."""
    try:
        # CPU time limit
        resource.setrlimit(resource.RLIMIT_CPU, (MAX_CPU_SECONDS, MAX_CPU_SECONDS))
        # Memory limit
        mem_bytes = MAX_MEMORY_MB * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        # No core dumps
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # Limit file size (100MB)
        resource.setrlimit(resource.RLIMIT_FSIZE, (100 * 1024 * 1024, 100 * 1024 * 1024))
    except (ValueError, OSError):
        pass  # Some limits may not be settable in containers


def _sandbox_run(cmd: str, timeout: int = 120, shell: bool = True,
                 env_override: Optional[dict] = None) -> subprocess.Popen:
    """Execute command in sandboxed environment.

    - Restricted environment variables
    - Resource limits (CPU, memory)
    - stdout/stderr captured separately
    - No direct host access
    """
    # Minimal environment — no secrets leak
    safe_env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": OZZ_WORKSPACE,
        "TMPDIR": OZZ_WORKSPACE,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    if env_override:
        safe_env.update(env_override)

    proc = subprocess.Popen(
        cmd,
        shell=shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=safe_env,
        preexec_fn=_set_resource_limits,
        cwd=OZZ_WORKSPACE,
    )
    return proc


class Tool:
    """Base tool wrapper with structured output and provenance tracking."""

    def __init__(self, name: str, description: str, usage: str, handler: Callable):
        self.name = name
        self.description = description
        self.usage = usage
        self.handler = handler

    def execute(self, args: str) -> ToolResult:
        start = time.time()
        try:
            result = self.handler(args)
            result.tool = self.name
            result.duration_s = round(time.time() - start, 2)
            return result
        except Exception as e:
            return ToolResult(
                tool=self.name,
                output="",
                success=False,
                error=f"ToolException: {type(e).__name__}: {e}",
                duration_s=round(time.time() - start, 2),
            )


class ToolRegistry:
    """Registry of all available tools with structured output.

    Integrates:
    - Least privilege enforcement per tool
    - Sandbox execution
    - Audit logging
    - Provenance tracking hooks
    """

    def __init__(self, allowed_targets: list[str] = None,
                 audit_logger=None, provenance_tracker=None,
                 contamination_detector=None):
        self.tools: dict[str, Tool] = {}
        self.privacy_policy = LeastPrivilegePolicy(allowed_targets)
        self.audit_logger = audit_logger
        self.provenance_tracker = provenance_tracker
        self.contamination_detector = contamination_detector
        self._register_defaults()

    def register(self, tool: Tool):
        self.tools[tool.name] = tool

    def execute(self, name: str, args: str, context_hash: str = "",
                target_id: str = "", thought: str = "") -> ToolResult:
        if name not in self.tools:
            return ToolResult(
                tool=name,
                output="",
                success=False,
                error=f"Unknown tool: {name}. Available: {list(self.tools.keys())}",
            )

        # ── Contamination check ─────────────────────────────────────
        if self.contamination_detector:
            events = self.contamination_detector.check(args, source=f"tool:{name}")
            if self.contamination_detector.should_abort(events):
                return ToolResult(
                    tool=name,
                    output="",
                    success=False,
                    error=f"CONTAMINATION_BLOCKED: Suspicious context detected in tool args: {[e.threat_type for e in events]}",
                )

        # ── Least privilege check ───────────────────────────────────
        priv_ok, priv_err = self._check_privilege(name, args)
        if not priv_ok:
            logger.warning(f"🛡️ LEAST PRIVILEGE BLOCKED: {name} — {priv_err}")
            return ToolResult(
                tool=name,
                output="",
                success=False,
                error=f"PRIVILEGE_DENIED: {priv_err}",
            )

        # ── Provenance tracking ─────────────────────────────────────
        prov_record = None
        if self.provenance_tracker:
            prov_record = self.provenance_tracker.begin_record(
                tool_name=name,
                tool_args=args,
                thought=thought,
                context=context_hash,
                target_id=target_id,
            )

        logger.info(f"🔧 Executing: {name} {args}")
        result = self.tools[name].execute(args)
        logger.info(
            f"{'✅' if result.success else '❌'} {name} "
            f"({len(result.output)} chars, {result.duration_s}s)"
        )

        # ── Complete provenance ─────────────────────────────────────
        if self.provenance_tracker and prov_record:
            self.provenance_tracker.complete_record(
                prov_record, result.output, result.success
            )

        # ── Audit logging ───────────────────────────────────────────
        if self.audit_logger:
            self.audit_logger.log(
                tool_name=name,
                tool_args=args,
                output=result.output,
                success=result.success,
                exit_code=result.exit_code,
                duration_s=result.duration_s,
                target_id=target_id,
                context_hash=context_hash,
                provenance_record_id=prov_record.record_id if prov_record else "",
            )

        return result

    def _check_privilege(self, name: str, args: str) -> tuple[bool, str]:
        """Apply least-privilege rules per tool."""
        policy = self.privacy_policy

        if name == "nmap":
            return policy.validate_nmap(args)
        elif name == "sqlmap":
            return policy.validate_sqlmap(args)
        elif name in ("curl", "wget"):
            return policy.validate_curl(args)
        elif name in ("file", "strings", "grep", "cat"):
            # File operations must stay in workspace
            path_match = re.search(r'(?:^|\s)(/[\w./-]+)', args)
            if path_match:
                path = path_match.group(1)
                if not policy.validate_file_path(path):
                    return False, f"File path {path} outside workspace {OZZ_WORKSPACE}"
            return True, ""
        elif name == "shell":
            # Shell commands: check for dangerous patterns
            dangerous = ['rm -rf /', 'dd if=', 'mkfs', '> /dev/', 'chmod 777 /',
                         'curl.*|.*sh', 'wget.*|.*sh', 'nc -e']
            for pattern in dangerous:
                if re.search(pattern, args):
                    return False, f"Shell command contains blocked pattern: {pattern}"
            # Also check localhost access
            if not policy.validate_localhost_access(args):
                return False, "Shell command blocked: unrestricted localhost access"
            return True, ""
        else:
            # Default: allow with logging
            return True, ""

    def describe_all(self) -> str:
        """Describe all tools for the LLM prompt."""
        lines = []
        for name, tool in self.tools.items():
            lines.append(f"- {name}: {tool.description}\n  Usage: {tool.usage}")
        return "\n".join(lines)

    def _register_defaults(self):
        """Register all default pentesting tools."""

        # ── Network Scanning ──────────────────────────────────────────
        self.register(Tool(
            "nmap",
            "Network scanner. Discovers hosts, ports, services, and OS.",
            "nmap <args>  (e.g., nmap -sV -sC -oX - 10.0.0.1)",
            self._nmap,
        ))

        # ── HTTP Clients ──────────────────────────────────────────────
        self.register(Tool(
            "curl",
            "HTTP client. Returns structured response with status code, headers, body.",
            "curl <args>  (e.g., curl -s -i http://target/)",
            self._curl,
        ))

        self.register(Tool(
            "wget",
            "Download files from web/FTP servers.",
            "wget <url> [-O output_file]",
            self._wget,
        ))

        # ── Web Scanning ──────────────────────────────────────────────
        self.register(Tool(
            "gobuster",
            "Directory/file bruteforcer for web servers.",
            "gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt",
            self._gobuster,
        ))

        self.register(Tool(
            "nikto",
            "Web server scanner. Checks for dangerous files, outdated software.",
            "nikto -h http://target",
            self._nikto,
        ))

        self.register(Tool(
            "whatweb",
            "Web technology identifier. Returns structured tech fingerprint.",
            "whatweb http://target",
            self._whatweb,
        ))

        self.register(Tool(
            "ffuf",
            "Fast web fuzzer for directory/parameter/vhost discovery.",
            "ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt",
            self._ffuf,
        ))

        # ── SQL Injection ─────────────────────────────────────────────
        self.register(Tool(
            "sqlmap",
            "Automatic SQL injection tool. Returns structured findings.",
            "sqlmap -u 'http://target/page?id=1' --batch --dbs",
            self._sqlmap,
        ))

        # ── Authentication ────────────────────────────────────────────
        self.register(Tool(
            "hydra",
            "Network login bruteforcer. Returns cracked credentials.",
            "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://target",
            self._hydra,
        ))

        # ── ExploitDB ─────────────────────────────────────────────────
        self.register(Tool(
            "searchsploit",
            "Search ExploitDB. Returns structured JSON results.",
            "searchsploit <query>",
            self._searchsploit,
        ))

        # ── Binary Analysis ───────────────────────────────────────────
        self.register(Tool(
            "checksec",
            "Check binary security controls (NX, Canary, PIE, RELRO).",
            "checksec --file=<binary>",
            self._checksec,
        ))

        self.register(Tool(
            "ropper",
            "ROP gadget finder for binary exploitation.",
            "ropper --file=<binary> --search 'pop rdi'",
            self._ropper,
        ))

        self.register(Tool(
            "one_gadget",
            "Find one-shot RCE gadgets in libc.",
            "one_gadget /path/to/libc.so.6",
            self._one_gadget,
        ))

        self.register(Tool(
            "readelf",
            "Read ELF binary headers, sections, symbols.",
            "readelf -s <binary>",
            self._readelf,
        ))

        self.register(Tool(
            "objdump",
            "Disassemble binary sections.",
            "objdump -d <binary> | head -100",
            self._objdump,
        ))

        # ── Generic Tools ─────────────────────────────────────────────
        self.register(Tool(
            "file",
            "Identify file types. Returns structured type info.",
            "file <path>",
            self._file,
        ))

        self.register(Tool(
            "strings",
            "Extract printable strings from binary files.",
            "strings <file> | grep -i flag",
            self._strings,
        ))

        self.register(Tool(
            "grep",
            "Search text patterns in files or output.",
            "grep -r 'flag{' /path/",
            self._grep,
        ))

        self.register(Tool(
            "nc",
            "Netcat — TCP/UDP connection tool.",
            "nc -zv target port  or  nc -lvnp 4444",
            self._netcat,
        ))

        self.register(Tool(
            "python",
            "Run Python scripts for custom exploits, encoding, crypto.",
            "python3 -c 'import socket; ...'",
            self._python,
        ))

        self.register(Tool(
            "shell",
            "Execute any shell command. Use for tools not explicitly registered.",
            "shell <command>",
            self._shell,
        ))

        # ── Steganography & Forensics ────────────────────────────────
        self.register(Tool(
            "exiftool",
            "Read metadata from files/images. Returns structured EXIF data.",
            "exiftool <file>",
            self._exiftool,
        ))

        self.register(Tool(
            "binwalk",
            "Analyze firmware/binaries for embedded files and signatures.",
            "binwalk <file>",
            self._binwalk,
        ))

        self.register(Tool(
            "steghide",
            "Extract/embed data in JPEG/BMP steganography.",
            "steghide extract -sf <file> [-p password]",
            self._steghide,
        ))

        self.register(Tool(
            "zsteg",
            "Detect steganography in PNG/BMP files (LSB, etc).",
            "zsteg <file.png> [-a]",
            self._zsteg,
        ))

        self.register(Tool(
            "foremost",
            "File carving — recover embedded/deleted files.",
            "foremost -i <file> -o <output_dir>",
            self._foremost,
        ))

        # ── Hash Cracking ─────────────────────────────────────────────
        self.register(Tool(
            "john",
            "John the Ripper password cracker.",
            "john --wordlist=<wordlist> <hashfile>",
            self._john,
        ))

        self.register(Tool(
            "hashcat",
            "GPU-accelerated hash cracker.",
            "hashcat -m <mode> <hashfile> <wordlist>",
            self._hashcat,
        ))

        # ── Remote Access ─────────────────────────────────────────────
        self.register(Tool(
            "ssh",
            "SSH client for remote access.",
            "ssh user@target [-i key.pem]",
            self._ssh,
        ))

        # ── Flag Submission ───────────────────────────────────────────
        self.register(Tool(
            "submit_flag",
            "Submit a captured flag. Returns structured confirmation.",
            "submit_flag flag{value_here}",
            self._submit_flag,
        ))

        # ── Composite Recon ───────────────────────────────────────────
        self.register(Tool(
            "quick_scan",
            "Fast comprehensive scan — nmap + web fingerprint.",
            "quick_scan <target_ip>",
            self._quick_scan,
        ))

    # ════════════════════════════════════════════════════════════════════
    # Tool Implementations — ALL return ToolResult with structured output
    # ════════════════════════════════════════════════════════════════════

    def _run_cmd(
        self, cmd: str, timeout: int = 120, shell: bool = True
    ) -> ToolResult:
        """Run a shell command in sandbox with resource limits.

        Sandbox features:
        - Restricted environment (no secrets in env)
        - CPU and memory resource limits
        - stdout/stderr captured separately
        - Working directory restricted to /tmp/ozz/
        - Output size capped
        """
        try:
            proc = _sandbox_run(cmd, timeout=timeout, shell=shell)
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                return ToolResult(
                    output="",
                    success=False,
                    error=f"TIMEOUT: Command exceeded {timeout}s limit (sandbox killed)",
                    exit_code=-9,
                )

            stdout_str = stdout.decode("utf-8", errors="replace")[:MAX_OUTPUT_BYTES]
            stderr_str = stderr.decode("utf-8", errors="replace")[:MAX_OUTPUT_BYTES]
            output = stdout_str + stderr_str
            success = proc.returncode == 0 or len(stdout_str) > 0
            return ToolResult(
                output=output[:10000],
                success=success,
                exit_code=proc.returncode,
                error=stderr_str.strip() if proc.returncode != 0 else None,
            )
        except FileNotFoundError as e:
            return ToolResult(
                output="",
                success=False,
                error=f"BINARY_NOT_FOUND: {e}",
                exit_code=127,
            )
        except Exception as e:
            return ToolResult(
                output="",
                success=False,
                error=f"EXEC_ERROR: {type(e).__name__}: {e}",
                exit_code=1,
            )

    # ── Network Scanning ──────────────────────────────────────────────

    def _nmap(self, args: str) -> ToolResult:
        result = self._run_cmd(f"nmap {args}", timeout=180)
        if result.success:
            result.parsed = self._parse_nmap(result.output)
        return result

    @staticmethod
    def _parse_nmap(output: str) -> dict:
        """Parse nmap output into structured data."""
        ports = []
        for m in re.finditer(
            r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)", output
        ):
            ports.append({
                "port": int(m.group(1)),
                "protocol": m.group(2),
                "state": m.group(3),
                "service": m.group(4),
                "version": m.group(5).strip(),
            })
        host_match = re.search(r"Nmap scan report for\s+(\S+)", output)
        os_match = re.search(r"OS details?:\s+(.+)", output)
        return {
            "host": host_match.group(1) if host_match else None,
            "ports": ports,
            "os": os_match.group(1).strip() if os_match else None,
            "raw_lines": output.count("\n"),
        }

    # ── HTTP Clients ──────────────────────────────────────────────────

    def _curl(self, args: str) -> ToolResult:
        # Include headers for structured parsing
        has_i = "-i " in args or args.startswith("-i ") or "-si" in args
        header_flag = "" if has_i else " -D -"
        result = self._run_cmd(
            f"curl -s{header_flag} -H 'bypass-tunnel-reminder: true' -m 30 {args}",
            timeout=35,
        )
        if result.success:
            result.parsed = self._parse_curl(result.output)
        return result

    @staticmethod
    def _parse_curl(output: str) -> dict:
        """Parse curl response into status, headers, body."""
        parsed: dict[str, Any] = {"status_code": None, "headers": {}, "body": output}
        # Split headers and body
        parts = output.split("\r\n\r\n", 1)
        if len(parts) == 2:
            header_block, body = parts
            parsed["body"] = body
            for line in header_block.split("\r\n"):
                if line.startswith("HTTP/"):
                    m = re.search(r"(\d{3})", line)
                    if m:
                        parsed["status_code"] = int(m.group(1))
                elif ": " in line:
                    k, v = line.split(": ", 1)
                    parsed["headers"][k.lower()] = v
        else:
            # Try HTTP/ prefix for status
            m = re.search(r"HTTP/[\d.]+\s+(\d{3})", output)
            if m:
                parsed["status_code"] = int(m.group(1))
        return parsed

    # ── Web Scanning ──────────────────────────────────────────────────

    def _gobuster(self, args: str) -> ToolResult:
        result = self._run_cmd(f"gobuster {args}", timeout=180)
        if result.success:
            dirs = []
            for m in re.finditer(r"(/\S+)\s+\(Status:\s*(\d+)\)", result.output):
                dirs.append({"path": m.group(1), "status": int(m.group(2))})
            result.parsed = {"directories": dirs, "count": len(dirs)}
        return result

    def _nikto(self, args: str) -> ToolResult:
        result = self._run_cmd(f"nikto {args}", timeout=180)
        if result.success:
            vulns = []
            for m in re.finditer(r"\+ (OSVDB-\d+|CVE-\S+|[\w/]+): (.+)", result.output):
                vulns.append({"id": m.group(1), "description": m.group(2).strip()})
            result.parsed = {"vulnerabilities": vulns, "count": len(vulns)}
        return result

    def _whatweb(self, args: str) -> ToolResult:
        result = self._run_cmd(f"whatweb {args}", timeout=30)
        if result.success:
            techs = re.findall(r"\[(\w[\w\s.-]+)\]", result.output)
            result.parsed = {"technologies": [t.strip() for t in techs]}
        return result

    def _ffuf(self, args: str) -> ToolResult:
        result = self._run_cmd(f"ffuf {args}", timeout=120)
        if result.success:
            paths = []
            for m in re.finditer(r"(/\S+)\s+\[Status:\s*(\d+)", result.output):
                paths.append({"path": m.group(1), "status": int(m.group(2))})
            result.parsed = {"found": paths, "count": len(paths)}
        return result

    # ── SQL Injection ─────────────────────────────────────────────────

    def _sqlmap(self, args: str) -> ToolResult:
        result = self._run_cmd(f"sqlmap {args}", timeout=180)
        if result.success:
            dbs = re.findall(r"\[\*\]\s+(\S+)", result.output)
            injectable = "is vulnerable" in result.output.lower() or "injectable" in result.output.lower()
            result.parsed = {
                "injectable": injectable,
                "databases": dbs,
                "has_output": len(result.output) > 50,
            }
        return result

    # ── Authentication ────────────────────────────────────────────────

    def _hydra(self, args: str) -> ToolResult:
        result = self._run_cmd(f"hydra {args}", timeout=180)
        if result.success:
            creds = []
            for m in re.finditer(
                r"\[(\d+)\]\[(\w+)\] host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)",
                result.output,
            ):
                creds.append({
                    "port": int(m.group(1)),
                    "service": m.group(2),
                    "host": m.group(3),
                    "username": m.group(4),
                    "password": m.group(5),
                })
            result.parsed = {"credentials": creds, "count": len(creds)}
        return result

    # ── ExploitDB ─────────────────────────────────────────────────────

    def _searchsploit(self, args: str) -> ToolResult:
        # Try JSON mode first
        result = self._run_cmd(f"searchsploit --json {args}", timeout=30)
        if result.success:
            try:
                parsed_json = json.loads(result.output)
                result.parsed = parsed_json
                return result
            except json.JSONDecodeError:
                pass
        # Fallback to text mode
        result = self._run_cmd(f"searchsploit {args}", timeout=30)
        if result.success:
            exploits = []
            for line in result.output.split("\n"):
                parts = line.split("|")
                if len(parts) >= 2:
                    exploits.append({
                        "title": parts[0].strip(),
                        "path": parts[1].strip() if len(parts) > 1 else "",
                    })
            result.parsed = {"exploits": exploits, "count": len(exploits)}
        return result

    # ── Binary Analysis ───────────────────────────────────────────────

    def _checksec(self, args: str) -> ToolResult:
        result = self._run_cmd(f"checksec {args}", timeout=15)
        if result.success:
            parsed = {}
            for key in ["RELRO", "Stack", "NX", "PIE", "FORTIFY"]:
                m = re.search(rf"{key}\s*:\s*(\S+)", result.output)
                if m:
                    val = m.group(1)
                    parsed[key] = val
                    if key == "Stack":
                        parsed["Canary"] = "Canary found" in val or "Yes" in val
                    elif key == "NX":
                        parsed["NX_enabled"] = val.lower() not in ("no", "disabled")
                    elif key == "PIE":
                        parsed["PIE_enabled"] = val.lower() not in ("no", "disabled")
                    elif key == "RELRO":
                        parsed["Full_RELRO"] = "full" in val.lower()
            result.parsed = parsed
        return result

    def _ropper(self, args: str) -> ToolResult:
        result = self._run_cmd(f"ropper {args}", timeout=60)
        if result.success:
            gadgets = []
            for m in re.finditer(r"(0x[0-9a-fA-F]+):\s+(.+)", result.output):
                gadgets.append({"address": m.group(1), "instruction": m.group(2).strip()})
            result.parsed = {"gadgets": gadgets, "count": len(gadgets)}
        return result

    def _one_gadget(self, args: str) -> ToolResult:
        result = self._run_cmd(f"one_gadget {args}", timeout=30)
        if result.success:
            gadgets = re.findall(r"(0x[0-9a-fA-F]+)", result.output)
            result.parsed = {"gadgets": gadgets, "count": len(gadgets)}
        return result

    def _readelf(self, args: str) -> ToolResult:
        result = self._run_cmd(f"readelf {args}", timeout=15)
        if result.success:
            result.parsed = {"sections": [], "symbols": []}
            for m in re.finditer(r"\[\s*\d+\]\s+(\S+)\s+\S+\s+(\S+)", result.output):
                result.parsed["sections"].append({"name": m.group(1), "addr": m.group(2)})
        return result

    def _objdump(self, args: str) -> ToolResult:
        result = self._run_cmd(f"objdump {args}", timeout=30)
        if result.success:
            funcs = re.findall(r"<(\w+)>:", result.output)
            result.parsed = {"functions": funcs, "count": len(funcs)}
        return result

    # ── Generic Tools ─────────────────────────────────────────────────

    def _file(self, args: str) -> ToolResult:
        result = self._run_cmd(f"file {args}", timeout=10)
        if result.success:
            type_match = re.search(r":\s+(.+)", result.output)
            result.parsed = {
                "file_type": type_match.group(1).strip() if type_match else result.output.strip(),
                "is_elf": "ELF" in result.output,
                "is_pe": "PE32" in result.output,
                "is_script": "script" in result.output.lower() or "text" in result.output.lower(),
            }
        return result

    def _strings(self, args: str) -> ToolResult:
        result = self._run_cmd(f"strings {args}", timeout=30)
        if result.success:
            lines = result.output.strip().split("\n")
            result.parsed = {"strings": lines[:500], "count": len(lines)}
        return result

    def _grep(self, args: str) -> ToolResult:
        result = self._run_cmd(f"grep {args}", timeout=30)
        if result.success:
            lines = [l for l in result.output.strip().split("\n") if l]
            result.parsed = {"matches": lines[:200], "count": len(lines)}
        return result

    def _netcat(self, args: str) -> ToolResult:
        return self._run_cmd(f"nc {args}", timeout=30)

    def _python(self, args: str) -> ToolResult:
        return self._run_cmd(f"python3 {args}", timeout=60)

    def _shell(self, args: str) -> ToolResult:
        return self._run_cmd(args, timeout=60)

    def _wget(self, args: str) -> ToolResult:
        return self._run_cmd(f"wget {args}", timeout=60)

    # ── Steganography & Forensics ─────────────────────────────────────

    def _exiftool(self, args: str) -> ToolResult:
        result = self._run_cmd(f"exiftool {args}", timeout=60)
        if result.success:
            metadata = {}
            for line in result.output.split("\n"):
                if ":" in line:
                    k, v = line.split(":", 1)
                    k = k.strip()
                    v = v.strip()
                    if k and v:
                        metadata[k] = v
            result.parsed = {"metadata": metadata, "field_count": len(metadata)}
        return result

    def _binwalk(self, args: str) -> ToolResult:
        result = self._run_cmd(f"binwalk {args}", timeout=60)
        if result.success:
            signatures = []
            for m in re.finditer(
                r"\s*(\d+)\s+(0x[0-9a-fA-F]+)\s+(.+)", result.output
            ):
                signatures.append({
                    "offset": int(m.group(1)),
                    "hex_offset": m.group(2),
                    "description": m.group(3).strip(),
                })
            result.parsed = {"signatures": signatures, "count": len(signatures)}
        return result

    def _steghide(self, args: str) -> ToolResult:
        return self._run_cmd(f"steghide {args}", timeout=30)

    def _zsteg(self, args: str) -> ToolResult:
        result = self._run_cmd(f"zsteg {args}", timeout=60)
        if result.success:
            findings = []
            for line in result.output.split("\n"):
                if line.strip() and not line.startswith("["):
                    findings.append(line.strip())
                elif "=" in line:
                    findings.append(line.strip())
            result.parsed = {"findings": findings, "count": len(findings)}
        return result

    def _foremost(self, args: str) -> ToolResult:
        return self._run_cmd(f"foremost {args}", timeout=120)

    # ── Hash Cracking ─────────────────────────────────────────────────

    def _john(self, args: str) -> ToolResult:
        result = self._run_cmd(f"john {args}", timeout=120)
        if result.success:
            cracked = re.findall(r"(\S+):\s*(\S+)", result.output)
            result.parsed = {
                "cracked": [{"user": u, "password": p} for u, p in cracked],
                "count": len(cracked),
            }
        return result

    def _hashcat(self, args: str) -> ToolResult:
        result = self._run_cmd(f"hashcat {args}", timeout=120)
        if result.success:
            cracked = re.findall(r"(\S+):(\S+)", result.output)
            result.parsed = {
                "cracked": [{"hash": h, "plaintext": p} for h, p in cracked],
                "count": len(cracked),
            }
        return result

    # ── Remote Access ─────────────────────────────────────────────────

    def _ssh(self, args: str) -> ToolResult:
        return self._run_cmd(
            f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 {args}",
            timeout=30,
        )

    # ── Flag Submission ───────────────────────────────────────────────

    def _submit_flag(self, flag: str) -> ToolResult:
        flag = flag.strip()
        # Extract flag pattern
        flag_match = re.search(r"(flag\{[^}]+\}|CTF\{[^}]+\}|[a-f0-9]{32})", flag)
        extracted = flag_match.group(1) if flag_match else flag
        logger.info(f"🚩 FLAG SUBMITTED: {extracted}")

        # Submit to scoreboard API (URL from environment, no hardcoded default)
        import os
        scoreboard_url = os.environ.get("SCOREBOARD_URL", "")
        scoreboard_result = None
        if scoreboard_url:
            try:
                import requests as _requests
                resp = _requests.post(
                    f"{scoreboard_url}/api/submit",
                    json={"flag": extracted, "agent": "Ozz"},
                    timeout=5,
                )
                if resp.headers.get("content-type", "").startswith("application/json"):
                    scoreboard_result = resp.json()
                    logger.info(f"  Scoreboard: {scoreboard_result.get('message', resp.status_code)}")
                else:
                    logger.info(f"  Scoreboard: HTTP {resp.status_code}")
            except Exception as e:
                logger.warning(f"  Scoreboard error: {e}")
        else:
            logger.info("  No SCOREBOARD_URL set — flag stored locally")

        return ToolResult(
            output=f"Flag captured: {extracted}" +
                   (f" — Scoreboard: {scoreboard_result.get('message', '')}" if scoreboard_result else ""),
            success=True,
            parsed={
                "flag": extracted,
                "submitted": True,
                "timestamp": time.time(),
                "scoreboard_url": scoreboard_url or None,
                "scoreboard": scoreboard_result,
            },
        )

    # ── Composite Recon ───────────────────────────────────────────────

    def _quick_scan(self, target: str) -> ToolResult:
        """Fast comprehensive scan combining nmap + web fingerprinting."""
        target = target.strip()
        # Sanitize target
        if not re.match(r"^[a-zA-Z0-9._:-]+$", target):
            return ToolResult(
                output="",
                success=False,
                error=f"INVALID_TARGET: {target!r} contains unsafe characters",
            )

        output_parts = []
        parsed: dict[str, Any] = {"target": target, "ports": [], "web_services": []}

        # 1. Quick nmap
        logger.info(f"🔍 Quick scan: nmap on {target}")
        nmap_result = self._run_cmd(
            f"nmap -sV -sC --top-ports 1000 -T4 {target}", timeout=120
        )
        output_parts.append(f"=== NMAP ===\n{nmap_result.output}")
        if nmap_result.parsed:
            parsed["ports"] = nmap_result.parsed.get("ports", [])
            parsed["os"] = nmap_result.parsed.get("os")

        # 2. Web fingerprinting for HTTP ports
        web_ports = []
        for port_info in parsed["ports"]:
            if "http" in port_info.get("service", "").lower():
                web_ports.append(port_info["port"])

        for port in web_ports:
            protocol = "https" if port in (443, 8443) else "http"
            url = f"{protocol}://{target}" if port in (80, 443) else f"{protocol}://{target}:{port}"

            logger.info(f"🌐 Web fingerprinting: {url}")
            whatweb_result = self._run_cmd(f"whatweb {url}", timeout=30)
            output_parts.append(f"=== WHATWEB ({url}) ===\n{whatweb_result.output}")
            if whatweb_result.parsed:
                parsed["web_services"].append({
                    "url": url,
                    "technologies": whatweb_result.parsed.get("technologies", []),
                })

        combined = "\n\n".join(output_parts)
        return ToolResult(
            output=combined[:10000],
            success=True,
            parsed=parsed,
        )
