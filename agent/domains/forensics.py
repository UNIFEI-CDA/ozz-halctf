"""
Bounded Context: Forensics Domain Solver
Análise forense digital, esteganografia, metadados e carving.
"""
import re
import json
from typing import List, Dict, Any, FrozenSet
from .base import BaseDomainSolver
from .registry import register_solver
from .hypothesis import Hypothesis, TournamentResult
from .engine import TacticalHypothesisEngine
from ..security.security_barrier_policy import CommandAllowlistPolicy
from ..dtos.domain_dtos import AnalysisRequest, DomainAnalysisReport, CommandSpec, ChecklistTemplate

ALLOWED_FORENSICS_BINARIES: FrozenSet[str] = frozenset({
    "strings", "exiftool", "binwalk", "file", "sha256sum", "md5sum",
    "steghide", "zsteg", "foremost", "xxd", "python3", "identify",
    "convert", "tesseract",
})


@register_solver("forensics")
@register_solver("stego")
class ForensicsDomainSolver(BaseDomainSolver):
    """Solver especializado em Forense Digital e Esteganografia com auto-exploração."""

    def __init__(self, executor=None, file_reader=None, engine: TacticalHypothesisEngine = None):
        super().__init__(executor=executor, file_reader=file_reader)
        self.engine = engine or TacticalHypothesisEngine()
        self.security_policy = CommandAllowlistPolicy(ALLOWED_FORENSICS_BINARIES)

    @property
    def domain_type(self) -> str:
        return "forensics"

    # ── Checklist ─────────────────────────────────────────────────────

    def get_checklist(self, file_path: str = "evidence.file") -> List[ChecklistTemplate]:
        return [
            ChecklistTemplate(
                name="Metadata",
                human_readable_command=f"exiftool {file_path}",
                description="Extrai metadados EXIF/IPTC.",
            ),
            ChecklistTemplate(
                name="Embedded files",
                human_readable_command=f"binwalk {file_path}",
                description="Detecta arquivos embarcados por assinatura.",
            ),
            ChecklistTemplate(
                name="Extract embedded",
                human_readable_command=f"binwalk -e {file_path}",
                description="Extrai arquivos embarcados para disco.",
            ),
            ChecklistTemplate(
                name="File identification",
                human_readable_command=f"file {file_path}",
                description="Identifica o tipo de arquivo por magic bytes.",
            ),
            ChecklistTemplate(
                name="SHA256 hash",
                human_readable_command=f"sha256sum {file_path}",
                description="Calcula hash SHA-256 para verificação.",
            ),
            ChecklistTemplate(
                name="Strings analysis",
                human_readable_command=f"strings {file_path}",
                description="Extrai strings imprimíveis.",
            ),
            ChecklistTemplate(
                name="Hex dump header",
                human_readable_command=f"xxd {file_path}",
                description="Dump hexadecimal dos primeiros bytes.",
            ),
        ]

    # ── Steganography Auto-Extraction ─────────────────────────────────

    def stego_auto_extract(self, file_path: str, password: str = "") -> Dict[str, Any]:
        """Attempt steganography extraction using multiple tools."""
        results: Dict[str, Any] = {"attempts": [], "findings": []}

        file_type_result = self.executor.execute(CommandSpec(
            binary="file", args=[file_path], timeout=10
        ))
        file_type = file_type_result.output if file_type_result.success else ""
        results["file_type"] = file_type

        is_image = any(t in file_type.lower() for t in ["png", "jpeg", "jpg", "bmp", "gif", "tiff"])
        is_png = "png" in file_type.lower()
        is_jpeg = "jpeg" in file_type.lower() or "jpg" in file_type.lower()

        # 1. exiftool for metadata/hidden comments
        exif_result = self.executor.execute(CommandSpec(
            binary="exiftool", args=[file_path], timeout=30
        ))
        if exif_result.success:
            results["attempts"].append("exiftool")
            # Look for suspicious metadata
            suspicious_fields = ["Comment", "Description", "UserComment", "ImageDescription",
                                 "XPComment", "XPAuthor", "Copyright", "Artist"]
            for field in suspicious_fields:
                match = re.search(rf"{field}\s*:\s*(.+)", exif_result.output)
                if match and match.group(1).strip():
                    results["findings"].append({
                        "tool": "exiftool",
                        "type": "metadata",
                        "field": field,
                        "value": match.group(1).strip(),
                    })

        # 2. strings for flags
        strings_result = self.executor.execute(CommandSpec(
            binary="strings", args=[file_path], timeout=30
        ))
        if strings_result.success:
            results["attempts"].append("strings")
            flag_matches = re.findall(
                r'(flag\{[^}]+\}|CTF\{[^}]+\}|FLAG[:=]\s*\S+)',
                strings_result.output, re.IGNORECASE
            )
            for flag in flag_matches:
                results["findings"].append({
                    "tool": "strings",
                    "type": "flag",
                    "value": flag,
                })

        # 3. binwalk for embedded files
        binwalk_result = self.executor.execute(CommandSpec(
            binary="binwalk", args=[file_path], timeout=30
        ))
        if binwalk_result.success:
            results["attempts"].append("binwalk")
            signatures = re.findall(r'\s*(\d+)\s+(0x[0-9a-fA-F]+)\s+(.+)', binwalk_result.output)
            if signatures:
                results["findings"].append({
                    "tool": "binwalk",
                    "type": "embedded_files",
                    "signatures": [{"offset": s[0], "hex": s[1], "desc": s[2].strip()} for s in signatures],
                })

        # 4. steghide (for JPEG/BMP)
        if is_jpeg or "bmp" in file_type.lower():
            passwords = [password, "", "password", "admin", "1234", "steghide", "secret"]
            if password:
                passwords = [password]
            for pw in passwords:
                args = f"extract -sf {file_path} -f"
                if pw:
                    args = f"extract -sf {file_path} -p '{pw}' -f"
                else:
                    args = f"extract -sf {file_path} -f"
                steghide_result = self.executor.execute(CommandSpec(
                    binary="steghide", args=args.split(), timeout=15
                ))
                if steghide_result.success and "could not extract" not in steghide_result.output.lower():
                    results["attempts"].append(f"steghide (pw='{pw}')")
                    results["findings"].append({
                        "tool": "steghide",
                        "type": "extracted",
                        "password": pw,
                        "output": steghide_result.output.strip(),
                    })
                    break

        # 5. zsteg (for PNG/BMP)
        if is_png or "bmp" in file_type.lower():
            zsteg_result = self.executor.execute(CommandSpec(
                binary="zsteg", args=["-a", file_path], timeout=60
            ))
            if zsteg_result.success and zsteg_result.output.strip():
                results["attempts"].append("zsteg")
                findings = []
                for line in zsteg_result.output.split('\n'):
                    if line.strip() and not line.startswith('im'):
                        findings.append(line.strip())
                if findings:
                    results["findings"].append({
                        "tool": "zsteg",
                        "type": "lsb_stego",
                        "results": findings[:20],
                    })

        # 6. binwalk extract
        binwalk_e_result = self.executor.execute(CommandSpec(
            binary="binwalk", args=["-e", file_path], timeout=60
        ))
        if binwalk_e_result.success:
            results["attempts"].append("binwalk -e")

        # 7. foremost for file carving
        foremost_result = self.executor.execute(CommandSpec(
            binary="foremost", args=["-i", file_path, "-o", "/tmp/foremost_out"], timeout=120
        ))
        if foremost_result.success:
            results["attempts"].append("foremost")
            results["findings"].append({
                "tool": "foremost",
                "type": "carved",
                "output_dir": "/tmp/foremost_out",
            })

        return results

    def detect_hidden_data(self, file_path: str) -> Dict[str, Any]:
        """Detect hidden data in various file types."""
        results: Dict[str, Any] = {"techniques": [], "findings": []}

        # Check for appended data after EOF
        # For JPEG: look for data after FF D9
        # For PNG: look for data after IEND
        # For ZIP: look for data after PK\x05\x06

        xxd_result = self.executor.execute(CommandSpec(
            binary="xxd", args=[file_path], timeout=30
        ))
        if xxd_result.success:
            output = xxd_result.output
            results["techniques"].append("hex_analysis")

            # Look for embedded file signatures
            sigs = {
                "PK": "ZIP/JAR/APK",
                "Rar!": "RAR archive",
                "\x1f\x8b": "GZIP",
                "BZ": "BZIP2",
                "%PDF": "PDF",
                "\x89PNG": "PNG image",
                "\xff\xd8\xff": "JPEG image",
                "GIF8": "GIF image",
                "\x7fELF": "ELF binary",
            }

            for sig, desc in sigs.items():
                hex_sig = sig.encode().hex() if isinstance(sig, str) else sig.hex()
                if hex_sig.lower() in output.lower():
                    results["findings"].append(f"Contains {desc} signature")

        return results

    # ── Tournament & Analysis ─────────────────────────────────────────

    def solve_tactical_step(self, metadata: Dict[str, Any]) -> TournamentResult[CommandSpec]:
        """Gera, sanitiza e ranqueia hipóteses táticas de forense via Torneio Elo."""
        target = str(metadata.get("target_resource", "evidence.file"))
        mime_type = str(metadata.get("mime_type", "")).lower()

        hyp_file_score = 0.9 if "unknown" in mime_type or not mime_type else 0.5
        hyp_exif_score = 0.95 if "image" in mime_type or "jpeg" in mime_type or "png" in mime_type else 0.4
        hyp_binwalk_score = 0.9 if "zip" in mime_type or "octet-stream" in mime_type else 0.5
        hyp_strings_score = 0.7 if "text" in mime_type or "executable" in mime_type else 0.3
        hyp_sha256_score = 0.3
        hyp_xxd_score = 0.6 if not mime_type else 0.4

        hypotheses = [
            Hypothesis(
                id="hyp_file",
                name="Identificação por Magic Bytes",
                payload=CommandSpec(binary="file", args=[target]),
                initial_score=hyp_file_score,
            ),
            Hypothesis(
                id="hyp_exif",
                name="Análise de Metadados EXIF",
                payload=CommandSpec(binary="exiftool", args=[target]),
                initial_score=hyp_exif_score,
            ),
            Hypothesis(
                id="hyp_binwalk",
                name="Inspeção de Assinaturas de Arquivo Embarcado",
                payload=CommandSpec(binary="binwalk", args=[target]),
                initial_score=hyp_binwalk_score,
            ),
            Hypothesis(
                id="hyp_strings",
                name="Extração de Strings Imprimíveis",
                payload=CommandSpec(binary="strings", args=[target]),
                initial_score=hyp_strings_score,
            ),
            Hypothesis(
                id="hyp_sha256",
                name="Cálculo de Hash SHA-256",
                payload=CommandSpec(binary="sha256sum", args=[target]),
                initial_score=hyp_sha256_score,
            ),
            Hypothesis(
                id="hyp_xxd",
                name="Análise Hexadecimal",
                payload=CommandSpec(binary="xxd", args=[target]),
                initial_score=hyp_xxd_score,
            ),
        ]

        return self.engine.run_tournament(
            hypotheses, context=metadata, policy=self.security_policy
        )

    def analyze(self, request: AnalysisRequest) -> DomainAnalysisReport:
        metadata = dict(request.options)
        metadata["target_resource"] = request.target_resource
        target = request.target_resource

        # Auto-detect mime type from extension
        if "mime_type" not in metadata:
            target_lower = target.lower()
            if target_lower.endswith((".png",)):
                metadata["mime_type"] = "image/png"
            elif target_lower.endswith((".jpg", ".jpeg")):
                metadata["mime_type"] = "image/jpeg"
            elif target_lower.endswith(".bmp"):
                metadata["mime_type"] = "image/bmp"
            elif target_lower.endswith(".gif"):
                metadata["mime_type"] = "image/gif"
            elif target_lower.endswith(".zip"):
                metadata["mime_type"] = "application/zip"
            elif target_lower.endswith((".elf", ".bin")):
                metadata["mime_type"] = "application/x-executable"
            elif target_lower.endswith(".pcap"):
                metadata["mime_type"] = "application/pcap"

        # Phase 1: Tactical tournament
        tournament_res = self.solve_tactical_step(metadata)
        winning_cmd = tournament_res.winner.payload
        exec_res = self.executor.execute(winning_cmd)

        observations = [exec_res.output] if exec_res.success else []
        errors = [exec_res.error] if exec_res.error else []
        result_metadata: Dict[str, Any] = {
            "target": target,
            "winning_hypothesis": tournament_res.winner.name,
            "debate_summary": tournament_res.debate_summary,
        }

        # Phase 2: Auto steganography extraction (for images)
        mime = metadata.get("mime_type", "")
        if "image" in mime or "bmp" in mime:
            try:
                stego_results = self.stego_auto_extract(target, password=metadata.get("stego_password", ""))
                result_metadata["stego_analysis"] = stego_results
                if stego_results.get("findings"):
                    for finding in stego_results["findings"]:
                        observations.append(f"[{finding.get('tool')}] {finding.get('type')}: {finding.get('value', finding.get('results', ''))}")
            except Exception as e:
                errors.append(f"Stego analysis error: {e}")

        # Phase 3: Hidden data detection
        try:
            hidden_results = self.detect_hidden_data(target)
            if hidden_results.get("findings"):
                result_metadata["hidden_data"] = hidden_results
                observations.extend(hidden_results["findings"])
        except Exception as e:
            errors.append(f"Hidden data detection error: {e}")

        # Phase 4: Flag extraction from all collected data
        all_text = " ".join(str(o) for o in observations)
        flag_matches = re.findall(r'(flag\{[^}]+\}|CTF\{[^}]+\})', all_text, re.IGNORECASE)
        if flag_matches:
            result_metadata["flags_found"] = list(set(flag_matches))
            observations.append(f"🚩 FLAGS FOUND: {list(set(flag_matches))}")

        return DomainAnalysisReport(
            domain=self.domain_type,
            success=exec_res.success or bool(result_metadata.get("flags_found")),
            observations=observations,
            errors=errors,
            metadata=result_metadata,
        )
