"""
Bounded Context: Crypto Domain Solver
Decodificação, inspeção de cifras, ataques criptográficos e análise de formatos.
"""
import re
import base64
import json
import codecs
from typing import Dict, Any, FrozenSet, List
from .base import BaseDomainSolver
from .registry import register_solver
from .hypothesis import Hypothesis, TournamentResult
from .engine import TacticalHypothesisEngine
from ..security.security_barrier_policy import CommandAllowlistPolicy
from ..dtos.domain_dtos import AnalysisRequest, DomainAnalysisReport, CommandSpec

ALLOWED_CRYPTO_BINARIES: FrozenSet[str] = frozenset({
    "base64", "xxd", "openssl", "john", "hashcat", "hashid", "python3",
})


@register_solver("crypto")
class CryptoDomainSolver(BaseDomainSolver):
    """Solver especializado em Criptografia com ataques automatizados."""

    def __init__(self, executor=None, file_reader=None, engine: TacticalHypothesisEngine = None):
        super().__init__(executor=executor, file_reader=file_reader)
        self.engine = engine or TacticalHypothesisEngine()
        self.security_policy = CommandAllowlistPolicy(ALLOWED_CRYPTO_BINARIES)

    @property
    def domain_type(self) -> str:
        return "crypto"

    # ── Auto-Decryption ───────────────────────────────────────────────

    def auto_detect_encoding(self, data: str) -> Dict[str, Any]:
        """Automatically detect and decode common encodings."""
        results: Dict[str, Any] = {"detected": [], "decoded": {}}

        # Base64
        if re.match(r'^[A-Za-z0-9+/]*={0,2}$', data) and len(data) % 4 == 0 and len(data) > 4:
            try:
                decoded = base64.b64decode(data).decode('utf-8', errors='replace')
                results["detected"].append("base64")
                results["decoded"]["base64"] = decoded
            except Exception:
                pass

        # Hex
        if re.match(r'^[0-9a-fA-F]+$', data) and len(data) % 2 == 0 and len(data) > 2:
            try:
                decoded = bytes.fromhex(data).decode('utf-8', errors='replace')
                results["detected"].append("hex")
                results["decoded"]["hex"] = decoded
            except Exception:
                pass

        # ROT13
        try:
            rot = codecs.decode(data, 'rot_13')
            if rot != data:
                results["decoded"]["rot13"] = rot
                results["detected"].append("rot13")
        except Exception:
            pass

        # Binary (groups of 8 bits)
        if re.match(r'^[01]{8}(\s[01]{8})*$', data.strip()):
            try:
                chars = [chr(int(data[i:i+8], 2)) for i in range(0, len(data.replace(' ', '')), 8)]
                decoded = ''.join(chars)
                results["detected"].append("binary")
                results["decoded"]["binary"] = decoded
            except Exception:
                pass

        # Decimal ASCII
        parts = data.strip().split()
        if len(parts) > 2 and all(p.isdigit() and 0 <= int(p) < 256 for p in parts):
            try:
                decoded = ''.join(chr(int(p)) for p in parts)
                results["detected"].append("decimal_ascii")
                results["decoded"]["decimal_ascii"] = decoded
            except Exception:
                pass

        # URL encoding
        if '%' in data and re.search(r'%[0-9a-fA-F]{2}', data):
            try:
                from urllib.parse import unquote
                decoded = unquote(data)
                if decoded != data:
                    results["detected"].append("url_encoding")
                    results["decoded"]["url_encoding"] = decoded
            except Exception:
                pass

        # Morse code
        if re.match(r'^[\.\-\/\s]+$', data.strip()):
            morse_map = {
                '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
                '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
                '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
                '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
                '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
                '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
                '...--': '3', '....-': '4', '.....': '5', '-....': '6',
                '--...': '7', '---..': '8', '----.': '9', '/': ' ',
            }
            try:
                words = data.strip().split(' / ')
                decoded_parts = []
                for word in words:
                    chars = word.split(' ')
                    decoded_parts.append(''.join(morse_map.get(c, '?') for c in chars))
                decoded = ' '.join(decoded_parts)
                results["detected"].append("morse")
                results["decoded"]["morse"] = decoded
            except Exception:
                pass

        return results

    def xor_brute_force(self, ciphertext: bytes, max_key_len: int = 1) -> Dict[str, Any]:
        """Brute-force single-byte XOR and find most likely plaintext."""
        results: List[Dict[str, Any]] = []

        # English letter frequency
        freq = {
            'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 12.7, 'f': 2.2,
            'g': 2.0, 'h': 6.1, 'i': 7.0, 'j': 0.15, 'k': 0.77, 'l': 4.0,
            'm': 2.4, 'n': 6.7, 'o': 7.5, 'p': 1.9, 'q': 0.095, 'r': 6.0,
            's': 6.3, 't': 9.1, 'u': 2.8, 'v': 0.98, 'w': 2.4, 'x': 0.15,
            'y': 2.0, 'z': 0.074, ' ': 13.0,
        }

        for key in range(256):
            decrypted = bytes(b ^ key for b in ciphertext)
            try:
                text = decrypted.decode('ascii', errors='strict')
                score = sum(freq.get(c.lower(), 0) for c in text) / max(len(text), 1)
                results.append({"key": key, "key_hex": f"0x{key:02x}", "plaintext": text[:200], "score": round(score, 2)})
            except Exception:
                pass

        results.sort(key=lambda x: x["score"], reverse=True)
        return {"top_results": results[:10], "total_tested": 256}

    def identify_hash(self, hash_str: str) -> Dict[str, Any]:
        """Identify hash type by length and pattern."""
        h = hash_str.strip()
        length = len(h)

        candidates = []
        if re.match(r'^[0-9a-fA-F]+$', h):
            mapping = {
                32: ["MD5", "NTLM", "MD4"],
                40: ["SHA1", "RIPEMD-160"],
                56: ["SHA-224", "SHA3-224"],
                64: ["SHA-256", "SHA3-256"],
                96: ["SHA-384", "SHA3-384"],
                128: ["SHA-512", "SHA3-512"],
            }
            candidates = mapping.get(length, [])
        elif ':' in h:
            # Hash:salt format
            candidates = ["Salted hash (various)"]
        elif h.startswith('$'):
            # Modular crypt format
            if '$2' in h[:4]:
                candidates = ["bcrypt"]
            elif '$6$' in h[:4]:
                candidates = ["SHA-512 crypt"]
            elif '$5$' in h[:4]:
                candidates = ["SHA-256 crypt"]
            elif '$1$' in h[:4]:
                candidates = ["MD5 crypt"]
        elif len(h) == 13:
            candidates = ["DES crypt"]

        return {
            "hash": h,
            "length": length,
            "candidates": candidates,
            "likely": candidates[0] if candidates else "Unknown",
        }

    def caesar_brute_force(self, ciphertext: str) -> Dict[str, Any]:
        """Brute-force all 26 Caesar cipher shifts."""
        results = []
        for shift in range(26):
            decoded = []
            for c in ciphertext:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    decoded.append(chr((ord(c) - base - shift) % 26 + base))
                else:
                    decoded.append(c)
            results.append({"shift": shift, "text": ''.join(decoded)})
        return {"results": results, "total_shifts": 26}

    # ── Tournament & Analysis ─────────────────────────────────────────

    def solve_tactical_step(self, metadata: Dict[str, Any]) -> TournamentResult[CommandSpec]:
        """Gera, sanitiza e ranqueia hipóteses táticas de análise criptográfica via Torneio Elo."""
        target = str(metadata.get("target_resource", "cipher.txt"))
        data_format = str(metadata.get("data_format", "base64")).lower()

        hyp_base64_score = 0.95 if data_format == "base64" or "b64" in target else 0.4
        hyp_xxd_score = 0.9 if data_format == "hex" or data_format == "binary_dump" else 0.5
        hyp_pem_score = 0.95 if data_format == "pem" or "pem" in target or "key" in target else 0.3
        hyp_strings_score = 0.7 if data_format == "unknown" else 0.3
        hyp_openssl_rsa_score = 0.9 if "rsa" in target.lower() or "pub" in target.lower() else 0.2

        hypotheses = [
            Hypothesis(
                id="hyp_base64_decode",
                name="Decodificação Base64",
                payload=CommandSpec(binary="base64", args=["-d", target]),
                initial_score=hyp_base64_score,
            ),
            Hypothesis(
                id="hyp_xxd_hexdump",
                name="Inspeção de Dump Hexadecimal",
                payload=CommandSpec(binary="xxd", args=[target]),
                initial_score=hyp_xxd_score,
            ),
            Hypothesis(
                id="hyp_openssl_asn1",
                name="Análise de Estrutura ASN1/PEM via OpenSSL",
                payload=CommandSpec(binary="openssl", args=["asn1parse", "-in", target]),
                initial_score=hyp_pem_score,
            ),
            Hypothesis(
                id="hyp_strings",
                name="Extração de Strings Imprimíveis",
                payload=CommandSpec(binary="strings", args=[target]),
                initial_score=hyp_strings_score,
            ),
            Hypothesis(
                id="hyp_openssl_rsa",
                name="Análise de Chave RSA Pública",
                payload=CommandSpec(binary="openssl", args=["rsa", "-pubin", "-in", target, "-text", "-noout"]),
                initial_score=hyp_openssl_rsa_score,
            ),
        ]

        return self.engine.run_tournament(
            hypotheses, context=metadata, policy=self.security_policy
        )

    def analyze(self, request: AnalysisRequest) -> DomainAnalysisReport:
        data_format = request.options.get("data_format", "base64")
        target = request.target_resource

        # Phase 1: Tactical analysis via tournament
        tournament_res = self.solve_tactical_step({
            "target_resource": target,
            "data_format": data_format,
        })
        winning_cmd = tournament_res.winner.payload
        exec_res = self.executor.execute(winning_cmd)

        observations = [exec_res.output] if exec_res.success else []
        errors = [exec_res.error] if exec_res.error else []
        metadata: Dict[str, Any] = {
            "target": target,
            "winning_hypothesis": tournament_res.winner.name,
            "debate_summary": tournament_res.debate_summary,
        }

        # Phase 2: Auto-detect encoding from output
        if exec_res.success and exec_res.output:
            try:
                # Try to detect encoding from the output content
                sample = exec_res.output.strip()[:500]
                encoding_result = self.auto_detect_encoding(sample)
                if encoding_result["detected"]:
                    metadata["auto_encoding"] = encoding_result
                    observations.append(f"Auto-detected encodings: {encoding_result['detected']}")

                    # If we decoded something, try to detect flags
                    for enc_type, decoded in encoding_result.get("decoded", {}).items():
                        flag_match = re.search(r'(flag\{[^}]+\}|CTF\{[^}]+\})', str(decoded), re.IGNORECASE)
                        if flag_match:
                            observations.append(f"FLAG FOUND via {enc_type}: {flag_match.group(1)}")
            except Exception as e:
                errors.append(f"Auto-encoding detection error: {e}")

        # Phase 3: Hash identification if output looks like a hash
        if exec_res.success and exec_res.output:
            for line in exec_res.output.strip().split('\n')[:5]:
                line = line.strip()
                if re.match(r'^[0-9a-fA-F]{32,128}$', line):
                    hash_result = self.identify_hash(line)
                    metadata["hash_identification"] = hash_result
                    observations.append(f"Hash detected: {hash_result['likely']} ({hash_result['length']} chars)")

        return DomainAnalysisReport(
            domain=self.domain_type,
            success=exec_res.success,
            observations=observations,
            errors=errors,
            metadata=metadata,
        )
