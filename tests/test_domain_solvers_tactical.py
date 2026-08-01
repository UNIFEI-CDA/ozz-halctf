"""
Suíte TDD dos 4 Solvers Táticos com Torneio de Hipóteses (Forensics, Web, Privesc, Crypto)
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.domains.forensics import ForensicsDomainSolver
from agent.domains.web import WebDomainSolver
from agent.domains.privesc import PrivescDomainSolver
from agent.domains.crypto import CryptoDomainSolver
from agent.ports.executor import MockProcessExecutor
from agent.ports.file_reader import MockFileReader
from agent.dtos.domain_dtos import AnalysisRequest


class TestDomainSolversTactical(unittest.TestCase):
    """Valida o torneio de hipóteses end-to-end nos 4 solvers de domínio."""

    def test_forensics_solver_tactical_step_determinism(self):
        """ForensicsDomainSolver com mime_type 'image/png' deve eleger 'Análise de Metadados EXIF'."""
        solver = ForensicsDomainSolver(
            executor=MockProcessExecutor(mock_output="EXIF metadata"),
            file_reader=MockFileReader(),
        )

        # 1. Teste via solve_tactical_step direto
        res = solver.solve_tactical_step({"target_resource": "evidence.png", "mime_type": "image/png"})
        self.assertEqual(res.winner.id, "hyp_exif")
        self.assertEqual(res.winner.payload.binary, "exiftool")

        # 2. Teste via analyze()
        req = AnalysisRequest(domain="forensics", target_resource="evidence.png")
        report = solver.analyze(req)
        self.assertTrue(report.success)
        self.assertEqual(report.metadata["winning_hypothesis"], "Análise de Metadados EXIF")

    def test_web_solver_tactical_step_determinism(self):
        """WebDomainSolver com target_type 'http' deve eleger 'Inspeção de Cabeçalhos HTTP Response'."""
        solver = WebDomainSolver(executor=MockProcessExecutor(mock_output="HTTP/1.1 200 OK"))

        res = solver.solve_tactical_step({"target_resource": "http://target.ctf", "target_type": "http"})
        self.assertEqual(res.winner.id, "hyp_headers")
        self.assertEqual(res.winner.payload.binary, "curl")
        self.assertIn("http://target.ctf", res.winner.payload.args)
        self.assertIn("-sI", res.winner.payload.args)

    def test_privesc_solver_tactical_step_determinism(self):
        """PrivescDomainSolver com user_level 'low_privilege' deve eleger 'Auditoria de Regras Sudo Sem Senha'."""
        solver = PrivescDomainSolver(executor=MockProcessExecutor(mock_output="(ALL : ALL) NOPASSWD: ALL"))

        res = solver.solve_tactical_step({"user_level": "low_privilege"})
        self.assertEqual(res.winner.id, "hyp_sudo_l")
        self.assertEqual(res.winner.payload.binary, "sudo")
        self.assertEqual(res.winner.payload.args, ["-l"])

    def test_crypto_solver_tactical_step_determinism(self):
        """CryptoDomainSolver deve eleger base64 para 'base64' e xxd para 'hex'."""
        solver = CryptoDomainSolver(executor=MockProcessExecutor(mock_output="decoded text"))

        # Caso 1: base64
        res_b64 = solver.solve_tactical_step({"target_resource": "flag.b64", "data_format": "base64"})
        self.assertEqual(res_b64.winner.id, "hyp_base64_decode")
        self.assertEqual(res_b64.winner.payload.binary, "base64")

        # Caso 2: hex dump
        res_hex = solver.solve_tactical_step({"target_resource": "dump.hex", "data_format": "hex"})
        self.assertEqual(res_hex.winner.id, "hyp_xxd_hexdump")
        self.assertEqual(res_hex.winner.payload.binary, "xxd")


if __name__ == "__main__":
    unittest.main()
