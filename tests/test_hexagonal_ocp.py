"""
Suíte TDD de Arquitetura Hexagonal, Ports & Adapters, OCP e DTOs Tipados (Portão 5 - RED)
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestPortsAndAdapters(unittest.TestCase):
    """Valida a abstração de I/O (Porta e Adaptadores)"""

    def test_mock_executor_port_injection(self):
        """Verifica se o solver de domínio executa via MockProcessExecutor sem invocar o SO"""
        from agent.ports.executor import MockProcessExecutor
        from agent.ports.file_reader import MockFileReader
        from agent.domains.pwn_rev import PwnRevDomainSolver
        from agent.dtos.domain_dtos import AnalysisRequest

        mock_executor = MockProcessExecutor(mock_output="ELF 64-bit LSB executable")
        mock_file_reader = MockFileReader(exists_return=True, header_return=b"\x7fELF")
        solver = PwnRevDomainSolver(executor=mock_executor, file_reader=mock_file_reader)
        
        req = AnalysisRequest(domain="pwn", target_resource="sample.elf")
        report = solver.analyze(req)
        
        self.assertTrue(report.success)
        self.assertGreaterEqual(len(mock_executor.executed_commands), 1)
        binaries = [cmd.binary for cmd in mock_executor.executed_commands]
        self.assertIn("readelf", binaries)

    def test_safe_process_executor_shell_false_sanitization(self):
        """Verifica se o SafeProcessExecutor usa listas parametrizadas (shell=False) protegendo contra Command Injection"""
        from agent.infra.executor import SafeProcessExecutor
        from agent.dtos.domain_dtos import CommandSpec

        executor = SafeProcessExecutor()
        # Tenta injetar comando perigoso no argumento de arquivo
        dangerous_spec = CommandSpec(binary="file", args=["target_file; whoami;"])
        
        # Execução segura via shell=False deve tratar o argumento como literal sem executar whoami
        res = executor.execute(dangerous_spec)
        self.assertNotIn("root", res.output)
        self.assertNotIn("user", res.output)


class TestOCPRegistry(unittest.TestCase):
    """Valida o Princípio Aberto/Fechado (OCP) e auto-descoberta de Solvers"""

    def test_dynamic_solver_registration_without_modifying_facade(self):
        """Verifica se um novo solver registrado via decorador é descoberto pelo ExploitArsenal sem alterar seu código"""
        from agent.domains.base import BaseDomainSolver
        from agent.domains.registry import DomainSolverRegistry, register_solver
        from agent.exploits import ExploitArsenal
        from agent.dtos.domain_dtos import AnalysisRequest, DomainAnalysisReport

        @register_solver("mobile")
        class MobileDomainSolver(BaseDomainSolver):
            @property
            def domain_type(self) -> str:
                return "mobile"

            def analyze(self, request: AnalysisRequest) -> DomainAnalysisReport:
                return DomainAnalysisReport(domain="mobile", success=True, observations=[])

        # O Registry e a Façade ExploitArsenal devem descobrir o solver "mobile" automaticamente
        self.assertTrue(DomainSolverRegistry.has_solver("mobile"))
        arsenal = ExploitArsenal()
        solver = arsenal.get_solver("mobile")
        self.assertIsNotNone(solver)
        self.assertEqual(solver.domain_type, "mobile")


class TestTypedDTOs(unittest.TestCase):
    """Valida contratos tipados (DTOs / Value Objects)"""

    def test_solver_returns_typed_report(self):
        """Verifica se os solvers retornam DTOs DomainAnalysisReport fortemente tipados"""
        from agent.ports.executor import MockProcessExecutor
        from agent.domains.forensics import ForensicsDomainSolver
        from agent.dtos.domain_dtos import AnalysisRequest, DomainAnalysisReport

        mock_executor = MockProcessExecutor(mock_output="ExifTool Version : 12.00")
        solver = ForensicsDomainSolver(executor=mock_executor)
        
        req = AnalysisRequest(domain="forensics", target_resource="image.png")
        report = solver.analyze(req)

        self.assertIsInstance(report, DomainAnalysisReport)
        self.assertEqual(report.domain, "forensics")
        self.assertTrue(report.success)


if __name__ == "__main__":
    unittest.main()
