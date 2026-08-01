"""
Suíte TDD de Auto-Discovery, Prevenção de Deadlocks e Regras de Domínio (Portão 5 - RED)
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAutoDiscovery(unittest.TestCase):
    """Valida o carregamento dinâmico de solvers via pkgutil sem imports manuais"""

    def test_pkgutil_autodiscovery_registers_solvers(self):
        """DomainSolverRegistry deve descobrir e registrar solvers em agent.domains automaticamente"""
        from agent.domains.registry import DomainSolverRegistry

        # Reseta o registro para testar a descoberta pura
        DomainSolverRegistry._solvers.clear()
        self.assertNotIn("pwn", DomainSolverRegistry._solvers)

        # Executa auto-descoberta
        DomainSolverRegistry.discover_solvers()
        self.assertTrue(DomainSolverRegistry.has_solver("pwn"))
        self.assertTrue(DomainSolverRegistry.has_solver("web"))
        self.assertTrue(DomainSolverRegistry.has_solver("forensics"))


class TestDeadlockAndTimeoutPrevention(unittest.TestCase):
    """Valida prevenção de deadlock e controle de exceções de infraestrutura"""

    def test_process_executor_timeout_kills_process(self):
        """SafeProcessExecutor deve matar processos em loop infinito via SIGKILL e retornar resultado gracioso"""
        from agent.infra.executor import SafeProcessExecutor
        from agent.dtos.domain_dtos import CommandSpec

        executor = SafeProcessExecutor()
        # Comando Python que entra em loop infinito
        infinite_loop_spec = CommandSpec(
            binary=sys.executable,
            args=["-c", "import time\nwhile True: time.sleep(0.1)"],
            timeout=0.5  # Timeout curto de 500ms
        )
        res = executor.execute(infinite_loop_spec)
        self.assertFalse(res.success)
        self.assertIn("EXECUTION_TIMEOUT_KILLED", res.error)
        self.assertEqual(res.exit_code, -9)

    def test_missing_binary_graceful_handling(self):
        """SafeProcessExecutor deve capturar FileNotFoundError para binários inexistentes sem estourar exceção"""
        from agent.infra.executor import SafeProcessExecutor
        from agent.dtos.domain_dtos import CommandSpec

        executor = SafeProcessExecutor()
        missing_bin_spec = CommandSpec(binary="non_existent_binary_xyz_123", args=[])
        res = executor.execute(missing_bin_spec)
        self.assertFalse(res.success)
        self.assertIn("BINARY_NOT_FOUND", res.error)


class TestDomainTacticalDecisionEngine(unittest.TestCase):
    """Valida regras de negócio puras de tomada de decisão tática no PwnRevDomainSolver"""

    def test_evaluate_tactical_strategy_rules(self):
        """PwnRevDomainSolver deve decidir a estratégia de exploração ideal para os 4 quadrantes"""
        from agent.domains.pwn_rev import PwnRevDomainSolver

        solver = PwnRevDomainSolver()

        # Quadrante 1: Sem NX -> Injection de Shellcode
        strat1 = solver.evaluate_tactical_strategy({"NX": False, "Canary": False, "PIE": False})
        self.assertEqual(strat1.strategy_name, "SHELLCODE_INJECTION")

        # Quadrante 2: NX ativado sem Canary -> Ret2libc Stack Overflow
        strat2 = solver.evaluate_tactical_strategy({"NX": True, "Canary": False, "PIE": False})
        self.assertEqual(strat2.strategy_name, "RET2LIBC_STACK_OVERFLOW")

        # Quadrante 3: NX e Canary ativados, PIE desativado -> ROP_FIXED_BINARY_BASE
        strat3 = solver.evaluate_tactical_strategy({"NX": True, "Canary": True, "PIE": False})
        self.assertEqual(strat3.strategy_name, "ROP_FIXED_BINARY_BASE")
        self.assertIn("canary_leak_primitive", strat3.prerequisites)
        self.assertIn("libc_leak_via_plt", strat3.prerequisites)

        # Quadrante 4: NX, Canary e PIE ativados -> LEAK_CANARY_AND_ROP
        strat4 = solver.evaluate_tactical_strategy({"NX": True, "Canary": True, "PIE": True})
        self.assertEqual(strat4.strategy_name, "LEAK_CANARY_AND_ROP")


class TestBinaryPathAndSolverValidation(unittest.TestCase):
    """Valida a pureza do BinaryPath VO e a resiliência do PwnRevDomainSolver com Ports injetadas"""

    def test_binary_path_vo_syntax_validation(self):
        """BinaryPath deve validar sintaxe em memória sem realizar I/O."""
        from agent.domains.pwn_rev import BinaryPath

        # Validações que devem lançar ValueError
        with self.assertRaises(ValueError):
            BinaryPath("")
        with self.assertRaises(ValueError):
            BinaryPath("binary\x00name")
        with self.assertRaises(ValueError):
            BinaryPath("../../../etc/passwd")
        with self.assertRaises(ValueError):
            BinaryPath("/etc/passwd")
        with self.assertRaises(ValueError):
            BinaryPath("/proc/self/mem")
        with self.assertRaises(ValueError):
            BinaryPath(r"C:\Windows\System32\cmd.exe")
        with self.assertRaises(ValueError):
            BinaryPath(r"\\server\share\file")

        # Validação que deve ter sucesso
        valid = BinaryPath("binaries/target_app")
        self.assertEqual(valid.value, "binaries/target_app")

    def test_solver_analyze_with_mock_ports(self):
        """analyze() deve usar FileReaderPort e ProcessExecutorPort sem invocar o SO."""
        from agent.domains.pwn_rev import PwnRevDomainSolver
        from agent.ports.file_reader import MockFileReader
        from agent.ports.executor import MockProcessExecutor
        from agent.dtos.domain_dtos import AnalysisRequest

        # 1. Caminho inválido (sintaxe) -> INVALID_TARGET
        solver = PwnRevDomainSolver(executor=MockProcessExecutor(), file_reader=MockFileReader())
        rep1 = solver.analyze(AnalysisRequest(domain="pwn", target_resource="/etc/passwd"))
        self.assertFalse(rep1.success)
        self.assertIn("INVALID_TARGET", rep1.errors[0])

        # 2. Arquivo inexistente no disco -> FILE_NOT_FOUND
        solver_no_file = PwnRevDomainSolver(
            executor=MockProcessExecutor(),
            file_reader=MockFileReader(exists_return=False)
        )
        rep2 = solver_no_file.analyze(AnalysisRequest(domain="pwn", target_resource="target_bin"))
        self.assertFalse(rep2.success)
        self.assertIn("FILE_NOT_FOUND", rep2.errors[0])

        # 3. Formato não-ELF (ex: PE header b"MZ") -> INVALID_FORMAT
        solver_pe = PwnRevDomainSolver(
            executor=MockProcessExecutor(),
            file_reader=MockFileReader(exists_return=True, header_return=b"MZ\x90\x00")
        )
        rep3 = solver_pe.analyze(AnalysisRequest(domain="pwn", target_resource="target_bin"))
        self.assertFalse(rep3.success)
        self.assertIn("INVALID_FORMAT", rep3.errors[0])

        # 4. Formato ELF válido -> Sucesso via checksec/readelf mock
        mock_exec = MockProcessExecutor(mock_output="0x0000000000000001 (NEEDED) Shared library: [libc.so.6]", exit_code=0)
        solver_elf = PwnRevDomainSolver(
            executor=mock_exec,
            file_reader=MockFileReader(exists_return=True, header_return=b"\x7fELF")
        )
        rep4 = solver_elf.analyze(AnalysisRequest(domain="pwn", target_resource="target_bin"))
        self.assertTrue(rep4.success)
        self.assertGreaterEqual(len(mock_exec.executed_commands), 1)
        binaries = [cmd.binary for cmd in mock_exec.executed_commands]
        self.assertIn("readelf", binaries)


if __name__ == "__main__":
    unittest.main()
