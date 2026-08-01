"""DomainSolverRegistry desacoplado cumprindo o OCP (<= 70 LOC)"""
from typing import Dict, Type, Optional
from .base import BaseDomainSolver

class DomainSolverRegistry:
    """Registro dinâmico de Solvers de Domínio (Open/Closed Principle)."""
    _solvers: Dict[str, Type[BaseDomainSolver]] = {}

    @classmethod
    def register(cls, domain_type: str, solver_cls: Type[BaseDomainSolver]):
        cls._solvers[domain_type] = solver_cls

    @classmethod
    def has_solver(cls, domain_type: str) -> bool:
        if not cls._solvers:
            cls.discover_solvers()
        return domain_type in cls._solvers

    @classmethod
    def get_solver(cls, domain_type: str) -> Optional[BaseDomainSolver]:
        if not cls._solvers:
            cls.discover_solvers()
        solver_cls = cls._solvers.get(domain_type)
        return solver_cls() if solver_cls else None

    @classmethod
    def list_domains(cls) -> list[str]:
        return list(cls._solvers.keys())

    @classmethod
    def discover_solvers(cls, package_name: str = "agent.domains"):
        """Descobre e carrega automaticamente todos os solvers no pacote agent.domains (OCP)."""
        import importlib
        import pkgutil
        import sys
        modules_to_load = ["web", "privesc", "forensics", "pwn_rev", "crypto", "code_assist", "ml_supply"]
        for mod in modules_to_load:
            full_name = f"{package_name}.{mod}"
            try:
                if full_name in sys.modules:
                    importlib.reload(sys.modules[full_name])
                else:
                    importlib.import_module(full_name)
            except Exception:
                pass


def register_solver(domain_type: str):
    """Decorador para registrar novos Solvers no Registry automaticamente."""
    def decorator(cls: Type[BaseDomainSolver]):
        DomainSolverRegistry.register(domain_type, cls)
        return cls
    return decorator
