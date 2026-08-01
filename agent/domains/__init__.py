"""
Package init for domain solvers (DDD Bounded Contexts)
"""
from .web import WebDomainSolver
from .privesc import PrivescDomainSolver
from .forensics import ForensicsDomainSolver
from .pwn_rev import PwnRevDomainSolver
from .crypto import CryptoDomainSolver
from .code_assist import CodeAssistDomainSolver
from .ml_supply import MLSupplyChainSolver

__all__ = [
    "WebDomainSolver",
    "PrivescDomainSolver",
    "ForensicsDomainSolver",
    "PwnRevDomainSolver",
    "CryptoDomainSolver",
    "CodeAssistDomainSolver",
    "MLSupplyChainSolver",
]
