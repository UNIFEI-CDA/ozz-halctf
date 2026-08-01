"""Ozz — HALctf Autonomous Pentesting Agent"""

from .core import OzzAgent
from .llm import LLM
from .memory import Memory, ContextNamespace
from .tools import ToolRegistry, Tool, ToolResult, LeastPrivilegePolicy
from .scoreboard import ScoreboardClient
from .circuit_breaker import ResilienceManager
from .network_discovery import NetworkDiscovery
from .provenance import ProvenanceTracker, ProvenanceRecord
from .audit import AuditLogger, AuditEntry
from .contamination import ContaminationDetector, ContaminationEvent
from .deception import BifurcationEngine, integrate_deception
from .fingerprinting import BehavioralFingerprint, create_fingerprinter
from .redteam_report import ReportBuilder, ReportManager, RedTeamReport
from .reports import ActionReportBuilder
from .self_test import ScaleTestPipeline, create_self_test, run_quick_self_test
from .context_engine import ContextEngine
from .browser import BrowserManager, BrowserTool, BrowserConfig, create_browser_tool
from .metrics import MetricsCollector, MetricsIntegration
from .policy_mapper import PolicyMapper
from .scenario_generator import ScenarioGenerator
from .artifact_generator import ArtifactGenerator
from .telemetry import (
    TelemetryMonitor, InjectionDetector, PromptClassification,
    TelemetrySanitizer, SanitizationResult,
    DeterministicEvaluator, SecurityPredicate, PredicateResult,
    AuditTrail, AuditEntry,
)

__version__ = "0.5.0"
__all__ = [
    "OzzAgent", "LLM", "Memory", "ContextNamespace",
    "ToolRegistry", "Tool", "ToolResult", "LeastPrivilegePolicy",
    "ScoreboardClient", "ResilienceManager", "NetworkDiscovery",
    "ProvenanceTracker", "ProvenanceRecord",
    "AuditLogger", "AuditEntry",
    "ContaminationDetector", "ContaminationEvent",
    # Track E: Red Team Methodology & Deception at Scale
    "BifurcationEngine", "integrate_deception",
    "BehavioralFingerprint", "create_fingerprinter",
    "ReportBuilder", "ReportManager", "RedTeamReport",
    "ScaleTestPipeline", "create_self_test", "run_quick_self_test",
    # Track A: Context Engineering, Browser, Reports, Metrics
    "ContextEngine", "BrowserManager", "BrowserTool", "BrowserConfig",
    "create_browser_tool", "ActionReportBuilder", "MetricsCollector", "MetricsIntegration",
    # Track D: SOC & Telemetry Defense Integration
    "PolicyMapper", "ScenarioGenerator", "ArtifactGenerator",
    "TelemetryMonitor", "InjectionDetector", "PromptClassification",
    "TelemetrySanitizer", "SanitizationResult",
    "DeterministicEvaluator", "SecurityPredicate", "PredicateResult",
    "AuditTrail", "AuditEntry",
]
