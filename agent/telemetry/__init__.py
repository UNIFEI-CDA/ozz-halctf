"""
Ozz Telemetry & SOC Defense Integration (Track D)

Modules:
  - monitor:    Prompt classification, injection detection, SIEM-compatible logging
  - sanitizer:  Sanitize attacker-controlled fields before LLM/tool processing
  - evaluator:  Deterministic predicate-based security evaluation
  - audit_trail: Append-only cryptographically-chained audit log
"""

from .monitor import TelemetryMonitor, PromptClassification, InjectionDetector
from .sanitizer import TelemetrySanitizer, SanitizationResult
from .evaluator import DeterministicEvaluator, SecurityPredicate, PredicateResult
from .audit_trail import AuditTrail, AuditEntry

__all__ = [
    "TelemetryMonitor",
    "PromptClassification",
    "InjectionDetector",
    "TelemetrySanitizer",
    "SanitizationResult",
    "DeterministicEvaluator",
    "SecurityPredicate",
    "PredicateResult",
    "AuditTrail",
    "AuditEntry",
]
