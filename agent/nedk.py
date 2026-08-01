"""
Ozz — Neural Executive Dynamic Kernel (NEDK)
MNHI 3.5 Formal Implementation: 4 Mathematical Spaces

    dS/dt = F(S, E, X) + u_Ψ + u_Ω

The NEDK wraps (composes with) OzzAgent without replacing its ReAct loop.
It provides the executive regulation layer: prioritization, attention,
risk assessment, loop detection, and state rollback.
"""

import copy
import hashlib
import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Optional

logger = logging.getLogger("ozz.nedk")


# ============================================================
# S(t) — STATE SPACE
# ============================================================

class StateSpace:
    """
    S(t) = (G(t), Φ(t), τ(t), J(t), I(t))

    G(t): Relational graph of targets, ports, services, vulns
    Φ(t): Contextual understanding per entity
    τ(t): Canonical SHA-256 identity per entity
    J(t): Active executive workspace (current plan)
    I(t): Execution invariants (flags, time, constraints)
    """

    def __init__(self):
        self.graph: dict = {}           # G(t)
        self.context: dict = {}         # Φ(t)
        self._identities: dict = {}     # τ(t) cache
        self.workspace: dict = {}       # J(t)
        self.invariants: dict = {       # I(t)
            "flags_found": 0,
            "flags": [],
            "start_time": time.time(),
            "max_iterations": 200,
            "do_not_destroy": True,
        }

    def register_host(self, host: str, ports: list = None,
                      services: dict = None, vulns: list = None):
        """Update G(t) with a discovered host."""
        ports = sorted(ports or [])
        self.graph[host] = {
            "ports": ports,
            "services": services or {},
            "vulns": vulns or [],
            "compromised": False,
            "credentials": [],
            "flags": [],
        }
        # Invalidate τ cache for this host
        self._identities.pop(host, None)

    def canonical_hash(self, host: str) -> str:
        """
        τ(t) = SHA-256(CanonicalSerialize(Sort(Normalize(entity))))
        Deterministic identity regardless of insertion order.
        """
        if host in self._identities:
            return self._identities[host]

        data = self.graph.get(host, {})
        # Normalize: sort ports, sort service keys
        normalized = {
            "host": host,
            "ports": sorted(data.get("ports", [])),
            "services": dict(sorted(data.get("services", {}).items())),
            "vulns": sorted(data.get("vulns", [])),
        }
        canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        tau = hashlib.sha256(canonical.encode()).hexdigest()
        self._identities[host] = tau
        return tau

    def record_flag(self, flag: str):
        """Record a captured flag in I(t). Idempotent."""
        if flag not in self.invariants["flags"]:
            self.invariants["flags"].append(flag)
            self.invariants["flags_found"] = len(self.invariants["flags"])

    def snapshot(self) -> dict:
        """σ(t) — Deep copy of the entire state for rollback."""
        return {
            "graph": copy.deepcopy(self.graph),
            "context": copy.deepcopy(self.context),
            "workspace": copy.deepcopy(self.workspace),
            "invariants": copy.deepcopy(self.invariants),
        }

    def restore(self, snapshot: dict):
        """Restore state from σ(t-1)."""
        self.graph = copy.deepcopy(snapshot["graph"])
        self.context = copy.deepcopy(snapshot["context"])
        self.workspace = copy.deepcopy(snapshot["workspace"])
        self.invariants = copy.deepcopy(snapshot["invariants"])
        self._identities.clear()


# ============================================================
# E(t) — EVENT SPACE (Event Mesh)
# ============================================================

class EventMesh:
    """
    Pub/sub bus for δS perturbations.

    Event Classes:
      CLASS_I   — Direct observation (tool output)
      CLASS_II  — Derived inference (agent reasoning)
      CLASS_III — External signal (time, other agents)
    """

    def __init__(self):
        self.subscribers: dict[str, list[Callable]] = defaultdict(list)
        self.history: list[dict] = []

    def subscribe(self, event_class: str, handler: Callable):
        """Register a handler for an event class."""
        self.subscribers[event_class].append(handler)

    def publish(self, event_class: str, delta: dict):
        """Publish a δS perturbation to all subscribers of this class."""
        event = {
            "class": event_class,
            "delta": delta,
            "timestamp": time.time(),
        }
        self.history.append(event)
        for handler in self.subscribers.get(event_class, []):
            handler(delta)

    def recent(self, n: int = 10) -> list[dict]:
        """Get the N most recent events."""
        return self.history[-n:]


# ============================================================
# X(t) — EXECUTIVE SPACE
# ============================================================

# Risk weights by action category
_RISK_WEIGHTS = {
    "nmap": 0.1, "quick_scan": 0.1, "whatweb": 0.1,
    "curl": 0.2, "gobuster": 0.3, "nikto": 0.3, "dirb": 0.3,
    "shell": 0.5, "sqlmap": 0.6, "hydra": 0.7,
    "searchsploit": 0.2, "submit_flag": 0.0,
}


class Executive:
    """
    X(t) = (Ω, A, P, R)

    Ω — Scheduler: which target to attack now
    A — Attention: which aspect to focus on
    P — Prioritizer: rank actions by tactical gain
    R — Risk Assessor: evaluate detection risk
    """

    def schedule(self, state: StateSpace) -> str:
        """
        Ω — Select the target with highest potential gain.
        Score = (num_ports × 2) + (num_vulns × 5) - (10 if compromised)
        """
        best_target = ""
        best_score = -1
        for host, data in state.graph.items():
            score = len(data.get("ports", [])) * 2
            score += len(data.get("vulns", [])) * 5
            if data.get("compromised"):
                score -= 10
            if score > best_score:
                best_score = score
                best_target = host
        return best_target

    def attend(self, state: StateSpace, target: str) -> dict:
        """A — Determine which aspect of the target to focus on."""
        data = state.graph.get(target, {})
        if not data.get("ports"):
            return {"focus": "recon", "reason": "No ports discovered yet"}
        if data.get("vulns"):
            return {"focus": "exploit", "reason": f"Vulns found: {data['vulns']}"}
        if data.get("services"):
            return {"focus": "enumerate", "reason": f"Services found: {list(data['services'].values())}"}
        return {"focus": "recon", "reason": "Need deeper scanning"}

    def prioritize(self, actions: list[dict]) -> list[dict]:
        """P — Rank actions by tactical gain score."""
        scored = []
        for action in actions:
            action_name = action.get("action", "")
            phase = action.get("phase", "recon")
            phase_weight = {"recon": 1.0, "enumerate": 1.5, "exploit": 3.0, "pivot": 2.0}.get(phase, 1.0)
            risk = _RISK_WEIGHTS.get(action_name, 0.5)
            score = phase_weight * (1.0 - risk)
            scored.append({**action, "score": round(score, 3)})
        return sorted(scored, key=lambda x: x["score"], reverse=True)

    def assess_risk(self, action: dict) -> float:
        """R — Return risk score between 0.0 (safe) and 1.0 (dangerous)."""
        action_name = action.get("action", "")
        return _RISK_WEIGHTS.get(action_name, 0.5)

    def compute_control(self, state: StateSpace) -> dict:
        """
        u_Ω — Produce the executive control signal.
        Determines which target to focus and in which phase.
        """
        target = self.schedule(state)
        if not target:
            return {"target": "", "phase": "done", "signal": "no_targets"}
        attention = self.attend(state, target)
        return {
            "target": target,
            "phase": attention["focus"],
            "reason": attention["reason"],
            "signal": "active",
        }


# ============================================================
# Ψ-STABILIZER
# ============================================================

class PsiStabilizer:
    """
    Predictive stabilizer and anti-loop detector.
    Generates u_Ψ perturbations when stagnation is detected.
    """

    def __init__(self, threshold: int = 3):
        self.threshold = threshold

    def detect_loop(self, history: list[dict]) -> bool:
        """Detect N+ consecutive identical actions (same action+target)."""
        if len(history) < self.threshold:
            return False
        recent = history[-self.threshold:]
        signatures = [f"{h.get('action', '')}:{h.get('target', '')}" for h in recent]
        return len(set(signatures)) == 1

    def generate_perturbation(self, state: StateSpace) -> dict:
        """
        u_Ψ — Generate a random perturbation to break stagnation.
        Selects a different target or suggests a phase change.
        """
        targets = list(state.graph.keys())
        if not targets:
            return {"action": "wait", "reason": "No targets available"}

        # Pick the least-explored target
        least_explored = min(
            targets,
            key=lambda t: len(state.graph[t].get("vulns", [])) + len(state.graph[t].get("flags", []))
        )
        return {
            "action": "switch_target",
            "target": least_explored,
            "reason": f"Loop detected — switching focus to {least_explored}",
        }


# ============================================================
# NEDK — NEURAL EXECUTIVE DYNAMIC KERNEL
# ============================================================

class NEDK:
    """
    The Orchestrating Mind.

    dS/dt = F(S, E, X) + u_Ψ + u_Ω

    Composes with OzzAgent (does NOT replace it).
    Provides executive regulation: prioritization, attention,
    risk assessment, loop detection, and state snapshot/rollback.
    """

    def __init__(self, targets: list[str], model_path: str = "/models",
                 dry_run: bool = False):
        self.targets = targets
        self.model_path = model_path
        self.dry_run = dry_run

        # The 4 Mathematical Spaces
        self.state = StateSpace()
        self.events = EventMesh()
        self.executive = Executive()
        self.stabilizer = PsiStabilizer()

        # Initialize S(0) with targets
        for target in targets:
            self.state.register_host(target)

        # Subscribe NEDK to EventMesh CLASS_I perturbations (Recon/Ingestion Adapter)
        self.events.subscribe("CLASS_I", self._handle_class_i_event)

        # Action history for loop detection
        self.action_history: list[dict] = []
        self.snapshots: list[dict] = []
        self.iteration_count = 0

        logger.info(f"🧠 NEDK initialized. Targets: {targets}")

    def _handle_class_i_event(self, event_data: dict):
        """
        Handler para eventos CLASS_I (ReconAdapter / Ingestão).
        Atualiza dinamicamente o Grafo G(t) e recalcula τ(t) no StateSpace S(t).
        """
        observations = []
        if hasattr(event_data, "observations"):
            observations = event_data.observations
        elif isinstance(event_data, dict) and "observations" in event_data:
            observations = event_data["observations"]

        for obs in observations:
            entity_key = getattr(obs, "entity_key", "") or obs.get("entity_key", "")
            attrs = getattr(obs, "attributes", {}) or obs.get("attributes", {})
            
            host = attrs.get("host") or attrs.get("ip") or attrs.get("domain")
            if not host or host == "target":
                host = entity_key.split(":")[0] if ":" in entity_key and entity_key.split(":")[0] != "target" else ""
            if not host:
                host = self.targets[0] if self.targets else "unknown"

            port = attrs.get("port")
            service = attrs.get("service")

            # Atualiza o G(t) no StateSpace
            existing_host = self.state.graph.get(host, {"ports": [], "services": {}, "vulns": []})
            ports = set(existing_host.get("ports", []))
            services = existing_host.get("services", {})

            if port:
                ports.add(int(port))
            if service and port:
                services[str(port)] = service

            self.state.register_host(
                host=host,
                ports=list(ports),
                services=services,
                vulns=existing_host.get("vulns", [])
            )
            logger.info(f"📡 NEDK S(t) atualizado via evento CLASS_I: host={host}, ports={list(ports)}")

    def run(self, agent=None):
        """
        Main NEDK execution loop.
        Orchestrates OzzAgent through the 4 mathematical spaces.
        Composes with an existing agent instance (preferred) or creates one.
        """
        if self.dry_run:
            logger.info("NEDK dry_run mode — skipping agent execution")
            return

        logger.info("🧠 NEDK activating Neural Executive Dynamic Kernel...")

        # Take initial snapshot σ(0)
        self.snapshots.append(self.state.snapshot())

        # Compute initial control signal u_Ω
        control = self.executive.compute_control(self.state)
        logger.info(f"🎯 u_Ω initial: target={control['target']}, phase={control['phase']}")

        if agent is None:
            from .core import OzzAgent
            agent = OzzAgent(targets=self.targets, model_path=self.model_path, nedk=self)

        # Run the agent
        agent.run()

        # Post-execution: harvest results from agent into S(t)
        for flag in agent.plan.flags_found:
            self.state.record_flag(flag)
            self.events.publish("CLASS_I", {"type": "flag_captured", "flag": flag})

        self.iteration_count = len(agent.history)

        # Generate final report
        report = self.generate_report()
        logger.info(f"🧠 NEDK complete. Report: {json.dumps(report, indent=2)}")

    def generate_report(self) -> dict:
        """Generate the final execution report."""
        return {
            "status": "SUCCESS" if self.state.invariants["flags_found"] > 0 else "COMPLETE",
            "agent": "Ozz",
            "kernel": "NEDK v1.0",
            "architecture": "MNHI 3.5",
            "targets": self.targets,
            "flags_found": self.state.invariants["flags_found"],
            "flags": self.state.invariants["flags"],
            "iterations": self.iteration_count,
            "snapshots": len(self.snapshots),
            "events_processed": len(self.events.history),
        }
