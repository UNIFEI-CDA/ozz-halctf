"""
Ozz — Circuit Breaker & Resilience Module
Prevents infinite loops, manages failures gracefully, and ensures
the agent can run for 8+ hours without human intervention.

Patterns implemented:
- Circuit Breaker (open/half-open/closed)
- Exponential Backoff with Jitter
- Tool-specific failure tracking
- Action deduplication with sliding window
- Graceful degradation
"""

import logging
import random
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger("ozz.resilience")


class CircuitState(Enum):
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Failing, reject calls
    HALF_OPEN = "half_open" # Testing recovery


@dataclass
class CircuitBreaker:
    """
    Per-tool circuit breaker.
    
    After `failure_threshold` consecutive failures, the circuit OPENS
    and rejects calls for `recovery_timeout` seconds.
    After recovery timeout, allows one test call (HALF_OPEN).
    If test succeeds, closes the circuit. If fails, re-opens.
    """
    name: str
    failure_threshold: int = 3
    recovery_timeout: float = 60.0
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    last_failure_time: float = 0.0
    success_count: int = 0
    total_calls: int = 0
    total_failures: int = 0

    def can_execute(self) -> bool:
        """Check if the circuit allows execution."""
        self.total_calls += 1

        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            if time.time() - self.last_failure_time >= self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                logger.info(f"⚡ Circuit '{self.name}' → HALF_OPEN (testing recovery)")
                return True
            return False

        if self.state == CircuitState.HALF_OPEN:
            return True

        return False

    def record_success(self):
        """Record a successful call."""
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            logger.info(f"✅ Circuit '{self.name}' → CLOSED (recovered)")
        self.success_count += 1
        self.failure_count = 0

    def record_failure(self):
        """Record a failed call."""
        self.failure_count += 1
        self.total_failures += 1
        self.last_failure_time = time.time()

        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            logger.warning(f"🔴 Circuit '{self.name}' → OPEN (failures={self.failure_count}, "
                         f"recovery in {self.recovery_timeout}s)")

    def get_stats(self) -> dict:
        """Get circuit statistics."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "total_calls": self.total_calls,
            "total_failures": self.total_failures,
            "success_count": self.success_count,
        }


class ExponentialBackoff:
    """
    Exponential backoff with jitter for retry logic.
    
    delay = min(base_delay * 2^attempt + random_jitter, max_delay)
    """

    def __init__(self, base_delay: float = 1.0, max_delay: float = 120.0,
                 jitter_range: float = 0.5):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter_range = jitter_range

    def get_delay(self, attempt: int) -> float:
        """Calculate delay for the given attempt number (0-indexed)."""
        delay = self.base_delay * (2 ** attempt)
        jitter = random.uniform(-self.jitter_range, self.jitter_range) * delay
        delay = min(delay + jitter, self.max_delay)
        return max(0.1, delay)


class ActionDeduplicator:
    """
    Sliding window action deduplication.
    
    Prevents the agent from repeating the same action on the same target
    within a configurable time window.
    """

    def __init__(self, window_size: int = 10, max_repeats: int = 2,
                 time_window: float = 300.0):
        self.window_size = window_size
        self.max_repeats = max_repeats
        self.time_window = time_window
        self.action_history: deque = deque(maxlen=200)

    def is_duplicate(self, action: str, target: str) -> bool:
        """Check if this action+target combo was recently executed too many times."""
        now = time.time()
        key = f"{action}:{target}"

        # Count occurrences within time window
        count = sum(
            1 for entry in self.action_history
            if entry["key"] == key and (now - entry["time"]) < self.time_window
        )

        return count >= self.max_repeats

    def record(self, action: str, target: str, success: bool = True):
        """Record an action execution."""
        self.action_history.append({
            "key": f"{action}:{target}",
            "time": time.time(),
            "success": success,
        })

    def get_fresh_actions(self, action: str, target: str) -> list[str]:
        """Suggest alternative actions when the current one is deduplicated."""
        alternatives = {
            "nmap": ["quick_scan", "curl", "shell"],
            "curl": ["wget", "shell", "nmap"],
            "sqlmap": ["shell", "curl", "searchsploit"],
            "ssh": ["shell", "hydra", "nc"],
            "quick_scan": ["nmap", "curl", "whatweb"],
            "gobuster": ["nikto", "curl", "dirb"],
        }
        return alternatives.get(action, ["shell", "quick_scan"])


class GracefulDegradation:
    """
    Graceful degradation manager.
    
    When multiple tools fail, the agent falls back to simpler,
    more reliable approaches.
    """

    # Degradation levels (higher = more degraded)
    LEVELS = {
        0: "full",          # All tools available
        1: "reduced",       # Some advanced tools failing
        2: "basic",         # Only basic tools (curl, nc, shell)
        3: "minimal",       # Only shell commands
        4: "emergency",     # Stop and report
    }

    def __init__(self):
        self.current_level = 0
        self.tool_failures: dict[str, int] = defaultdict(int)
        self.degradation_threshold = 5

    def record_failure(self, tool: str):
        """Record a tool failure and check if we need to degrade."""
        self.tool_failures[tool] += 1
        failed_tools = sum(1 for f in self.tool_failures.values() if f >= self.degradation_threshold)

        if failed_tools >= 5 and self.current_level < 4:
            self.current_level = min(self.current_level + 1, 4)
            logger.warning(f"⚠️ Graceful degradation → Level {self.current_level} ({self.LEVELS[self.current_level]})")

    def record_success(self, tool: str):
        """Record a tool success. May improve degradation level."""
        if tool in self.tool_failures:
            self.tool_failures[tool] = max(0, self.tool_failures[tool] - 1)

        # Check if we can improve
        failed_tools = sum(1 for f in self.tool_failures.values() if f >= self.degradation_threshold)
        if failed_tools < 3 and self.current_level > 0:
            self.current_level = max(0, self.current_level - 1)
            logger.info(f"📈 Graceful degradation improved → Level {self.current_level} ({self.LEVELS[self.current_level]})")

    def is_tool_available(self, tool: str) -> bool:
        """Check if a tool is available at the current degradation level."""
        if self.current_level == 0:
            return True
        if self.current_level == 1:
            return tool not in {"gobuster", "nikto", "whatweb", "sqlmap"}
        if self.current_level == 2:
            return tool in {"curl", "nc", "shell", "wget", "grep", "file", "strings", "python"}
        if self.current_level == 3:
            return tool in {"shell", "python"}
        return False  # Emergency: nothing available

    def get_available_tools(self) -> list[str]:
        """Get list of available tools at current degradation level."""
        all_tools = ["nmap", "curl", "nc", "shell", "wget", "grep", "file",
                     "strings", "python", "ssh", "sqlmap", "gobuster", "nikto",
                     "whatweb", "hydra", "searchsploit", "exiftool", "binwalk"]
        return [t for t in all_tools if self.is_tool_available(t)]

    def get_status(self) -> dict:
        """Get current degradation status."""
        return {
            "level": self.current_level,
            "status": self.LEVELS[self.current_level],
            "available_tools": self.get_available_tools(),
            "failed_tools": dict(self.tool_failures),
        }


class ResilienceManager:
    """
    Central resilience manager combining all patterns.
    
    Used by the agent to check if actions are allowed, track failures,
    and manage recovery.
    """

    def __init__(self):
        self.circuit_breakers: dict[str, CircuitBreaker] = {}
        self.backoff = ExponentialBackoff()
        self.deduplicator = ActionDeduplicator()
        self.degradation = GracefulDegradation()
        self.start_time = time.time()
        self.max_runtime = 8 * 3600  # 8 hours

    def get_circuit_breaker(self, tool: str) -> CircuitBreaker:
        """Get or create a circuit breaker for a tool."""
        if tool not in self.circuit_breakers:
            self.circuit_breakers[tool] = CircuitBreaker(
                name=tool,
                failure_threshold=3,
                recovery_timeout=60.0
            )
        return self.circuit_breakers[tool]

    def can_execute(self, action: str, target: str) -> tuple[bool, str]:
        """
        Check if an action can be executed.
        
        Returns (allowed, reason) tuple.
        """
        # Check runtime limit
        elapsed = time.time() - self.start_time
        if elapsed >= self.max_runtime:
            return False, f"Maximum runtime ({self.max_runtime/3600:.1f}h) exceeded"

        # Check degradation
        if not self.degradation.is_tool_available(action):
            return False, f"Tool '{action}' unavailable at degradation level {self.degradation.current_level}"

        # Check circuit breaker
        cb = self.get_circuit_breaker(action)
        if not cb.can_execute():
            remaining = cb.recovery_timeout - (time.time() - cb.last_failure_time)
            return False, f"Circuit breaker OPEN for '{action}' (recovery in {remaining:.0f}s)"

        # Check deduplication
        if self.deduplicator.is_duplicate(action, target):
            alternatives = self.deduplicator.get_fresh_actions(action, target)
            return False, f"Action '{action}' on '{target}' deduplicated. Try: {alternatives}"

        return True, "OK"

    def record_success(self, action: str, target: str):
        """Record a successful action."""
        self.get_circuit_breaker(action).record_success()
        self.deduplicator.record(action, target, success=True)
        self.degradation.record_success(action)

    def record_failure(self, action: str, target: str):
        """Record a failed action."""
        self.get_circuit_breaker(action).record_failure()
        self.deduplicator.record(action, target, success=False)
        self.degradation.record_failure(action)

    def get_backoff_delay(self, attempt: int) -> float:
        """Get exponential backoff delay for retry."""
        return self.backoff.get_delay(attempt)

    def should_stop(self) -> tuple[bool, str]:
        """Check if the agent should stop entirely."""
        elapsed = time.time() - self.start_time
        if elapsed >= self.max_runtime:
            return True, f"Maximum runtime reached ({elapsed/3600:.1f}h)"

        if self.degradation.current_level >= 4:
            return True, "Emergency degradation level reached"

        return False, ""

    def get_status(self) -> dict:
        """Get full resilience status."""
        elapsed = time.time() - self.start_time
        return {
            "runtime_seconds": elapsed,
            "runtime_hours": elapsed / 3600,
            "max_runtime_hours": self.max_runtime / 3600,
            "degradation": self.degradation.get_status(),
            "circuit_breakers": {name: cb.get_stats() for name, cb in self.circuit_breakers.items()},
            "deduplicator": {
                "history_size": len(self.deduplicator.action_history),
                "max_repeats": self.deduplicator.max_repeats,
            },
        }
