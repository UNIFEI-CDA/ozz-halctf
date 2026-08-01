"""
Ozz — Autonomous Orchestrator
The main loop for DEF CON 34 HALctf competition.

Handles:
- Network discovery of unknown targets
- Autonomous attack loop with phase management
- Flag submission via scoreboard API
- Circuit breaker and graceful degradation
- 8+ hour continuous operation
- Round adaptation (targets change between rounds)
- Heartbeat/liveness monitoring
"""

import json
import logging
import os
import signal
import sys
import time
from typing import Optional

from .core import OzzAgent, AgentState
from .circuit_breaker import ResilienceManager
from .network_discovery import NetworkDiscovery
from .scoreboard import ScoreboardClient

logger = logging.getLogger("ozz.orchestrator")


class AutonomousOrchestrator:
    """
    Main orchestrator for autonomous CTF competition.
    
    Lifecycle:
    1. STARTUP: Initialize components, discover network
    2. DISCOVERY: Find all live hosts and services
    3. ATTACK: Run agent loop against discovered targets
    4. SUBMIT: Submit found flags to scoreboard
    5. ADAPT: Handle round changes, new targets
    6. RECOVER: Handle failures, circuit breaker trips
    7. REPORT: Generate final competition report
    """

    def __init__(self):
        # Configuration from environment
        self.targets = self._parse_targets()
        self.model_path = os.environ.get("MODEL_PATH", "/models")
        self.round_duration = int(os.environ.get("ROUND_DURATION", "1800"))  # 30 min default
        self.max_runtime = int(os.environ.get("MAX_RUNTIME", "28800"))  # 8 hours
        self.discovery_interval = int(os.environ.get("DISCOVERY_INTERVAL", "600"))  # 10 min
        self.scoreboard_url = os.environ.get("SCOREBOARD_URL", "")

        # Components
        self.resilience = ResilienceManager()
        self.scoreboard = ScoreboardClient()
        self.discovery = NetworkDiscovery()

        # State
        self.current_round = 0
        self.start_time = 0.0
        self.last_discovery = 0.0
        self.all_flags: list[str] = []
        self.round_reports: list[dict] = []
        self.running = True

        # Graceful shutdown
        signal.signal(signal.SIGINT, self._shutdown_handler)
        signal.signal(signal.SIGTERM, self._shutdown_handler)

    def _shutdown_handler(self, sig, frame):
        """Handle graceful shutdown."""
        logger.info(f"Received signal {sig}, shutting down gracefully...")
        self.running = False

    def _parse_targets(self) -> list[str]:
        """Parse targets from environment."""
        targets = []
        env_targets = os.environ.get("TARGETS", "")
        if env_targets:
            targets.extend([t.strip() for t in env_targets.split(",") if t.strip()])

        targets_file = os.environ.get("TARGETS_FILE", "/config/targets.txt")
        if os.path.exists(targets_file):
            with open(targets_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)

        return list(dict.fromkeys(targets))

    def run(self):
        """Main orchestrator entry point."""
        self.start_time = time.time()
        logger.info("=" * 60)
        logger.info("🏴 OZZ — AUTONOMOUS ORCHESTRATOR")
        logger.info("  DEF CON 34 AI Village — HALctf")
        logger.info("=" * 60)
        logger.info(f"  Configured targets: {self.targets}")
        logger.info(f"  Max runtime: {self.max_runtime / 3600:.1f}h")
        logger.info(f"  Round duration: {self.round_duration}s")
        logger.info(f"  Discovery interval: {self.discovery_interval}s")
        logger.info(f"  Scoreboard: {self.scoreboard_url or 'local only'}")
        logger.info("=" * 60)

        # Phase 1: Initial network discovery
        self._discover_targets()

        if not self.targets:
            logger.error("No targets found! Cannot proceed.")
            return

        # Phase 2: Main competition loop
        cycle_count = 0
        while self.running:
            # Check if we should stop
            should_stop, reason = self.resilience.should_stop()
            if should_stop:
                logger.info(f"Stopping: {reason}")
                break

            elapsed = time.time() - self.start_time
            if elapsed >= self.max_runtime:
                logger.info(f"Max runtime reached ({elapsed/3600:.1f}h)")
                break

            # Check for round changes (new targets)
            self._check_round_change()

            # Run one attack cycle
            cycle_count += 1
            logger.info(f"\n{'='*60}")
            logger.info(f"⚔️ ATTACK CYCLE {cycle_count} | Round {self.current_round}")
            logger.info(f"  Elapsed: {elapsed/3600:.2f}h | Targets: {len(self.targets)}")
            logger.info(f"{'='*60}")

            self._run_attack_cycle()

            # Brief pause between cycles
            time.sleep(2)

        # Phase 3: Final report
        self._generate_final_report()

    def _discover_targets(self):
        """Discover targets on the network."""
        logger.info("🔍 Phase 1: Network Discovery")
        seed = self.targets[0] if self.targets else ""

        try:
            hosts = self.discovery.discover_network(seed)
            if hosts:
                new_targets = [h.ip for h in hosts]
                # Merge with existing targets
                all_targets = list(dict.fromkeys(self.targets + new_targets))
                self.targets = all_targets
                self.last_discovery = time.time()
                logger.info(f"📡 Discovery complete: {len(hosts)} hosts, {len(self.targets)} total targets")

                # Print summary
                for h in hosts:
                    ports_str = ", ".join(f"{p}/{h.services.get(str(p), '?')}" for p in h.ports[:10])
                    logger.info(f"  📍 {h.ip}: [{ports_str}]")
            else:
                logger.warning("No hosts discovered, using configured targets")
        except Exception as e:
            logger.error(f"Discovery failed: {e}, using configured targets")

    def _check_round_change(self):
        """Check if targets have changed (new round)."""
        now = time.time()
        if now - self.last_discovery < self.discovery_interval:
            return

        logger.info("🔄 Periodic target re-discovery...")
        try:
            hosts = self.discovery.discover_network(self.targets[0] if self.targets else "")
            if hosts:
                new_ips = {h.ip for h in hosts}
                old_ips = set(self.targets)

                if new_ips != old_ips:
                    self.current_round += 1
                    added = new_ips - old_ips
                    removed = old_ips - new_ips
                    logger.info(f"🆕 Round change detected! Round {self.current_round}")
                    if added:
                        logger.info(f"  New targets: {added}")
                    if removed:
                        logger.info(f"  Removed targets: {removed}")

                    # Update targets
                    self.targets = list(new_ips)
                    self.round_reports.append({
                        "round": self.current_round,
                        "timestamp": now,
                        "targets": list(new_ips),
                        "added": list(added),
                        "removed": list(removed),
                    })

            self.last_discovery = now
        except Exception as e:
            logger.warning(f"Re-discovery failed: {e}")

    def _run_attack_cycle(self):
        """Run one attack cycle against all targets."""
        try:
            # Create agent with current targets
            agent = OzzAgent(
                targets=self.targets,
                model_path=self.model_path,
                scoreboard_url=self.scoreboard_url,
            )

            # Run the agent
            logger.info("🧠 Starting agent run...")
            agent.run()

            # Collect flags from agent
            for flag in agent.plan.flags_found:
                if flag not in self.all_flags:
                    self.all_flags.append(flag)
                    logger.info(f"🚩 NEW FLAG: {flag}")

            # Update resilience with metrics
            failures = agent.run_metrics.get("tool_failures", 0)
            if failures > 5:
                self.resilience.record_failure("agent_cycle", "all")
            else:
                self.resilience.record_success("agent_cycle", "all")

            # Log cycle summary
            logger.info(f"📊 Cycle complete: {len(agent.plan.flags_found)} flags, "
                        f"{len(agent.history)} actions, {failures} failures")

        except Exception as e:
            logger.error(f"Attack cycle failed: {e}", exc_info=True)
            self.resilience.record_failure("agent_cycle", "all")
            # Backoff before retrying
            delay = self.resilience.get_backoff_delay(1)
            logger.info(f"⏳ Backing off {delay:.1f}s before retry...")
            time.sleep(delay)

    def _generate_final_report(self):
        """Generate the final competition report."""
        elapsed = time.time() - self.start_time
        report = {
            "competition": "DEF CON 34 — HALctf",
            "agent": "Ozz",
            "architecture": "MNHI 3.5 / NEDK",
            "total_runtime_hours": elapsed / 3600,
            "total_rounds": self.current_round + 1,
            "total_flags": len(self.all_flags),
            "flags": self.all_flags,
            "round_reports": self.round_reports,
            "scoreboard_summary": self.scoreboard.get_submission_summary(),
            "resilience_summary": self.resilience.get_status(),
            "targets_final": self.targets,
        }

        # Print report
        logger.info("\n" + "=" * 60)
        logger.info("🏴 OZZ — FINAL COMPETITION REPORT")
        logger.info("=" * 60)
        logger.info(f"  Runtime: {elapsed / 3600:.2f} hours")
        logger.info(f"  Rounds: {self.current_round + 1}")
        logger.info(f"  Flags captured: {len(self.all_flags)}")
        for flag in self.all_flags:
            logger.info(f"    🚩 {flag}")
        logger.info(f"  Targets: {len(self.targets)}")
        logger.info(f"  Resilience: {self.resilience.degradation.LEVELS[self.resilience.degradation.current_level]}")
        logger.info("=" * 60)

        # Save report to file
        try:
            log_dir = os.environ.get("LOG_DIR", "/tmp/ozz")
            os.makedirs(log_dir, exist_ok=True)
            report_file = os.path.join(log_dir, "ozz_final_report.json")
            with open(report_file, "w") as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"📄 Report saved to {report_file}")
        except Exception as e:
            logger.warning(f"Could not save report: {e}")

        return report


def main():
    """Entry point for autonomous orchestrator."""
    log_dir = os.environ.get("LOG_DIR", "/tmp/ozz")
    os.makedirs(log_dir, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(os.path.join(log_dir, "ozz_orchestrator.log")),
        ]
    )

    orchestrator = AutonomousOrchestrator()
    orchestrator.run()


if __name__ == "__main__":
    main()
