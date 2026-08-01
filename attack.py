"""
OZZ — Autonomous Attack Entry Point
Uses the agent's ReAct loop to discover and exploit targets.

NO hardcoded credentials, URLs, or attack sequences.
The LLM decides everything based on the targets provided.

Usage:
  python attack.py --targets 10.0.0.10,10.0.0.20 [--scoreboard http://host:9090]
  TARGETS=10.0.0.10,10.0.0.20 python attack.py
"""

import argparse
import json
import logging
import os
import sys
import time

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("ozz.attack")


def parse_targets(args) -> list[str]:
    """Parse targets from args, environment, or config file."""
    targets = []

    # From command line
    if args.targets:
        targets.extend([t.strip() for t in args.targets.split(",") if t.strip()])

    # From environment
    env_targets = os.environ.get("TARGETS", "")
    if env_targets:
        targets.extend([t.strip() for t in env_targets.split(",") if t.strip()])

    # From file
    targets_file = args.targets_file or os.environ.get("TARGETS_FILE", "")
    if targets_file and os.path.exists(targets_file):
        with open(targets_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)

    if not targets:
        logger.error("No targets specified! Use --targets, TARGETS env, or TARGETS_FILE.")
        sys.exit(1)

    return list(dict.fromkeys(targets))  # Deduplicate


def main():
    parser = argparse.ArgumentParser(
        description="Ozz — Autonomous CTF Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python attack.py --targets 10.0.0.10,10.0.0.20
  python attack.py --targets 10.0.0.10 --scoreboard http://scoreboard:9090
  TARGETS=10.0.0.10 python attack.py
        """,
    )
    parser.add_argument("--targets", "-t", help="Comma-separated target IPs/hostnames")
    parser.add_argument("--targets-file", "-f", help="File with targets (one per line)")
    parser.add_argument("--scoreboard", "-s", default=os.environ.get("SCOREBOARD_URL", ""),
                        help="Scoreboard URL for flag submission")
    parser.add_argument("--model", "-m", default=os.environ.get("MODEL_PATH", "/models"),
                        help="Model path for vLLM")
    parser.add_argument("--max-iterations", type=int,
                        default=int(os.environ.get("OZZ_MAX_ITERATIONS", "200")),
                        help="Maximum agent iterations")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Set env vars from args
    if args.scoreboard:
        os.environ["SCOREBOARD_URL"] = args.scoreboard
    os.environ["OZZ_MAX_ITERATIONS"] = str(args.max_iterations)

    # Banner
    print("""
  ╔══════════════════════════════════════════════╗
  ║  🏴 OZZ — Autonomous CTF Agent               ║
  ║  DEF CON 34 AI Village                       ║
  ╚══════════════════════════════════════════════╝
    """)

    # Parse targets
    targets = parse_targets(args)
    logger.info(f"Targets: {targets}")
    logger.info(f"Scoreboard: {args.scoreboard or 'disabled'}")
    logger.info(f"Max iterations: {args.max_iterations}")

    # Import and run
    from agent import OzzAgent

    agent = OzzAgent(
        targets=targets,
        model_path=args.model,
        scoreboard_url=args.scoreboard,
    )

    start_time = time.time()
    agent.run()
    elapsed = time.time() - start_time

    # Summary
    print(f"\n{'='*60}")
    print(f"  Run complete in {elapsed:.1f}s")
    print(f"  Flags found: {len(agent.plan.flags_found)}")
    print(f"  Flags submitted: {len(agent.scoreboard.submitted)}")
    print(f"  Iterations: {agent.run_metrics['iterations']}")
    print(f"{'='*60}")

    # Return exit code based on success
    sys.exit(0 if agent.plan.flags_found else 1)


if __name__ == "__main__":
    main()
