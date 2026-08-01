"""Ozz — Entry point for the autonomous agent."""

import argparse
import io
import json
import os
import sys
import logging
import time
import signal
import tempfile
from agent import OzzAgent

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(tempfile.gettempdir(), "ozz.log")),
    ]
)
logger = logging.getLogger("ozz")


def wait_for_model(timeout: int = 300):
    """Wait for the LLM model server to be ready."""
    import requests
    port = int(os.environ.get("VLLM_PORT", "8000"))
    api_url = f"http://localhost:{port}/v1/models"

    logger.info(f"Waiting for model server at {api_url}...")
    start = time.time()

    while time.time() - start < timeout:
        try:
            resp = requests.get(api_url, timeout=5)
            if resp.status_code == 200:
                models = resp.json().get("data", [])
                if models:
                    logger.info(f"Model ready: {models[0].get('id', 'unknown')}")
                    return True
        except requests.ConnectionError:
            pass
        except Exception as e:
            logger.debug(f"Waiting... {e}")

        time.sleep(2)

    logger.error(f"Model server not ready after {timeout}s")
    return False


def parse_targets() -> list[str]:
    """Parse targets from environment or arguments."""
    targets = []

    # From environment variable
    env_targets = os.environ.get("TARGETS", "")
    if env_targets:
        targets.extend([t.strip() for t in env_targets.split(",") if t.strip()])

    # From file
    targets_file = os.environ.get("TARGETS_FILE", "/config/targets.txt")
    if os.path.exists(targets_file):
        with open(targets_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)

    # From command line args
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--target", dest="targets", action="append")
    parser.add_argument("positional_targets", nargs="*")
    args, _ = parser.parse_known_args(sys.argv[1:])

    if args.targets:
        targets.extend(args.targets)
    if args.positional_targets:
        targets.extend(args.positional_targets)

    if not targets:
        logger.error("No targets specified! Set TARGETS env or pass as arguments.")
        sys.exit(1)

    # Deduplicate
    targets = list(dict.fromkeys(targets))
    logger.info(f"Targets: {targets}")
    return targets


def main():
    """Main entry point."""
    logger.info("="*58)
    logger.info("  OZZ — HALctf Autonomous Pentesting Agent")
    logger.info("  DEF CON 34 AI Village")
    logger.info("="*60)

    # Graceful shutdown
    def signal_handler(sig, frame):
        logger.info("Shutting down gracefully...")
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Wait for model
    if not wait_for_model():
        logger.error("Cannot start without model server. Exiting.")
        sys.exit(1)

    # Parse targets
    targets = parse_targets()

    # Get model path
    model_path = os.environ.get("MODEL_PATH", "/models")

    # Get scoreboard URL
    scoreboard_url = os.environ.get("SCOREBOARD_URL", "")

    # Create and run agent
    agent = OzzAgent(targets=targets, model_path=model_path, scoreboard_url=scoreboard_url)
    logger.info("Starting autonomous run with observability enabled.")
    agent.run()

    metrics = agent.memory.get_run_metrics(run_id=agent.run_id)
    logger.info("Run summary: %s", json.dumps(metrics, default=str))
    logger.info("Ozz finished.")


if __name__ == "__main__":
    main()
