#!/usr/bin/env python3
"""
RL Scorer runner - executes scoring cycles every 5 minutes.
"""
import asyncio
import logging
import os
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [rl-scorer] %(levelname)s: %(message)s",
)
logger = logging.getLogger("rl-scorer")

# Initialize DB
from src.models import init_db
init_db()

from src.rl_scorer import run_scoring_cycle

INTERVAL = int(os.environ.get("SCORER_INTERVAL", "300"))


def main():
    logger.info("RL Scorer started (interval=%ds, ES=%s)", INTERVAL, os.environ.get("ES_URL", "?"))
    while True:
        try:
            asyncio.run(run_scoring_cycle())
        except Exception as e:
            logger.error("Scoring cycle error: %s", e, exc_info=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
