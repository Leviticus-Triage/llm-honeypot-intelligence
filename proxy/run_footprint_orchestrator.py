#!/usr/bin/env python3
"""
Footprint Orchestrator runner — triggers SpiderFoot OSINT scans for
clearly malicious targeted attackers and feeds results into threat-intel/.

Runs after heuristic detector output is available (ip_reputation.json).
Default interval: 30 minutes (aligned with heuristic detector).
"""
import asyncio
import logging
import os
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [footprint] %(levelname)s: %(message)s",
)
logger = logging.getLogger("footprint")

from src.models import init_db  # noqa: E402
init_db()

from src.footprint_orchestrator import run_footprint_cycle  # noqa: E402

INTERVAL = int(os.environ.get("FOOTPRINT_INTERVAL", "1800"))


def main():
    logger.info(
        "Footprint Orchestrator started (interval=%ds, spiderfoot=%s, output=%s)",
        INTERVAL,
        os.environ.get("SPIDERFOOT_URL", "http://127.0.0.1:5001/spiderfoot"),
        os.environ.get("THREAT_DIR", "/data/ollama-proxy/threat-intel"),
    )

    while True:
        try:
            summary = asyncio.run(run_footprint_cycle())
            if summary.get("status") == "ok":
                logger.info(
                    "Cycle: candidates=%d new=%d completed=%d failed=%d running=%d",
                    summary.get("candidates", 0),
                    summary.get("new_scans", 0),
                    summary.get("completed", 0),
                    summary.get("failed", 0),
                    summary.get("still_running", 0),
                )
            else:
                logger.warning("Cycle status: %s", summary.get("status"))
        except Exception:
            logger.exception("Footprint cycle failed")

        logger.info("Sleeping %ds until next cycle", INTERVAL)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
