#!/usr/bin/env python3
"""
ML Heuristic Detector runner - runs behavioral analysis every 30 minutes.

Performs:
- Isolation Forest anomaly detection on attack sessions
- DBSCAN campaign clustering to group coordinated attacks
- Threat classification (heuristic + ML)
- Dynamic IP reputation scoring
- Predictive alert generation

Outputs to: /data/ollama-proxy/threat-intel/
"""
import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [heuristic] %(levelname)s: %(message)s",
)
logger = logging.getLogger("heuristic")

# Initialize DB (needed for shared volume access)
from src.models import init_db
init_db()

from src.heuristic_detector import run_heuristic_detection

INTERVAL = int(os.environ.get("HEURISTIC_INTERVAL", "1800"))  # 30 min default


def main():
    logger.info("ML Heuristic Detector started (interval=%ds, since=%sh, output=%s)",
                INTERVAL,
                os.environ.get("HEURISTIC_SINCE_HOURS", "24"),
                os.environ.get("THREAT_DIR", "/data/ollama-proxy/threat-intel"))

    first_run = True

    while True:
        try:
            summary = asyncio.run(run_heuristic_detection())

            if summary.get("status") not in ("no_data", "insufficient_data"):
                logger.info("Cycle complete: sessions=%d anomalies=%d campaigns=%d alerts=%d",
                           summary.get("total_sessions", 0),
                           summary.get("anomalies_detected", 0),
                           summary.get("campaigns_identified", 0),
                           summary.get("alerts_generated", 0))

            if first_run:
                logger.info("First run complete. Next run in %d seconds (%d minutes).",
                           INTERVAL, INTERVAL // 60)
                first_run = False

        except Exception as e:
            logger.error("Heuristic detection error: %s", e, exc_info=True)

        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
