#!/usr/bin/env python3
"""Runner for the C2 Detection Engine."""
import asyncio
import logging
import os
import sys

sys.path.insert(0, "/app")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("c2-detector")

INTERVAL = int(os.environ.get("C2_INTERVAL", "300"))


async def main():
    from src.c2_detection.engine import run_detection_cycle
    logger.info("C2 Detection Engine started (interval=%ds)", INTERVAL)

    while True:
        try:
            count = await run_detection_cycle()
            logger.info("Cycle complete: %d indicators", count)
        except Exception as e:
            logger.error("Cycle failed: %s", e, exc_info=True)
        await asyncio.sleep(INTERVAL)


if __name__ == "__main__":
    asyncio.run(main())
