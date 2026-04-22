#!/usr/bin/env python3
"""
Offline ML runner entrypoint.

Usage:
  python run_ml_runner.py export
  python run_ml_runner.py train
  python run_ml_runner.py infer
  python run_ml_runner.py all
  python run_ml_runner.py loop   # run `all` periodically, driven by ML_RUNNER_LOOP_INTERVAL

Environment:
  ML_RUNNER_LOOP_INTERVAL  Seconds between ticks in `loop` mode.
                           Accepts plain seconds ("21600") or a suffixed
                           string ("6h", "30m", "3600s"). Default: 6h.
  ML_RUNNER_STARTUP_DELAY  Optional seconds to wait before the very first
                           tick in `loop` mode. Default: 0.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
import time
import traceback

from src.ml_runner import export_trainset, infer_and_update, train_isoforest, train_lgbm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ml-runner] %(levelname)s: %(message)s",
)
logger = logging.getLogger("ml-runner")


_INTERVAL_RE = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$", re.IGNORECASE)
_UNIT_SECONDS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def _parse_interval(raw: str, default_seconds: int) -> int:
    if not raw:
        return default_seconds
    m = _INTERVAL_RE.match(raw)
    if not m:
        logger.warning("Could not parse ML_RUNNER_LOOP_INTERVAL=%r; using default %ds",
                       raw, default_seconds)
        return default_seconds
    value = int(m.group(1))
    unit = m.group(2).lower()
    return max(60, value * _UNIT_SECONDS[unit])


def _run_once() -> None:
    asyncio.run(export_trainset())
    train_isoforest()
    train_lgbm()
    asyncio.run(infer_and_update())


def _run_loop() -> int:
    interval = _parse_interval(os.environ.get("ML_RUNNER_LOOP_INTERVAL", ""), 6 * 3600)
    startup_delay = _parse_interval(os.environ.get("ML_RUNNER_STARTUP_DELAY", ""), 0)
    logger.info(
        "Entering loop mode (interval=%ds, startup_delay=%ds)",
        interval,
        startup_delay,
    )
    if startup_delay > 0:
        time.sleep(startup_delay)

    tick = 0
    while True:
        tick += 1
        started = time.monotonic()
        logger.info("Loop tick %d starting", tick)
        try:
            _run_once()
            logger.info("Loop tick %d complete in %.1fs", tick, time.monotonic() - started)
        except Exception as e:
            logger.error("Loop tick %d failed: %s\n%s", tick, e, traceback.format_exc())
        elapsed = time.monotonic() - started
        sleep_for = max(60, interval - int(elapsed))
        logger.info("Loop sleeping %ds until next tick", sleep_for)
        time.sleep(sleep_for)


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "all"
    if cmd not in {"export", "train", "infer", "all", "loop"}:
        logger.error("Unknown command: %s", cmd)
        return 2

    if cmd == "loop":
        return _run_loop()

    if cmd in {"export", "all"}:
        asyncio.run(export_trainset())
    if cmd in {"train", "all"}:
        train_isoforest()
        train_lgbm()
    if cmd in {"infer", "all"}:
        asyncio.run(infer_and_update())

    logger.info("ML runner command '%s' complete", cmd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
