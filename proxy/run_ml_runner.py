#!/usr/bin/env python3
"""
Offline ML runner entrypoint.

Usage:
  python run_ml_runner.py export
  python run_ml_runner.py train
  python run_ml_runner.py infer
  python run_ml_runner.py all
"""

from __future__ import annotations

import asyncio
import logging
import sys

from src.ml_runner import export_trainset, infer_and_update, train_isoforest, train_lgbm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ml-runner] %(levelname)s: %(message)s",
)
logger = logging.getLogger("ml-runner")


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "all"
    if cmd not in {"export", "train", "infer", "all"}:
        logger.error("Unknown command: %s", cmd)
        return 2

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
