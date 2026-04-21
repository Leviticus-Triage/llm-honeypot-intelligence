#!/usr/bin/env python3
"""
Phase 5 Reward Aggregator runner.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path

from src.models import init_db
from src.reward_aggregator import run_reward_cycle

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [reward-aggregator] %(levelname)s: %(message)s",
)
logger = logging.getLogger("reward-aggregator")

INTERVAL = int(os.environ.get("REWARD_INTERVAL", "900"))
WINDOW_MINUTES = int(os.environ.get("REWARD_WINDOW_MINUTES", "30"))
FULL_BACKFILL_HOUR_UTC = int(os.environ.get("REWARD_BACKFILL_HOUR_UTC", "2"))
STATE_PATH = Path(os.environ.get("REWARD_STATE_PATH", "/data/ollama-proxy/reward_aggregator_state.json"))
ONESHOT = os.environ.get("ONESHOT", "false").lower() in {"1", "true", "yes"}


def _load_state() -> dict:
    if not STATE_PATH.is_file():
        return {}
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(STATE_PATH)


def _since_minutes_for_cycle() -> int:
    state = _load_state()
    now = time.gmtime()
    today = f"{now.tm_year:04d}-{now.tm_mon:02d}-{now.tm_mday:02d}"
    if now.tm_hour == FULL_BACKFILL_HOUR_UTC and state.get("last_full_backfill_day") != today:
        state["last_full_backfill_day"] = today
        _save_state(state)
        return 24 * 60
    return WINDOW_MINUTES


def main() -> int:
    init_db()
    logger.info(
        "Reward Aggregator started (interval=%ss window=%sm backfill_hour_utc=%s)",
        INTERVAL,
        WINDOW_MINUTES,
        FULL_BACKFILL_HOUR_UTC,
    )
    if ONESHOT:
        since = _since_minutes_for_cycle()
        asyncio.run(run_reward_cycle(since_minutes=since))
        return 0

    while True:
        since = _since_minutes_for_cycle()
        try:
            asyncio.run(run_reward_cycle(since_minutes=since))
        except Exception as e:
            logger.error("Reward cycle failed: %s", e, exc_info=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    raise SystemExit(main())
