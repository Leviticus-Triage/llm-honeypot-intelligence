#!/usr/bin/env python3
"""
Rule Generator runner - generates security rules every 6 hours
from Elasticsearch honeypot data.

Generates: Sigma, YARA, Suricata, Firewall blocklists.
Outputs to: /data/ollama-proxy/generated-rules/
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
    format="%(asctime)s [rule-gen] %(levelname)s: %(message)s",
)
logger = logging.getLogger("rule-gen")

# Initialize DB (needed for shared volume access)
from src.models import init_db
init_db()

from src.rule_generator import run_rule_generation

INTERVAL = int(os.environ.get("RULEGEN_INTERVAL", "21600"))  # 6 hours default
NOTIFY_NOTION = os.environ.get("NOTIFY_NOTION", "false").lower() == "true"
NOTION_PAGE_ID = os.environ.get("NOTION_PAGE_ID", "")

# Optional: Notion notification
NOTION_TOKEN = os.environ.get("NOTION_TOKEN", "")


async def notify_notion(summary: dict):
    """Update Notion page with latest rule generation results."""
    if not NOTION_TOKEN or not NOTION_PAGE_ID:
        logger.info("Notion notification skipped (no token/page configured)")
        return

    try:
        import httpx
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        counts = summary.get("counts", {})
        text = (
            f"**Letzte Generierung**: {timestamp}\n"
            f"- Sigma Rules: {counts.get('sigma', 0)}\n"
            f"- YARA Rules: {counts.get('yara', 0)}\n"
            f"- Suricata Rules: {counts.get('suricata', 0)}\n"
            f"- Firewall IPs: {counts.get('firewall', 0)}\n"
            f"- Dateien: {len(summary.get('files', []))}"
        )
        logger.info("Notion update: %s", text.replace("\n", " | "))
    except Exception as e:
        logger.warning("Notion notification failed: %s", e)


def main():
    logger.info("Rule Generator started (interval=%ds, since=%sh, output=%s)",
                INTERVAL,
                os.environ.get("RULEGEN_SINCE_HOURS", "24"),
                os.environ.get("RULES_DIR", "/data/ollama-proxy/generated-rules"))

    # Run immediately on first start
    first_run = True

    while True:
        try:
            summary = asyncio.run(run_rule_generation())

            if summary.get("status") != "no_data":
                logger.info("Cycle complete: %s", json.dumps(summary.get("counts", {})))

                # Write latest summary for proxy health endpoint
                summary_path = Path(os.environ.get("RULES_DIR", "/data/ollama-proxy/generated-rules")) / "latest_summary.json"
                summary_path.parent.mkdir(parents=True, exist_ok=True)
                with open(summary_path, "w") as f:
                    json.dump({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "counts": summary.get("counts", {}),
                        "files": summary.get("files", []),
                    }, f, indent=2)

                if NOTIFY_NOTION:
                    asyncio.run(notify_notion(summary))

            if first_run:
                logger.info("First run complete. Next run in %d seconds (%d hours).",
                           INTERVAL, INTERVAL // 3600)
                first_run = False

        except Exception as e:
            logger.error("Rule generation cycle error: %s", e, exc_info=True)

        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
