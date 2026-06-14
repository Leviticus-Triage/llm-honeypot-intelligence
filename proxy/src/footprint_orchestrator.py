"""
Automated SpiderFoot footprint orchestrator.

Triggers Passive OSINT scans for clearly malicious, targeted attackers
(critical/high threat + block action) and stores results for rule generation.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .osint_enrichment import (
    OSINT_DIR,
    enrich_campaigns,
    is_private_ip,
    parse_spiderfoot_events,
    serialise_footprint,
)
from .spiderfoot_client import SpiderFootClient, SpiderFootError

logger = logging.getLogger("ollama-proxy.footprint")

THREAT_DIR = Path(
    os.environ.get("THREAT_DIR", "/data/ollama-proxy/threat-intel")
)
STATE_PATH = Path(
    os.environ.get(
        "FOOTPRINT_STATE_PATH",
        "/data/ollama-proxy/threat-intel/footprint_state.json",
    )
)

COOLDOWN_HOURS = int(os.environ.get("FOOTPRINT_COOLDOWN_HOURS", "24"))
MAX_NEW_SCANS = int(os.environ.get("FOOTPRINT_MAX_NEW_SCANS", "3"))
MAX_CONCURRENT = int(os.environ.get("FOOTPRINT_MAX_CONCURRENT", "2"))
SCAN_TIMEOUT = float(os.environ.get("FOOTPRINT_SCAN_TIMEOUT", "3600"))
POLL_INTERVAL = float(os.environ.get("FOOTPRINT_POLL_INTERVAL", "30"))
SCAN_USECASE = os.environ.get("FOOTPRINT_USECASE", "Passive")

# Minimum reputation score even if threat_level is high
MIN_BLOCK_SCORE = int(os.environ.get("FOOTPRINT_MIN_SCORE", "80"))

PRIVATE_IP_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|::1)"
)


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as exc:
        logger.warning("Could not read %s: %s", path, exc)
        return default


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def _load_noise_ips() -> set[str]:
    payload = _load_json(THREAT_DIR / "noise_ips.json", {})
    return {e["ip"] for e in payload.get("ips", []) if e.get("ip")}


def _load_state() -> dict:
    return _load_json(STATE_PATH, {
        "scans": {},
        "last_run": None,
        "stats": {"completed": 0, "failed": 0, "skipped": 0},
    })


def _save_state(state: dict) -> None:
    _save_json(STATE_PATH, state)


def select_footprint_candidates(
    reputation: dict,
    alerts: list[dict],
    campaigns: list[dict],
    noise_ips: set[str],
) -> list[dict]:
    """
    Select IPs warranting OSINT footprint scans.

    Criteria:
    - threat_level in (critical, high)
    - action == block OR score >= MIN_BLOCK_SCORE
    - not in noise_ips, not private IP
    - bonus priority for CVE/exploit alerts and campaign members
    """
    candidates: dict[str, dict] = {}

    alert_ips: set[str] = set()
    for alert in alerts:
        if alert.get("severity") in ("critical", "high"):
            for ip in alert.get("ips", [alert.get("ip")]):
                if ip:
                    alert_ips.add(ip)

    campaign_ips: set[str] = set()
    high_campaign_ips: set[str] = set()
    for camp in campaigns:
        if camp.get("max_threat_level") in ("critical", "high"):
            for ip in camp.get("ips", []):
                high_campaign_ips.add(ip)
        for ip in camp.get("ips", []):
            campaign_ips.add(ip)

    for ip, rep in reputation.items():
        if not ip or is_private_ip(ip) or ip in noise_ips:
            continue

        level = rep.get("threat_level", "low")
        if level == "benign" or level not in ("critical", "high"):
            continue

        action = rep.get("action", "monitor")
        score = rep.get("score", 0)
        if action != "block" and score < MIN_BLOCK_SCORE:
            continue

        priority = score
        if level == "critical":
            priority += 20
        if ip in alert_ips:
            priority += 15
        if ip in high_campaign_ips:
            priority += 10
        if ip in campaign_ips:
            priority += 5

        candidates[ip] = {
            "ip": ip,
            "priority": priority,
            "threat_level": level,
            "score": score,
            "action": action,
            "reasons": rep.get("reasons", [])[:5],
            "country": rep.get("country", "Unknown"),
            "asn": rep.get("asn", "Unknown"),
            "campaign_id": rep.get("campaign_id", -1),
            "events": rep.get("events", 0),
            "sources": [],
        }

        if ip in alert_ips:
            candidates[ip]["sources"].append("alert")
        if ip in high_campaign_ips:
            candidates[ip]["sources"].append("campaign")
        candidates[ip]["sources"].append("reputation")

    ranked = sorted(candidates.values(), key=lambda c: -c["priority"])
    logger.info(
        "Footprint candidates: %d (critical/high + block, excl. noise)",
        len(ranked),
    )
    return ranked


def _in_cooldown(state: dict, ip: str) -> bool:
    entry = state.get("scans", {}).get(ip)
    if not entry:
        return False
    last = entry.get("started_at") or entry.get("completed_at")
    if not last:
        return False
    try:
        ts = datetime.fromisoformat(last.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - ts < timedelta(hours=COOLDOWN_HOURS)
    except Exception:
        return False


def _running_count(state: dict) -> int:
    return sum(
        1 for s in state.get("scans", {}).values()
        if s.get("status") == "RUNNING"
    )


async def run_footprint_cycle() -> dict:
    """
    One orchestration cycle:
    1. Load threat intel outputs
    2. Select candidates
    3. Start new scans (rate-limited)
    4. Poll running scans
    5. Export + persist results
    6. Write enriched campaigns
    """
    logger.info("=" * 60)
    logger.info("Footprint Orchestrator cycle starting")
    logger.info("=" * 60)

    client = SpiderFootClient()
    if not await client.ping():
        logger.error("SpiderFoot not reachable at %s", os.environ.get("SPIDERFOOT_URL"))
        return {"status": "spiderfoot_unreachable"}

    reputation = _load_json(THREAT_DIR / "ip_reputation.json", {})
    alerts = _load_json(THREAT_DIR / "alerts.json", [])
    campaigns = _load_json(THREAT_DIR / "campaigns.json", [])
    noise_ips = _load_noise_ips()

    if not reputation:
        logger.warning("No ip_reputation.json — run heuristic detector first")
        return {"status": "no_reputation_data"}

    candidates = select_footprint_candidates(
        reputation, alerts, campaigns, noise_ips
    )
    state = _load_state()
    OSINT_DIR.mkdir(parents=True, exist_ok=True)

    summary = {
        "status": "ok",
        "candidates": len(candidates),
        "new_scans": 0,
        "completed": 0,
        "failed": 0,
        "skipped_cooldown": 0,
        "still_running": 0,
    }

    # ── Poll existing RUNNING scans ──
    for ip, entry in list(state.get("scans", {}).items()):
        if entry.get("status") != "RUNNING":
            continue

        scan_id = entry.get("scan_id")
        if not scan_id or len(str(scan_id)) != 8:
            entry["status"] = "FAILED"
            entry["error"] = "invalid scan_id"
            summary["failed"] += 1
            continue

        try:
            rows = await client.scan_status(scan_id)
            if not rows:
                continue
            status = str(rows[0][5] if len(rows[0]) > 5 else "UNKNOWN").upper()
            entry["last_checked"] = datetime.now(timezone.utc).isoformat()

            if status in ("FINISHED", "FINISHED-ERROR"):
                await _finalize_scan(client, ip, scan_id, entry, reputation.get(ip, {}))
                entry["status"] = "COMPLETED"
                entry["completed_at"] = datetime.now(timezone.utc).isoformat()
                summary["completed"] += 1
                state["stats"]["completed"] = state["stats"].get("completed", 0) + 1
            elif status.startswith("ERROR") or status.startswith("ABORT"):
                entry["status"] = "FAILED"
                entry["error"] = status
                entry["completed_at"] = datetime.now(timezone.utc).isoformat()
                summary["failed"] += 1
                state["stats"]["failed"] = state["stats"].get("failed", 0) + 1
                logger.warning("Scan %s for %s failed: %s", scan_id, ip, status)
            else:
                summary["still_running"] += 1

        except SpiderFootError as exc:
            logger.warning("Poll failed for %s: %s", ip, exc)

    # ── Start new scans ──
    new_started = 0
    for cand in candidates:
        if new_started >= MAX_NEW_SCANS:
            break
        if _running_count(state) >= MAX_CONCURRENT:
            break

        ip = cand["ip"]
        if _in_cooldown(state, ip):
            summary["skipped_cooldown"] += 1
            continue

        existing = state.get("scans", {}).get(ip, {})
        if existing.get("status") == "RUNNING":
            continue
        if existing.get("status") == "COMPLETED" and _in_cooldown(state, ip):
            summary["skipped_cooldown"] += 1
            continue

        scan_name = (
            f"honeypot-{ip}-{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        )
        try:
            scan_id = await client.start_scan(
                ip,
                scan_name,
                usecase=SCAN_USECASE,
            )
            state.setdefault("scans", {})[ip] = {
                "scan_id": scan_id,
                "scan_name": scan_name,
                "status": "RUNNING",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "threat_level": cand["threat_level"],
                "reputation_score": cand["score"],
                "threat_reasons": cand["reasons"],
                "priority": cand["priority"],
            }
            new_started += 1
            summary["new_scans"] += 1
            logger.info(
                "Started footprint scan %s for %s (level=%s score=%d)",
                scan_id, ip, cand["threat_level"], cand["score"],
            )
        except SpiderFootError as exc:
            logger.error("Failed to start scan for %s: %s", ip, exc)
            state.setdefault("scans", {})[ip] = {
                "status": "FAILED",
                "error": str(exc),
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
            summary["failed"] += 1

    # ── Blocking wait for newly started scans if configured ──
    wait_inline = os.environ.get("FOOTPRINT_WAIT_INLINE", "false").lower() == "true"
    if wait_inline and new_started:
        for ip, entry in state.get("scans", {}).items():
            if entry.get("status") != "RUNNING":
                continue
            scan_id = entry.get("scan_id")
            if not scan_id:
                continue
            try:
                final = await client.wait_for_scan(
                    scan_id,
                    poll_interval=POLL_INTERVAL,
                    timeout=SCAN_TIMEOUT,
                )
                if final.startswith("FINISHED"):
                    await _finalize_scan(
                        client, ip, scan_id, entry,
                        reputation.get(ip, {}),
                    )
                    entry["status"] = "COMPLETED"
                    entry["completed_at"] = datetime.now(timezone.utc).isoformat()
                    summary["completed"] += 1
                else:
                    entry["status"] = "FAILED"
                    entry["error"] = final
                    summary["failed"] += 1
            except SpiderFootError as exc:
                entry["status"] = "FAILED"
                entry["error"] = str(exc)
                summary["failed"] += 1

    # ── Write queue status + enriched campaigns ──
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    summary["still_running"] = _running_count(state)
    _save_state(state)

    queue = {
        "generated_at": state["last_run"],
        "candidates": len(candidates),
        "running": _running_count(state),
        "scans": state.get("scans", {}),
        "summary": summary,
    }
    _save_json(THREAT_DIR / "footprint_queue.json", queue)

    # Enrich campaigns with completed footprints
    from .osint_enrichment import load_all_footprints
    footprints = load_all_footprints()
    if footprints and campaigns:
        enriched = enrich_campaigns(campaigns, footprints)
        _save_json(THREAT_DIR / "campaigns_osint_enriched.json", enriched)
        logger.info("Wrote campaigns_osint_enriched.json (%d campaigns)", len(enriched))

    # Index of all footprints
    index = {
        "generated_at": state["last_run"],
        "count": len(footprints),
        "targets": {
            t: {
                "scan_id": fp.get("scan_id"),
                "threat_level": fp.get("threat_level"),
                "domains": len(fp.get("domains", [])),
                "related_ips": len(fp.get("ipv4", {})),
                "malicious": len(fp.get("malicious_indicators", [])),
            }
            for t, fp in footprints.items()
        },
    }
    _save_json(OSINT_DIR / "index.json", index)

    logger.info("=" * 60)
    logger.info(
        "Footprint cycle done: new=%d completed=%d failed=%d "
        "cooldown_skip=%d running=%d",
        summary["new_scans"], summary["completed"], summary["failed"],
        summary["skipped_cooldown"], summary["still_running"],
    )
    logger.info("=" * 60)

    return summary


async def _finalize_scan(
    client: SpiderFootClient,
    ip: str,
    scan_id: str,
    entry: dict,
    reputation: dict,
) -> None:
    """Export scan results and write footprint JSON."""
    events = await client.export_json(scan_id)
    parsed = parse_spiderfoot_events(events, seed_target=ip, scan_id=scan_id)

    parsed["threat_level"] = entry.get("threat_level") or reputation.get("threat_level")
    parsed["reputation_score"] = entry.get("reputation_score") or reputation.get("score")
    parsed["threat_reasons"] = entry.get("threat_reasons") or reputation.get("reasons", [])
    parsed["country"] = reputation.get("country", "Unknown")
    parsed["asn_honeypot"] = reputation.get("asn", "Unknown")
    parsed["scan_completed_at"] = datetime.now(timezone.utc).isoformat()
    parsed["raw_events"] = events  # keep full export for rule gen deep-dive

    safe_name = ip.replace(":", "_").replace("/", "_")
    out_path = OSINT_DIR / f"{safe_name}.json"
    _save_json(out_path, serialise_footprint(parsed))
    logger.info(
        "Footprint saved: %s (%d events, %d domains, %d related IPs)",
        out_path.name,
        parsed["raw_event_count"],
        len(parsed.get("domains", [])),
        len(parsed.get("ipv4", {})),
    )
