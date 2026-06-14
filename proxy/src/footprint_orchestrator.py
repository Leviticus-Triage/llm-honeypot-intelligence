"""
Automated SpiderFoot footprint orchestrator — two-tier escalation.

Tier 1 (Passive): API/OSINT modules via Tor — critical/high + block.
Tier 2 (Active/Footprint): Nmap, Nuclei, etc. — only when targeted
exploitation signals fire AND passive scan completed (or urgent cred-theft).

Ban/blocklist duration is configured separately (default 12h).
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from .osint_enrichment import (
    OSINT_DIR,
    enrich_campaigns,
    is_private_ip,
    load_all_footprints,
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

# ── Passive tier (API/OSINT, Tor-friendly) ──
PASSIVE_COOLDOWN_HOURS = int(os.environ.get("FOOTPRINT_COOLDOWN_HOURS", "24"))
PASSIVE_MAX_NEW = int(os.environ.get("FOOTPRINT_MAX_NEW_SCANS", "3"))
PASSIVE_MAX_CONCURRENT = int(os.environ.get("FOOTPRINT_MAX_CONCURRENT", "2"))
PASSIVE_USECASE = os.environ.get("FOOTPRINT_PASSIVE_USECASE", "Passive")

# ── Active tier (Nmap/Nuclei — slow, noisy, Tor-limited) ──
ACTIVE_ENABLED = os.environ.get("FOOTPRINT_ACTIVE_ENABLED", "true").lower() == "true"
ACTIVE_COOLDOWN_HOURS = int(os.environ.get("FOOTPRINT_ACTIVE_COOLDOWN_HOURS", "168"))
ACTIVE_MAX_NEW = int(os.environ.get("FOOTPRINT_ACTIVE_MAX_NEW", "1"))
ACTIVE_MAX_CONCURRENT = int(os.environ.get("FOOTPRINT_ACTIVE_MAX_CONCURRENT", "1"))
ACTIVE_USECASE = os.environ.get("FOOTPRINT_ACTIVE_USECASE", "Footprint")
ACTIVE_MIN_SCORE = int(os.environ.get("FOOTPRINT_ACTIVE_MIN_SCORE", "85"))
ACTIVE_REQUIRE_PASSIVE = os.environ.get(
    "FOOTPRINT_ACTIVE_REQUIRE_PASSIVE", "true"
).lower() == "true"

SCAN_TIMEOUT = float(os.environ.get("FOOTPRINT_SCAN_TIMEOUT", "3600"))
ACTIVE_SCAN_TIMEOUT = float(os.environ.get("FOOTPRINT_ACTIVE_SCAN_TIMEOUT", "7200"))
POLL_INTERVAL = float(os.environ.get("FOOTPRINT_POLL_INTERVAL", "30"))
MIN_BLOCK_SCORE = int(os.environ.get("FOOTPRINT_MIN_SCORE", "80"))

# Stuck-scan recovery — prevents CREATED/STARTING limbo from blocking concurrency slots.
STUCK_CREATED_MINUTES = int(os.environ.get("FOOTPRINT_STUCK_CREATED_MINUTES", "3"))
STUCK_STARTING_MINUTES = int(os.environ.get("FOOTPRINT_STUCK_STARTING_MINUTES", "10"))
STUCK_PASSIVE_RUNNING_MINUTES = int(
    os.environ.get("FOOTPRINT_STUCK_PASSIVE_RUNNING_MINUTES", "30")
)
STUCK_ACTIVE_RUNNING_MINUTES = int(
    os.environ.get(
        "FOOTPRINT_STUCK_ACTIVE_RUNNING_MINUTES",
        str(max(60, int(ACTIVE_SCAN_TIMEOUT / 60))),
    )
)

# SpiderFoot statuses that may block concurrency slots until resolved.
_STUCK_PRONE_STATUSES = frozenset({
    "CREATED", "STARTING", "INITIALIZING", "RUNNING",
})

ScanTier = Literal["passive", "active"]

# Reasons that justify escalating to active tooling (Nmap/Nuclei).
ACTIVE_REASON_PATTERN = re.compile(
    r"CVE|exploit|RCE|webshell|malware|reverse.?shell|credential|"
    r"lateral|payload|shell.?download|0day|0-day|vuln",
    re.IGNORECASE,
)

URGENT_ALERT_TYPES = frozenset({"credential_theft"})


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
    raw = _load_json(STATE_PATH, {
        "scans": {},
        "last_run": None,
        "stats": {"passive_completed": 0, "active_completed": 0, "failed": 0},
    })
    _migrate_state(raw)
    return raw


def _migrate_state(state: dict) -> None:
    """Upgrade legacy flat per-IP entries to {passive, active} structure."""
    scans = state.get("scans", {})
    for ip, entry in list(scans.items()):
        if not isinstance(entry, dict):
            continue
        if "passive" in entry or "active" in entry:
            continue
        if entry.get("scan_id"):
            scans[ip] = {"passive": entry, "active": None}
        else:
            scans[ip] = {"passive": None, "active": None}


def _save_state(state: dict) -> None:
    _save_json(STATE_PATH, state)


def _tier_entry(state: dict, ip: str, tier: ScanTier) -> dict | None:
    slot = state.get("scans", {}).get(ip, {})
    return slot.get(tier) if isinstance(slot, dict) else None


def _set_tier_entry(state: dict, ip: str, tier: ScanTier, entry: dict | None) -> None:
    state.setdefault("scans", {}).setdefault(ip, {"passive": None, "active": None})
    if "passive" not in state["scans"][ip]:
        _migrate_state(state)
    state["scans"][ip][tier] = entry


def _entry_age_minutes(entry: dict) -> float | None:
    """Minutes since scan entry was started (UTC)."""
    started = entry.get("started_at")
    if not started:
        return None
    try:
        ts = datetime.fromisoformat(str(started).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - ts).total_seconds() / 60
    except Exception:
        return None


def _running_stuck_limit_minutes(tier: ScanTier) -> int:
    return (
        STUCK_ACTIVE_RUNNING_MINUTES
        if tier == "active"
        else STUCK_PASSIVE_RUNNING_MINUTES
    )


def _mark_scan_failed(
    entry: dict,
    summary: dict,
    reason: str,
    *,
    was_running: bool = False,
) -> None:
    entry["status"] = "FAILED"
    entry["error"] = reason
    entry["failed_at"] = datetime.now(timezone.utc).isoformat()
    summary["failed"] += 1
    if was_running and summary.get("still_running", 0) > 0:
        summary["still_running"] -= 1


async def _abort_stuck_scan(
    client: SpiderFootClient,
    scan_id: str,
    entry: dict,
    summary: dict,
    reason: str,
) -> None:
    try:
        await client.stop_scan(scan_id)
    except Exception as exc:
        logger.debug("stop_scan %s failed (may already be dead): %s", scan_id, exc)
    _mark_scan_failed(entry, summary, reason, was_running=True)
    logger.warning("Scan %s marked failed: %s", scan_id, reason)


def _stuck_reason(status: str, age_mins: float | None, tier: ScanTier) -> str | None:
    """Return failure reason when a RUNNING entry is stuck, else None."""
    if age_mins is None:
        return None

    if status == "CREATED" and age_mins >= STUCK_CREATED_MINUTES:
        return f"stuck_created_{STUCK_CREATED_MINUTES}m"

    if status == "STARTING" and age_mins >= STUCK_STARTING_MINUTES:
        return f"stuck_starting_{STUCK_STARTING_MINUTES}m"

    if status in ("RUNNING", "INITIALIZING"):
        limit = _running_stuck_limit_minutes(tier)
        if age_mins >= limit:
            return f"stuck_{status.lower()}_{limit}m"

    if status == "UNKNOWN" and age_mins >= STUCK_STARTING_MINUTES:
        return "stuck_unknown"

    return None


async def _poll_running_scan(
    client: SpiderFootClient,
    ip: str,
    tier: ScanTier,
    entry: dict,
    reputation: dict,
    state: dict,
    summary: dict,
) -> None:
    """Poll SpiderFoot for one orchestrator RUNNING entry; finalize or fail it."""
    scan_id = entry.get("scan_id")
    if not scan_id or len(str(scan_id)) != 8:
        _mark_scan_failed(entry, summary, "invalid scan_id")
        return

    try:
        raw = await client.scan_status(scan_id)
        parsed = client.parse_scan_status(raw)
        status = str(parsed.get("status", "UNKNOWN")).upper()
        entry["last_checked"] = datetime.now(timezone.utc).isoformat()
        entry["spiderfoot_status"] = status
        age_mins = _entry_age_minutes(entry)

        ended = str(parsed.get("ended") or "")
        if (
            status == "CREATED"
            and ended.startswith("1970-")
            and age_mins is not None
            and age_mins >= 2
        ):
            await _abort_stuck_scan(
                client, scan_id, entry, summary, "stuck_created_never_started",
            )
            return

        if status in ("FINISHED", "FINISHED-ERROR"):
            await _finalize_scan(
                client, ip, scan_id, entry, reputation.get(ip, {}), tier,
            )
            entry["status"] = "COMPLETED"
            entry["completed_at"] = datetime.now(timezone.utc).isoformat()
            summary["completed"] += 1
            key = f"{tier}_completed"
            state["stats"][key] = state["stats"].get(key, 0) + 1
            logger.info("Scan %s %s/%s completed", scan_id, ip, tier)
            return

        if status.startswith("ERROR") or status.startswith("ABORT"):
            _mark_scan_failed(entry, summary, status)
            return

        stuck_reason = _stuck_reason(status, age_mins, tier)
        if stuck_reason:
            await _abort_stuck_scan(client, scan_id, entry, summary, stuck_reason)
            return

        if status in _STUCK_PRONE_STATUSES or status == "UNKNOWN":
            summary["still_running"] += 1
            return

        logger.warning(
            "Scan %s %s has unexpected status %s — failing",
            scan_id, ip, status,
        )
        await _abort_stuck_scan(
            client, scan_id, entry, summary, f"unexpected_status:{status}",
        )

    except SpiderFootError as exc:
        entry["last_checked"] = datetime.now(timezone.utc).isoformat()
        age_mins = _entry_age_minutes(entry)
        err = str(exc).lower()
        if "http 404" in err or "not found" in err:
            _mark_scan_failed(entry, summary, "scan_lost", was_running=True)
            logger.warning("Scan %s %s lost in SpiderFoot: %s", scan_id, ip, exc)
            return
        if age_mins is not None and age_mins >= STUCK_STARTING_MINUTES:
            await _abort_stuck_scan(
                client, scan_id, entry, summary, f"poll_error:{exc}",
            )
            return
        logger.warning("Poll %s/%s failed (will retry): %s", ip, tier, exc)
        summary["still_running"] += 1


def _in_cooldown(entry: dict | None, hours: int) -> bool:
    if not entry:
        return False
    last = entry.get("started_at") or entry.get("completed_at")
    if not last:
        return False
    try:
        ts = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - ts < timedelta(hours=hours)
    except Exception:
        return False


def _running_count(state: dict, tier: ScanTier | None = None) -> int:
    count = 0
    for slot in state.get("scans", {}).values():
        if not isinstance(slot, dict):
            continue
        tiers = [tier] if tier else ["passive", "active"]
        for t in tiers:
            e = slot.get(t)
            if e and e.get("status") == "RUNNING":
                count += 1
    return count


def _build_alert_index(alerts: list[dict]) -> dict[str, list[dict]]:
    """Map IP -> matching critical/high alerts."""
    index: dict[str, list[dict]] = {}
    for alert in alerts:
        if alert.get("severity") not in ("critical", "high"):
            continue
        ips: list[str] = []
        if alert.get("ip"):
            raw = str(alert["ip"])
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", raw):
                ips.append(raw)
            else:
                ips.extend(re.findall(r"\d+\.\d+\.\d+\.\d+", raw))
        for ip in alert.get("ips", []):
            if ip:
                ips.append(ip)
        for ip in ips:
            index.setdefault(ip, []).append(alert)
    return index


def select_passive_candidates(
    reputation: dict,
    alerts: list[dict],
    campaigns: list[dict],
    noise_ips: set[str],
) -> list[dict]:
    """Tier 1: Passive OSINT for critical/high attackers recommended for block."""
    candidates: dict[str, dict] = {}
    alert_index = _build_alert_index(alerts)

    high_campaign_ips: set[str] = set()
    for camp in campaigns:
        if camp.get("max_threat_level") in ("critical", "high"):
            high_campaign_ips.update(camp.get("ips", []))

    for ip, rep in reputation.items():
        if not ip or is_private_ip(ip) or ip in noise_ips:
            continue
        level = rep.get("threat_level", "low")
        if level not in ("critical", "high"):
            continue
        score = rep.get("score", 0)
        if rep.get("action") != "block" and score < MIN_BLOCK_SCORE:
            continue

        priority = score + (20 if level == "critical" else 0)
        if ip in alert_index:
            priority += 15
        if ip in high_campaign_ips:
            priority += 10

        candidates[ip] = {
            "ip": ip,
            "tier": "passive",
            "priority": priority,
            "threat_level": level,
            "score": score,
            "reasons": rep.get("reasons", [])[:8],
        }

    ranked = sorted(candidates.values(), key=lambda c: -c["priority"])
    logger.info("Passive candidates: %d", len(ranked))
    return ranked


def select_active_candidates(
    reputation: dict,
    alerts: list[dict],
    campaigns: list[dict],
    noise_ips: set[str],
    state: dict,
    footprints: dict[str, dict],
) -> list[dict]:
    """
    Tier 2: Active Footprint (Nmap/Nuclei) — strict triggers only.

    Policy (industry-aligned for honeypot CTI):
    - MUST be critical + block (score >= ACTIVE_MIN_SCORE)
    - MUST have at least one targeted-exploitation signal
    - SHOULD have completed passive scan first (waived for credential_theft)
    - Max 1 active scan at a time; 7-day cooldown per IP
    """
    if not ACTIVE_ENABLED:
        return []

    candidates: list[dict] = []
    alert_index = _build_alert_index(alerts)

    critical_campaign_ips: set[str] = set()
    for camp in campaigns:
        if camp.get("max_threat_level") == "critical" and camp.get("ip_count", 0) >= 3:
            critical_campaign_ips.update(camp.get("ips", []))

    for ip, rep in reputation.items():
        if not ip or is_private_ip(ip) or ip in noise_ips:
            continue
        if rep.get("threat_level") != "critical":
            continue
        if rep.get("action") != "block":
            continue
        score = rep.get("score", 0)
        if score < ACTIVE_MIN_SCORE:
            continue

        reasons = rep.get("reasons", [])
        ip_alerts = alert_index.get(ip, [])
        passive_entry = _tier_entry(state, ip, "passive")
        passive_done = (
            passive_entry
            and passive_entry.get("status") == "COMPLETED"
        ) or ip in footprints
        fp = footprints.get(ip, {})

        triggers: list[str] = []

        # Urgent: credential theft — may skip passive prerequisite
        for alert in ip_alerts:
            if alert.get("type") in URGENT_ALERT_TYPES:
                triggers.append(f"alert:{alert['type']}")

        if ip in critical_campaign_ips:
            triggers.append("campaign:critical_coordinated")

        if any(ACTIVE_REASON_PATTERN.search(r) for r in reasons):
            triggers.append("reason:exploit_indicator")

        malicious = len(fp.get("malicious_indicators", []))
        if malicious >= 1:
            triggers.append(f"osint:malicious_hits={malicious}")

        related_domains = len(fp.get("domains", []))
        if related_domains >= 3 and score >= 90:
            triggers.append(f"osint:related_domains={related_domains}")

        if not triggers:
            continue

        urgent = any(t.startswith("alert:credential_theft") for t in triggers)
        if ACTIVE_REQUIRE_PASSIVE and not passive_done and not urgent:
            logger.debug(
                "Active skipped %s: passive scan not complete (triggers=%s)",
                ip, triggers,
            )
            continue

        priority = score + len(triggers) * 10 + (50 if urgent else 0)
        candidates.append({
            "ip": ip,
            "tier": "active",
            "priority": priority,
            "threat_level": "critical",
            "score": score,
            "reasons": reasons[:8],
            "active_triggers": triggers,
            "passive_completed": passive_done,
            "urgent": urgent,
        })

    ranked = sorted(candidates, key=lambda c: -c["priority"])
    logger.info(
        "Active candidates: %d (enabled=%s, require_passive=%s)",
        len(ranked), ACTIVE_ENABLED, ACTIVE_REQUIRE_PASSIVE,
    )
    return ranked


async def run_footprint_cycle() -> dict:
    """Run passive + active scan orchestration cycle."""
    logger.info("=" * 60)
    logger.info("Footprint Orchestrator cycle starting")
    logger.info("=" * 60)

    client = SpiderFootClient()
    if not await client.ping():
        logger.error("SpiderFoot not reachable")
        return {"status": "spiderfoot_unreachable"}

    reputation = _load_json(THREAT_DIR / "ip_reputation.json", {})
    alerts = _load_json(THREAT_DIR / "alerts.json", [])
    campaigns = _load_json(THREAT_DIR / "campaigns.json", [])
    noise_ips = _load_noise_ips()

    if not reputation:
        return {"status": "no_reputation_data"}

    state = _load_state()
    OSINT_DIR.mkdir(parents=True, exist_ok=True)
    footprints = load_all_footprints()

    passive_candidates = select_passive_candidates(
        reputation, alerts, campaigns, noise_ips
    )
    active_candidates = select_active_candidates(
        reputation, alerts, campaigns, noise_ips, state, footprints
    )

    summary = {
        "status": "ok",
        "passive_candidates": len(passive_candidates),
        "active_candidates": len(active_candidates),
        "new_passive": 0,
        "new_active": 0,
        "completed": 0,
        "failed": 0,
        "skipped_cooldown": 0,
        "still_running": 0,
    }

    # ── Poll all running scans ──
    for ip, slot in list(state.get("scans", {}).items()):
        if not isinstance(slot, dict):
            continue
        for tier in ("passive", "active"):
            entry = slot.get(tier)
            if not entry or entry.get("status") != "RUNNING":
                continue
            await _poll_running_scan(
                client, ip, tier, entry, reputation, state, summary,
            )

    # ── Start passive scans ──
    summary["new_passive"] = await _start_scans(
        client, state, passive_candidates, "passive",
        usecase=PASSIVE_USECASE,
        max_new=PASSIVE_MAX_NEW,
        max_concurrent=PASSIVE_MAX_CONCURRENT,
        cooldown_hours=PASSIVE_COOLDOWN_HOURS,
        summary=summary,
    )

    # ── Start active scans (heavy tooling) ──
    summary["new_active"] = await _start_scans(
        client, state, active_candidates, "active",
        usecase=ACTIVE_USECASE,
        max_new=ACTIVE_MAX_NEW,
        max_concurrent=ACTIVE_MAX_CONCURRENT,
        cooldown_hours=ACTIVE_COOLDOWN_HOURS,
        summary=summary,
    )

    summary["new_scans"] = summary["new_passive"] + summary["new_active"]
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    summary["still_running"] = _running_count(state)
    _save_state(state)

    footprints = load_all_footprints()
    queue = {
        "generated_at": state["last_run"],
        "policy": {
            "passive_usecase": PASSIVE_USECASE,
            "active_usecase": ACTIVE_USECASE,
            "active_enabled": ACTIVE_ENABLED,
            "active_require_passive": ACTIVE_REQUIRE_PASSIVE,
            "active_cooldown_hours": ACTIVE_COOLDOWN_HOURS,
        },
        "passive_candidates": len(passive_candidates),
        "active_candidates": len(active_candidates),
        "running": summary["still_running"],
        "scans": state.get("scans", {}),
        "summary": summary,
    }
    _save_json(THREAT_DIR / "footprint_queue.json", queue)

    if footprints and campaigns:
        enriched = enrich_campaigns(campaigns, footprints)
        _save_json(THREAT_DIR / "campaigns_osint_enriched.json", enriched)

    _save_json(OSINT_DIR / "index.json", {
        "generated_at": state["last_run"],
        "count": len(footprints),
        "targets": {
            t: {
                "tier": fp.get("scan_tier", "passive"),
                "scan_id": fp.get("scan_id"),
                "threat_level": fp.get("threat_level"),
                "malicious": len(fp.get("malicious_indicators", [])),
            }
            for t, fp in footprints.items()
        },
    })

    logger.info(
        "Cycle done: passive_new=%d active_new=%d completed=%d failed=%d running=%d",
        summary["new_passive"], summary["new_active"],
        summary["completed"], summary["failed"], summary["still_running"],
    )
    return summary


async def _start_scans(
    client: SpiderFootClient,
    state: dict,
    candidates: list[dict],
    tier: ScanTier,
    *,
    usecase: str,
    max_new: int,
    max_concurrent: int,
    cooldown_hours: int,
    summary: dict,
) -> int:
    started = 0
    for cand in candidates:
        if started >= max_new:
            break
        if _running_count(state, tier) >= max_concurrent:
            break

        ip = cand["ip"]
        existing = _tier_entry(state, ip, tier)

        if existing and existing.get("status") == "RUNNING":
            continue
        if existing and existing.get("status") != "FAILED":
            if _in_cooldown(existing, cooldown_hours):
                summary["skipped_cooldown"] += 1
                continue

        scan_name = (
            f"honeypot-{tier}-{ip}-"
            f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        )
        try:
            scan_id = await client.start_scan(ip, scan_name, usecase=usecase)
            entry = {
                "scan_id": scan_id,
                "scan_name": scan_name,
                "scan_tier": tier,
                "usecase": usecase,
                "status": "RUNNING",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "threat_level": cand["threat_level"],
                "reputation_score": cand["score"],
                "threat_reasons": cand.get("reasons", []),
                "priority": cand["priority"],
            }
            if tier == "active":
                entry["active_triggers"] = cand.get("active_triggers", [])
            _set_tier_entry(state, ip, tier, entry)
            started += 1
            logger.info(
                "Started %s %s scan %s for %s (score=%d triggers=%s)",
                usecase, tier, scan_id, ip, cand["score"],
                cand.get("active_triggers", []),
            )
        except SpiderFootError as exc:
            logger.error("Failed %s scan for %s: %s", tier, ip, exc)
            _set_tier_entry(state, ip, tier, {
                "status": "FAILED",
                "error": str(exc),
                "scan_tier": tier,
                "started_at": datetime.now(timezone.utc).isoformat(),
            })
            summary["failed"] += 1
    return started


async def _finalize_scan(
    client: SpiderFootClient,
    ip: str,
    scan_id: str,
    entry: dict,
    reputation: dict,
    tier: ScanTier,
) -> None:
    """Export scan results; passive -> <ip>.json, active -> <ip>.active.json."""
    events = await client.export_json(scan_id)
    parsed = parse_spiderfoot_events(events, seed_target=ip, scan_id=scan_id)
    parsed["scan_tier"] = tier
    parsed["usecase"] = entry.get("usecase", "")
    parsed["threat_level"] = entry.get("threat_level") or reputation.get("threat_level")
    parsed["reputation_score"] = entry.get("reputation_score") or reputation.get("score")
    parsed["threat_reasons"] = entry.get("threat_reasons") or reputation.get("reasons", [])
    parsed["active_triggers"] = entry.get("active_triggers", [])
    parsed["country"] = reputation.get("country", "Unknown")
    parsed["asn_honeypot"] = reputation.get("asn", "Unknown")
    parsed["scan_completed_at"] = datetime.now(timezone.utc).isoformat()
    parsed["raw_events"] = events

    safe = ip.replace(":", "_").replace("/", "_")
    suffix = ".active.json" if tier == "active" else ".json"
    out_path = OSINT_DIR / f"{safe}{suffix}"
    _save_json(out_path, serialise_footprint(parsed))
    logger.info(
        "Saved %s footprint %s (%d events, %d malicious)",
        tier, out_path.name, parsed["raw_event_count"],
        len(parsed.get("malicious_indicators", [])),
    )
