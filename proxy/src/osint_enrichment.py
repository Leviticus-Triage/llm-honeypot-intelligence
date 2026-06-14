"""
Parse SpiderFoot scan exports into structured IOCs and enrichment metadata
for rule generation, campaign clustering, and fail2ban blocklists.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("ollama-proxy.osint")

OSINT_DIR = Path(
    os.environ.get(
        "OSINT_FOOTPRINTS_DIR",
        "/data/ollama-proxy/threat-intel/osint-footprints",
    )
)

# SpiderFoot event types we care about for IOC extraction
IP_TYPES = {
    "IP_ADDRESS", "IPV6_ADDRESS", "AFFILIATE_IPADDR",
    "NETBLOCK_OWNER", "NETBLOCK_MEMBER",
}
DOMAIN_TYPES = {
    "INTERNET_NAME", "DOMAIN_NAME", "AFFILIATE_INTERNET_NAME",
    "CO_HOSTED_SITE", "SIMILARDOMAIN",
}
URL_TYPES = {"LINKED_URL_INTERNAL", "LINKED_URL_EXTERNAL", "URL_FORM"}
HASH_TYPES = {"HASH", "SHA256", "SHA1", "MD5"}
EMAIL_TYPES = {"EMAILADDR", "EMAILADDR_COMPROMISED"}
ASN_TYPES = {"ASN", "BGP_AS_OWNER", "ASN_ADVERTISEMENT"}
ORG_TYPES = {"ASN_ADVERTISEMENT", "COMPANY_NAME", "PROVIDER_HOSTING"}
MALICIOUS_TYPES = {
    "MALICIOUS_IPADDR", "MALICIOUS_INTERNET_NAME",
    "BLACKLISTED_IPADDR", "BLACKLISTED_INTERNET_NAME",
    "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_COHOST",
}

PRIVATE_IP_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.)"
)


def is_private_ip(ip: str) -> bool:
    return bool(PRIVATE_IP_RE.match(ip or ""))


def parse_spiderfoot_events(
    events: list[dict],
    *,
    seed_target: str = "",
    scan_id: str = "",
) -> dict[str, Any]:
    """
    Convert raw SpiderFoot JSON export into normalized enrichment dict.
    """
    result: dict[str, Any] = {
        "seed_target": seed_target,
        "scan_id": scan_id,
        "parsed_at": datetime.now(timezone.utc).isoformat(),
        "ipv4": Counter(),
        "ipv6": set(),
        "domains": set(),
        "urls": set(),
        "hashes_sha256": set(),
        "hashes_md5": set(),
        "emails": set(),
        "asns": set(),
        "organizations": set(),
        "hostnames": set(),
        "malicious_indicators": [],
        "raw_event_count": len(events),
        "modules_seen": set(),
        "event_types": Counter(),
    }

    for ev in events:
        if not isinstance(ev, dict):
            continue

        # SpiderFoot export: {type, data, module, source, ...}
        ev_type = str(ev.get("type", ev.get("event_type", ""))).upper()
        data = str(ev.get("data", ev.get("value", ""))).strip()
        module = str(ev.get("module", ev.get("source_module", "")))
        source = str(ev.get("source", ""))

        if not data:
            continue

        result["event_types"][ev_type] += 1
        if module:
            result["modules_seen"].add(module)

        if ev_type in IP_TYPES or _looks_like_ip(data):
            if ":" in data and "." not in data:
                result["ipv6"].add(data)
            elif not is_private_ip(data):
                result["ipv4"][data] += 1

        if ev_type in DOMAIN_TYPES or (
            ev_type == "RAW_DNS_RECORDS" and "." in data
        ):
            domain = _extract_domain(data)
            if domain and not _looks_like_ip(domain):
                result["domains"].add(domain)
                result["hostnames"].add(domain)

        if ev_type in URL_TYPES or data.startswith(("http://", "https://")):
            result["urls"].add(data[:500])

        if ev_type in HASH_TYPES:
            if len(data) == 64:
                result["hashes_sha256"].add(data.lower())
            elif len(data) == 32:
                result["hashes_md5"].add(data.lower())

        if ev_type in EMAIL_TYPES and "@" in data:
            result["emails"].add(data.lower())

        if ev_type in ASN_TYPES or ev_type == "ASN":
            result["asns"].add(data)

        if ev_type in ORG_TYPES:
            result["organizations"].add(data[:200])

        if ev_type in MALICIOUS_TYPES or "MALICIOUS" in ev_type:
            result["malicious_indicators"].append({
                "type": ev_type,
                "data": data[:300],
                "module": module,
                "source": source,
            })

    # Convert sets for JSON serialization downstream
    result["modules_seen"] = sorted(result["modules_seen"])
    result["event_types"] = dict(result["event_types"].most_common(50))
    return result


def _looks_like_ip(value: str) -> bool:
    return bool(re.match(r"^[\d.:a-fA-F]+$", value)) and "." in value


def _extract_domain(value: str) -> str | None:
    value = value.strip().lower()
    if value.startswith("http"):
        m = re.match(r"https?://([^/:]+)", value)
        return m.group(1) if m else None
    if re.match(r"^[a-z0-9][-a-z0-9.]*\.[a-z]{2,}$", value):
        return value
    return None


def load_all_footprints(base_dir: Path | None = None) -> dict[str, dict]:
    """
    Load completed footprint JSON files keyed by seed IP/target.

    Passive: <ip>.json — Active: <ip>.active.json (merged, active fields win).
    """
    base = base_dir or OSINT_DIR
    footprints: dict[str, dict] = {}

    if not base.exists():
        return footprints

    for path in sorted(base.glob("*.json")):
        if path.name in ("index.json", "footprint_queue.json"):
            continue
        try:
            with open(path) as f:
                payload = json.load(f)
            stem = path.name
            if stem.endswith(".active.json"):
                target = payload.get("seed_target") or stem[: -len(".active.json")]
            else:
                target = payload.get("seed_target") or path.stem
            if target in footprints:
                footprints[target] = {**footprints[target], **payload}
            else:
                footprints[target] = payload
        except Exception as exc:
            logger.warning("Could not load footprint %s: %s", path, exc)

    logger.info("Loaded %d OSINT footprints from %s", len(footprints), base)
    return footprints


def aggregate_osint(footprints: dict[str, dict]) -> dict[str, Any]:
    """Merge all footprints into a single enrichment bundle for rule gen."""
    agg: dict[str, Any] = {
        "footprint_count": len(footprints),
        "ipv4": Counter(),
        "domains": set(),
        "urls": set(),
        "hashes_sha256": set(),
        "hashes_md5": set(),
        "emails": set(),
        "asns": set(),
        "organizations": set(),
        "malicious_indicators": [],
        "targets": {},
    }

    for target, fp in footprints.items():
        agg["targets"][target] = {
            "scan_id": fp.get("scan_id"),
            "threat_level": fp.get("threat_level"),
            "score": fp.get("reputation_score"),
            "reasons": fp.get("threat_reasons", [])[:5],
            "related_ips": len(fp.get("ipv4", {})),
            "related_domains": len(fp.get("domains", [])),
            "malicious_count": len(fp.get("malicious_indicators", [])),
        }

        for ip, count in (fp.get("ipv4") or {}).items():
            if not is_private_ip(ip) and ip != target:
                agg["ipv4"][ip] += count

        for key in ("domains", "urls", "hashes_sha256", "hashes_md5", "emails", "asns", "organizations"):
            val = fp.get(key)
            if isinstance(val, list):
                agg[key].update(val)
            elif isinstance(val, dict):
                agg[key].update(val.keys())
            elif isinstance(val, set):
                agg[key].update(val)

        agg["malicious_indicators"].extend(fp.get("malicious_indicators", []))

    return agg


def enrich_campaigns(
    campaigns: list[dict],
    footprints: dict[str, dict],
) -> list[dict]:
    """Attach OSINT context to campaign records for clustering visibility."""
    enriched = []
    for camp in campaigns:
        copy = dict(camp)
        osint_context = []
        shared_domains: set[str] = set()
        shared_asns: set[str] = set()
        malicious_hits = 0

        for ip in camp.get("ips", []):
            fp = footprints.get(ip)
            if not fp:
                continue
            osint_context.append({
                "ip": ip,
                "domains": sorted(fp.get("domains", []))[:10],
                "asns": sorted(fp.get("asns", []))[:5],
                "malicious": len(fp.get("malicious_indicators", [])),
                "organizations": sorted(fp.get("organizations", []))[:3],
            })
            shared_domains.update(fp.get("domains", []))
            shared_asns.update(fp.get("asns", []))
            malicious_hits += len(fp.get("malicious_indicators", []))

        copy["osint"] = {
            "footprinted_ips": len(osint_context),
            "shared_domains": sorted(shared_domains)[:20],
            "shared_asns": sorted(shared_asns)[:10],
            "malicious_indicator_count": malicious_hits,
            "per_ip": osint_context,
        }
        enriched.append(copy)

    return enriched


def merge_osint_into_iocs(iocs: dict, agg: dict) -> dict:
    """Merge aggregated OSINT into existing IOC dict from honeypot data."""
    for ip, count in (agg.get("ipv4") or {}).items():
        iocs["ipv4"][ip] = iocs["ipv4"].get(ip, 0) + count

    for key in ("domains", "urls", "hashes_sha256", "hashes_md5", "emails"):
        if key in iocs and key in agg:
            iocs[key].update(agg[key])

    iocs["osint_asns"] = sorted(agg.get("asns", set()))
    iocs["osint_organizations"] = sorted(agg.get("organizations", set()))
    iocs["osint_malicious"] = agg.get("malicious_indicators", [])[:100]
    iocs["osint_footprint_targets"] = list(agg.get("targets", {}).keys())
    return iocs


def serialise_footprint(parsed: dict) -> dict:
    """Convert sets/Counters to JSON-safe types for disk storage."""
    out = dict(parsed)
    for key in ("ipv4",):
        if isinstance(out.get(key), Counter):
            out[key] = dict(out[key])
    for key in ("ipv6", "domains", "urls", "hashes_sha256", "hashes_md5",
                "emails", "asns", "organizations", "hostnames"):
        if isinstance(out.get(key), set):
            out[key] = sorted(out[key])
    return out
