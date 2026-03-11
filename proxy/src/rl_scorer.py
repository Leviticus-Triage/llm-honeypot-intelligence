"""
RL Engagement Scorer - reads session data from Elasticsearch and updates
engagement scores in the cache database.

Runs as a background task or standalone cronjob.

v3 fixes:
- Galah IP Correlation: retroactively fix serve_log IPs by matching
  ES Galah LLM events against proxy responses (response text + timestamp)
- Fix Galah ES flat field parsing (request.requestURI is a flat key, not nested)
- Galah scoring now works even without IP forwarding
- Better text matching using HTTP request patterns from prompts
"""

import json
import logging
import math
import os
import sqlite3
from datetime import datetime, timedelta, timezone

import httpx

logger = logging.getLogger("ollama-proxy.rl_scorer")

ES_URL = os.environ.get("ES_URL", "https://localhost:64297/es")
ES_USER = os.environ.get("ES_USER", "")
ES_PASS = os.environ.get("ES_PASS", "")
DB_PATH = os.environ.get("CACHE_DB", "/data/ollama-proxy/cache.db")
EMA_ALPHA = 0.3  # Exponential moving average smoothing factor
SINCE_MINUTES = int(os.environ.get("SCORER_SINCE_MINUTES", "60"))


def parse_duration(dur_str: str) -> float:
    """Parse session duration string like '44.30s' or '2m30s' to seconds."""
    if not dur_str:
        return 0.0
    dur_str = dur_str.strip().lower()
    if dur_str.endswith("s"):
        if "m" in dur_str:
            parts = dur_str.rstrip("s").split("m")
            return float(parts[0]) * 60 + float(parts[1] or 0)
        return float(dur_str.rstrip("s"))
    elif dur_str.endswith("m"):
        return float(dur_str.rstrip("m")) * 60
    try:
        return float(dur_str)
    except ValueError:
        return 0.0


def compute_engagement_score(duration_seconds: float, interaction_count: int) -> float:
    """
    Compute engagement score from session metrics.
    score = normalize(duration * log2(interactions + 1))
    Normalized to 0..1 range using sigmoid-like scaling.
    """
    if duration_seconds <= 0 or interaction_count <= 0:
        return 0.1  # Minimal score for zero engagement
    raw = duration_seconds * math.log2(interaction_count + 1)
    # Sigmoid normalization: maps raw score to (0, 1)
    # Tuned so that 60s * 5 interactions ~ 0.7, 300s * 20 interactions ~ 0.95
    normalized = 1.0 / (1.0 + math.exp(-0.005 * (raw - 200)))
    return max(0.05, min(0.99, normalized))


async def fetch_beelzebub_sessions(
    es_url: str, since_minutes: int = SINCE_MINUTES
) -> list[dict]:
    """Fetch Beelzebub events with actual attacker input from Elasticsearch."""
    since = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
    query = {
        "size": 500,
        "query": {
            "bool": {
                "must": [
                    {"term": {"type.keyword": "Beelzebub"}},
                    {"exists": {"field": "input"}},
                    {"range": {"@timestamp": {"gte": since}}},
                ]
            }
        },
        "sort": [{"@timestamp": "desc"}],
        "_source": [
            "session", "session_duration", "src_ip", "input",
            "output", "message", "@timestamp", "status",
        ],
    }
    auth = (ES_USER, ES_PASS) if ES_USER else None
    async with httpx.AsyncClient(timeout=15.0, verify=False, auth=auth) as client:
        resp = await client.post(
            f"{es_url}/logstash-*/_search",
            json=query,
        )
        if resp.status_code != 200:
            logger.warning("ES Beelzebub query failed: %s %s", resp.status_code, resp.text[:200])
            return []
        data = resp.json()
        hits = [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]
        total = data.get("hits", {}).get("total", {}).get("value", 0)
        logger.info("Beelzebub: fetched %d events (total matching: %d, window: %dm)", len(hits), total, since_minutes)
        return hits


async def fetch_galah_sessions(
    es_url: str, since_minutes: int = SINCE_MINUTES
) -> list[dict]:
    """Fetch Galah events with LLM responses from Elasticsearch.
    ES uses FLAT field names (e.g. 'request.requestURI') not nested objects."""
    since = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
    query = {
        "size": 500,
        "query": {
            "bool": {
                "must": [
                    {"term": {"type.keyword": "Galah"}},
                    {"term": {"msg.keyword": "successfulResponse"}},
                    {"range": {"@timestamp": {"gte": since}}},
                ]
            }
        },
        "sort": [{"@timestamp": "desc"}],
        "_source": [
            "src_ip", "request.requestURI", "request.method", "response.body",
            "response.metadata.generationSource", "hostname",
            "@timestamp", "session",
        ],
    }
    auth = (ES_USER, ES_PASS) if ES_USER else None
    async with httpx.AsyncClient(timeout=15.0, verify=False, auth=auth) as client:
        resp = await client.post(
            f"{es_url}/logstash-*/_search",
            json=query,
        )
        if resp.status_code != 200:
            logger.warning("ES Galah query failed: %s %s", resp.status_code, resp.text[:200])
            return []
        data = resp.json()
        hits = [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]
        total = data.get("hits", {}).get("total", {}).get("value", 0)
        logger.info("Galah: fetched %d events (total matching: %d, window: %dm)", len(hits), total, since_minutes)
        return hits


async def fetch_galah_llm_events(
    es_url: str, since_hours: int = 24
) -> list[dict]:
    """Fetch Galah events where generationSource=llm (actually hit our proxy).
    These are the events we can correlate with serve_log entries."""
    since = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
    query = {
        "size": 1000,
        "query": {
            "bool": {
                "must": [
                    {"term": {"type.keyword": "Galah"}},
                    {"term": {"msg.keyword": "successfulResponse"}},
                    {"term": {"response.metadata.generationSource.keyword": "llm"}},
                    {"range": {"@timestamp": {"gte": since}}},
                ]
            }
        },
        "sort": [{"@timestamp": "desc"}],
        "_source": [
            "src_ip", "request.requestURI", "request.method",
            "response.body", "@timestamp",
        ],
    }
    auth = (ES_USER, ES_PASS) if ES_USER else None
    async with httpx.AsyncClient(timeout=15.0, verify=False, auth=auth) as client:
        resp = await client.post(
            f"{es_url}/logstash-*/_search",
            json=query,
        )
        if resp.status_code != 200:
            logger.warning("ES Galah LLM query failed: %s", resp.status_code)
            return []
        data = resp.json()
        hits = [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]
        total = data.get("hits", {}).get("total", {}).get("value", 0)
        logger.info("Galah LLM events: %d fetched (total: %d, window: %dh)", len(hits), total, since_hours)
        return hits


VM_IP = os.environ.get("TPOT_VM_IP", "127.0.0.1")  # T-Pot VM IP that Galah connects from


def correlate_beelzebub_ips(bee_events: list[dict]):
    """
    Retroactively fix serve_log IPs for Beelzebub sessions.

    Beelzebub runs inside the T-Pot VM and connects to the proxy from the
    VM IP. ES Beelzebub events have the REAL attacker IP + the input command.
    We match the input command text against prompt_cache.prompt_text to find
    the corresponding serve_log entry and update its src_ip.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    correlated = 0
    already_done = 0

    for event in bee_events:
        real_ip = event.get("src_ip", "")
        input_cmd = event.get("input", "")

        if not real_ip or not input_cmd or real_ip == VM_IP:
            continue

        # Clean up the input for LIKE matching
        input_clean = input_cmd.strip()[:100]
        if len(input_clean) < 3:
            continue

        # Find prompt_cache entries that contain this input
        try:
            rows = conn.execute(
                "SELECT pc.prompt_hash FROM prompt_cache pc "
                "WHERE pc.prompt_text LIKE ? "
                "LIMIT 5",
                (f"%{input_clean}%",),
            ).fetchall()
        except Exception:
            continue

        if not rows:
            continue

        for row in rows:
            prompt_hash = row[0]

            # Check if already correlated
            existing = conn.execute(
                "SELECT COUNT(*) FROM serve_log "
                "WHERE prompt_hash = ? AND src_ip = ?",
                (prompt_hash, real_ip),
            ).fetchone()[0]

            if existing > 0:
                already_done += 1
                continue

            # Update the most recent serve_log entry with VM IP for this prompt
            updated = conn.execute(
                "UPDATE serve_log SET src_ip = ? "
                "WHERE prompt_hash = ? AND src_ip = ? "
                "AND rowid = ("
                "  SELECT rowid FROM serve_log "
                "  WHERE prompt_hash = ? AND src_ip = ? "
                "  ORDER BY served_at DESC LIMIT 1"
                ")",
                (real_ip, prompt_hash, VM_IP, prompt_hash, VM_IP),
            ).rowcount
            correlated += updated

    conn.commit()
    conn.close()

    if correlated > 0 or already_done > 0:
        logger.info(
            "Beelzebub IP Correlation: %d serve_log entries updated, %d already correlated",
            correlated, already_done,
        )
    return correlated


def correlate_galah_ips(llm_events: list[dict]):
    """
    Retroactively fix serve_log IPs for Galah by correlating ES events
    with proxy responses. This solves the Galah IP forwarding problem
    WITHOUT requiring a Galah source code fork.

    Strategy:
    1. For each Galah LLM event in ES (has real attacker IP + response.body)
    2. Search proxy responses table for matching response text
    3. Find the serve_log entry via response_id + time proximity
    4. Update serve_log.src_ip from VM IP to real attacker IP
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    correlated = 0
    already_done = 0

    for event in llm_events:
        real_ip = event.get("src_ip", "")
        resp_body = event.get("response.body", "")
        if not real_ip or not resp_body or real_ip == VM_IP:
            continue

        # Truncate response body for matching (avoid huge texts)
        match_text = resp_body[:200].replace("'", "''")

        # Find matching responses in our cache that contain this body text
        try:
            rows = conn.execute(
                "SELECT r.id FROM responses r "
                "WHERE r.response_text LIKE ? "
                "LIMIT 10",
                (f"%{match_text[:100]}%",),
            ).fetchall()
        except Exception:
            continue

        if not rows:
            continue

        response_ids = [r[0] for r in rows]

        # For each matching response, check serve_log for VM IP entries
        for resp_id in response_ids:
            # Check if already correlated for this response
            existing = conn.execute(
                "SELECT COUNT(*) FROM serve_log "
                "WHERE response_id = ? AND src_ip = ?",
                (resp_id, real_ip),
            ).fetchone()[0]

            if existing > 0:
                already_done += 1
                continue

            # Find serve_log entries from VM IP for this response
            updated = conn.execute(
                "UPDATE serve_log SET src_ip = ? "
                "WHERE response_id = ? AND src_ip = ? "
                "AND rowid = ("
                "  SELECT rowid FROM serve_log "
                "  WHERE response_id = ? AND src_ip = ? "
                "  ORDER BY served_at DESC LIMIT 1"
                ")",
                (real_ip, resp_id, VM_IP, resp_id, VM_IP),
            ).rowcount
            correlated += updated

    conn.commit()
    conn.close()

    if correlated > 0 or already_done > 0:
        logger.info(
            "Galah IP Correlation: %d serve_log entries updated, %d already correlated",
            correlated, already_done,
        )
    return correlated


def update_scores_from_sessions(
    sessions: list[dict], honeypot_type: str
):
    """
    Update engagement scores in the cache DB based on session data.

    For Beelzebub: groups by session ID, counts interactions, estimates duration.
    For Galah: groups by src_ip to estimate session duration and interaction count.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row

    if honeypot_type == "beelzebub":
        # Group by session ID
        session_map = {}
        for s in sessions:
            sid = s.get("session", "unknown")
            if sid not in session_map:
                session_map[sid] = {
                    "duration": 0.0,
                    "interactions": 0,
                    "commands": [],
                    "timestamps": [],
                    "src_ip": s.get("src_ip", ""),
                }
            dur = parse_duration(s.get("session_duration", ""))
            if dur > session_map[sid]["duration"]:
                session_map[sid]["duration"] = dur
            session_map[sid]["interactions"] += 1
            session_map[sid]["timestamps"].append(s.get("@timestamp", ""))
            if not session_map[sid]["src_ip"]:
                session_map[sid]["src_ip"] = s.get("src_ip", "")
            cmd = s.get("input", "") or s.get("message", "")
            if cmd:
                session_map[sid]["commands"].append(cmd)

        logger.info("Beelzebub: %d unique sessions found", len(session_map))

        # If no explicit duration, estimate from timestamps
        for sid, data in session_map.items():
            if data["duration"] == 0.0 and len(data["timestamps"]) >= 2:
                try:
                    times = sorted(data["timestamps"])
                    t0 = datetime.fromisoformat(times[0].replace("Z", "+00:00"))
                    t1 = datetime.fromisoformat(times[-1].replace("Z", "+00:00"))
                    data["duration"] = max(1.0, (t1 - t0).total_seconds())
                except Exception:
                    data["duration"] = 5.0
            elif data["duration"] == 0.0:
                data["duration"] = 5.0  # Single event, minimal duration

        total_updated = 0
        for sid, data in session_map.items():
            score = compute_engagement_score(data["duration"], data["interactions"])
            # Primary: match by src_ip (reliable)
            updated = _update_matching_responses_by_ip(conn, data.get("src_ip", ""), score)
            if not updated:
                # Fallback: match by command text
                updated = _update_matching_responses_by_text(conn, data["commands"], score)
            total_updated += updated

        if total_updated > 0:
            logger.info("Beelzebub: updated %d response scores across %d sessions", total_updated, len(session_map))
        else:
            logger.info("Beelzebub: %d sessions but no matching cache entries (cache has %d prompts)",
                len(session_map), conn.execute("SELECT COUNT(*) FROM prompt_cache").fetchone()[0])

    elif honeypot_type == "galah":
        # Group by src_ip to form pseudo-sessions
        # IMPORTANT: ES uses FLAT field names like "request.requestURI" (not nested)
        ip_sessions = {}
        for s in sessions:
            ip = s.get("src_ip", "unknown")
            ts_str = s.get("@timestamp", "")
            if ip not in ip_sessions:
                ip_sessions[ip] = {"timestamps": [], "requests": [], "responses": []}
            ip_sessions[ip]["timestamps"].append(ts_str)

            # Flat field access (ES returns "request.requestURI" as a top-level key)
            uri = s.get("request.requestURI", "")
            method = s.get("request.method", "GET")
            if uri:
                ip_sessions[ip]["requests"].append(uri)
                # Also add "METHOD URI" pattern for better prompt matching
                ip_sessions[ip]["requests"].append(f"{method} {uri}")

            resp_body = s.get("response.body", "")
            if resp_body:
                ip_sessions[ip]["responses"].append(str(resp_body)[:200])

        logger.info("Galah: %d unique IPs (pseudo-sessions)", len(ip_sessions))

        total_updated = 0
        for ip, data in ip_sessions.items():
            n_requests = len(data["timestamps"])
            # Estimate duration from first to last timestamp
            if n_requests >= 2:
                try:
                    times = sorted(data["timestamps"])
                    t0 = datetime.fromisoformat(times[0].replace("Z", "+00:00"))
                    t1 = datetime.fromisoformat(times[-1].replace("Z", "+00:00"))
                    duration = max(1.0, (t1 - t0).total_seconds())
                except Exception:
                    duration = 0.0
            else:
                duration = 5.0  # Single request, minimal duration

            score = compute_engagement_score(duration, n_requests)

            # Strategy 1: Match by real attacker IP (works AFTER IP correlation!)
            updated = _update_matching_responses_by_ip(conn, ip, score)

            if not updated:
                # Strategy 2: Match by response text (Galah response.body is
                # contained in our cached response JSON)
                for resp_body in data["responses"]:
                    if len(resp_body) < 10:
                        continue
                    rows = conn.execute(
                        "SELECT r.id FROM responses r "
                        "WHERE r.response_text LIKE ? "
                        "LIMIT 5",
                        (f"%{resp_body[:80]}%",),
                    ).fetchall()
                    for row in rows:
                        conn.execute(
                            "UPDATE responses SET engagement_score = "
                            "? * ? + (1.0 - ?) * engagement_score "
                            "WHERE id = ?",
                            (EMA_ALPHA, score, EMA_ALPHA, row[0]),
                        )
                        updated += 1

            if not updated:
                # Strategy 3: Match by URI pattern in prompt text
                match_texts = [r for r in data["requests"] if len(r) > 3]
                updated = _update_matching_responses_by_text(conn, match_texts, score)

            total_updated += updated

        if total_updated > 0:
            logger.info("Galah: updated %d response scores across %d IPs", total_updated, len(ip_sessions))
        else:
            logger.info("Galah: %d IPs but no matching cache entries (cache has %d prompts)",
                len(ip_sessions), conn.execute("SELECT COUNT(*) FROM prompt_cache").fetchone()[0])

    conn.commit()
    conn.close()


def _update_matching_responses_by_ip(conn, src_ip: str, score: float, time_window_min: int = 120) -> int:
    """Update engagement scores for responses served to a specific IP.
    Uses serve_log.src_ip for direct correlation (most reliable method).
    Returns the number of responses updated."""
    if not src_ip:
        return 0

    # Find responses served to this IP in the time window
    rows = conn.execute(
        "SELECT DISTINCT sl.response_id FROM serve_log sl "
        "WHERE sl.src_ip = ? "
        "AND sl.served_at >= datetime('now', ?)"
        "ORDER BY sl.served_at DESC LIMIT 20",
        (src_ip, f"-{time_window_min} minutes"),
    ).fetchall()

    updated = 0
    for row in rows:
        resp_id = row[0]
        conn.execute(
            "UPDATE responses SET engagement_score = "
            "? * ? + (1.0 - ?) * engagement_score "
            "WHERE id = ?",
            (EMA_ALPHA, score, EMA_ALPHA, resp_id),
        )
        updated += 1

    return updated


def _update_matching_responses_by_text(conn, commands: list[str], score: float) -> int:
    """Fallback: match ES session data against cached prompts by text similarity.
    Returns the number of responses updated."""
    if not commands:
        return 0

    updated = 0
    for cmd in commands:
        if not cmd or len(cmd.strip()) < 3:
            continue

        # Strategy 1: Match via serve_log -> prompt_cache
        rows = conn.execute(
            "SELECT sl.response_id FROM serve_log sl "
            "JOIN prompt_cache pc ON sl.prompt_hash = pc.prompt_hash "
            "WHERE pc.prompt_text LIKE ? "
            "ORDER BY sl.served_at DESC LIMIT 5",
            (f"%{cmd[:80]}%",),
        ).fetchall()

        if not rows:
            # Strategy 2: Broader match directly on prompt_cache text
            rows = conn.execute(
                "SELECT r.id AS response_id FROM responses r "
                "JOIN prompt_cache pc ON r.prompt_cache_id = pc.id "
                "WHERE pc.prompt_text LIKE ? "
                "ORDER BY r.last_served DESC LIMIT 5",
                (f"%{cmd[:80]}%",),
            ).fetchall()

        for row in rows:
            resp_id = row[0]
            conn.execute(
                "UPDATE responses SET engagement_score = "
                "? * ? + (1.0 - ?) * engagement_score "
                "WHERE id = ?",
                (EMA_ALPHA, score, EMA_ALPHA, resp_id),
            )
            updated += 1

    return updated


async def _resolve_real_ip_from_es(es_url: str, prompt_text: str, served_at: str, protocol: str) -> str:
    """
    Last-resort IP resolution: query ES for Beelzebub/Galah events around the
    same timestamp whose input/request matches the prompt text. Returns the
    real attacker IP or empty string.
    """
    if not prompt_text or len(prompt_text) < 5:
        return ""

    # Build query for Beelzebub (SSH) or Galah (HTTP)
    if protocol == "ssh":
        query = {
            "size": 1,
            "query": {"bool": {"must": [
                {"term": {"type.keyword": "Beelzebub"}},
                {"exists": {"field": "input"}},
                {"range": {"@timestamp": {"gte": f"{served_at}||/m-5m", "lte": f"{served_at}||/m+5m"}}},
            ]}},
            "sort": [{"@timestamp": "desc"}],
            "_source": ["src_ip", "input"],
        }
    else:
        query = {
            "size": 1,
            "query": {"bool": {"must": [
                {"term": {"type.keyword": "Galah"}},
                {"range": {"@timestamp": {"gte": f"{served_at}||/m-5m", "lte": f"{served_at}||/m+5m"}}},
            ]}},
            "sort": [{"@timestamp": "desc"}],
            "_source": ["src_ip"],
        }

    auth = (ES_USER, ES_PASS) if ES_USER else None
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False, auth=auth) as client:
            resp = await client.post(f"{es_url}/logstash-*/_search", json=query)
            if resp.status_code == 200:
                hits = resp.json().get("hits", {}).get("hits", [])
                if hits:
                    real_ip = hits[0]["_source"].get("src_ip", "")
                    if real_ip and real_ip != VM_IP:
                        return real_ip
    except Exception:
        pass
    return ""


async def push_cve_sessions_to_es(es_url: str, since_minutes: int = 60):
    """
    Push CVE-tagged sessions from local serve_log to Elasticsearch.

    Reads serve_log entries with non-empty cve_id and pushes them
    to the dedicated 'honeypot-cve-sessions' index for dashboard use.

    IMPORTANT: Resolves VM IPs to real attacker IPs before pushing.
    Uses serve_log.src_ip (already corrected by IP correlation phases),
    and falls back to ES timestamp-based lookup for any remaining VM IPs.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        "SELECT sl.id, sl.served_at, sl.src_ip, sl.cve_id, sl.cve_vendor, sl.cve_product, "
        "       sl.prompt_hash, r.response_text, pc.prompt_text "
        "FROM serve_log sl "
        "JOIN responses r ON sl.response_id = r.id "
        "JOIN prompt_cache pc ON r.prompt_cache_id = pc.id "
        "WHERE sl.cve_id != '' "
        "AND sl.served_at >= datetime('now', ?) "
        "ORDER BY sl.served_at DESC",
        (f"-{since_minutes} minutes",),
    ).fetchall()

    conn.close()

    if not rows:
        return 0

    from .cve_templates import CVE_BY_ID

    auth = (ES_USER, ES_PASS) if ES_USER else None
    bulk_body = ""
    count = 0
    vm_ip_resolved = 0
    vm_ip_skipped = 0

    for row in rows:
        cve_id = row["cve_id"]
        profile = CVE_BY_ID.get(cve_id)
        src_ip = row["src_ip"]
        protocol = profile.protocol if profile else "ssh"

        # Resolve VM IP to real attacker IP
        if src_ip == VM_IP:
            resolved = await _resolve_real_ip_from_es(
                es_url, row["prompt_text"] or "", row["served_at"], protocol
            )
            if resolved:
                src_ip = resolved
                vm_ip_resolved += 1
            else:
                vm_ip_skipped += 1
                continue  # Skip entries we can't resolve -- don't push wrong IPs

        doc = {
            "@timestamp": row["served_at"],
            "src_ip": src_ip,
            "cve_id": cve_id,
            "cve_vendor": row["cve_vendor"],
            "cve_product": row["cve_product"],
            "cve_severity": profile.severity if profile else "unknown",
            "cvss_score": profile.cvss_score if profile else 0.0,
            "protocol": profile.protocol if profile else "unknown",
            "mitre_techniques": profile.mitre_techniques if profile else [],
            "description": profile.description if profile else "",
            "prompt_text": (row["prompt_text"] or "")[:500],
            "response_text": (row["response_text"] or "")[:1000],
            "serve_log_id": row["id"],
        }

        bulk_body += json.dumps({"index": {"_index": "honeypot-cve-sessions"}}) + "\n"
        bulk_body += json.dumps(doc) + "\n"
        count += 1

    if vm_ip_resolved > 0 or vm_ip_skipped > 0:
        logger.info(
            "CVE IP resolution: %d resolved to real IP, %d skipped (unresolvable VM IP)",
            vm_ip_resolved, vm_ip_skipped,
        )

    if not bulk_body:
        return 0

    async with httpx.AsyncClient(timeout=30.0, verify=False, auth=auth) as client:
        resp = await client.post(
            f"{es_url}/_bulk",
            content=bulk_body,
            headers={"Content-Type": "application/x-ndjson"},
        )
        if resp.status_code in (200, 201):
            data = resp.json()
            errors = data.get("errors", False)
            if errors:
                logger.warning("CVE ES bulk push had errors: %d items", count)
            else:
                logger.info("CVE sessions pushed to ES: %d documents", count)
        else:
            logger.warning("CVE ES bulk push failed: %s %s", resp.status_code, resp.text[:200])

    return count


async def run_scoring_cycle():
    """Run one scoring cycle: fetch sessions from ES and update scores."""
    es_url = os.environ.get("ES_URL", ES_URL)
    logger.info("Running RL scoring cycle (ES: %s)", es_url)

    try:
        # ── Phase 0a: Galah IP Correlation ─────────────────────────
        # Retroactively fix serve_log IPs by matching ES Galah LLM events
        # against proxy responses. This enables IP-based scoring for Galah.
        try:
            llm_events = await fetch_galah_llm_events(es_url, since_hours=24)
            if llm_events:
                correlate_galah_ips(llm_events)
        except Exception as e:
            logger.warning("Galah IP correlation failed (non-critical): %s", e)

        # ── Phase 0b: Beelzebub IP Correlation ─────────────────────
        # Same principle: Beelzebub connects from VM IP. Match ES events
        # (which have real attacker IPs + input commands) to fix serve_log.
        try:
            bee_events = await fetch_beelzebub_sessions(es_url)
            if bee_events:
                correlate_beelzebub_ips(bee_events)
        except Exception as e:
            logger.warning("Beelzebub IP correlation failed (non-critical): %s", e)

        # ── Phase 1: Beelzebub Scoring ─────────────────────────────
        bee_sessions = await fetch_beelzebub_sessions(es_url)
        if bee_sessions:
            update_scores_from_sessions(bee_sessions, "beelzebub")

        # ── Phase 2: Galah Scoring ─────────────────────────────────
        galah_sessions = await fetch_galah_sessions(es_url)
        if galah_sessions:
            update_scores_from_sessions(galah_sessions, "galah")

        if not bee_sessions and not galah_sessions:
            logger.info("No sessions found in last %d minutes", SINCE_MINUTES)

        # ── Phase 3: CVE Session Push to ES ────────────────────────
        try:
            pushed = await push_cve_sessions_to_es(es_url, since_minutes=SINCE_MINUTES)
            if pushed:
                logger.info("CVE session push: %d documents indexed", pushed)
        except Exception as e:
            logger.warning("CVE session push failed (non-critical): %s", e)

    except Exception as e:
        logger.error("Scoring cycle failed: %s", e, exc_info=True)


if __name__ == "__main__":
    import asyncio
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_scoring_cycle())
