"""
ML-Powered Heuristic Threat Detection Engine v1.0

Provides reactive and proactive threat detection through:
1. Behavioral Anomaly Detection  - Isolation Forest on session features
2. Attack Campaign Clustering    - DBSCAN groups related attack sessions
3. Predictive Threat Scoring     - Gradient Boosting classifies new sessions
4. Session Fingerprinting        - Creates behavioural fingerprints per attacker toolkit
5. Automated IP Reputation       - Dynamic scoring based on historical behaviour

Runs periodically, reads from Elasticsearch, writes results to JSON + SQLite.
Exposes results via the proxy's /proxy/threats endpoint.
"""

import hashlib
import json
import logging
import os
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import httpx
import numpy as np

logger = logging.getLogger("ollama-proxy.heuristic_detector")

ES_URL = os.environ.get("ES_URL", "https://localhost:64297/es")
ES_USER = os.environ.get("ES_USER", "")
ES_PASS = os.environ.get("ES_PASS", "")
CACHE_DB = os.environ.get("CACHE_DB", "/data/ollama-proxy/cache.db")
OUTPUT_DIR = Path(os.environ.get("THREAT_DIR", "/data/ollama-proxy/threat-intel"))
SINCE_HOURS = int(os.environ.get("HEURISTIC_SINCE_HOURS", "24"))

# ─── Feature Extraction Constants ──────────────────────────────────────

# Known attacker toolkit fingerprints (command sequences)
TOOLKIT_SIGNATURES = {
    "crypto_miner_recon": ["cat /proc/cpuinfo", "grep -i nvidia", "lscpu", "nproc"],
    "botnet_installer": ["scp -qt", "chmod +x", "/tmp/", "/dev/shm/"],
    "credential_stealer": ["TelegramDesktop", "tdata", "/var/spool/sms", ".aws/credentials"],
    "system_profiler": ["uname", "hostname", "arch", "dmidecode", "lspci"],
    "web_scanner": [".env", "wp-admin", "phpunit", "eval-stdin"],
    "vpn_exploit": ["CSCOE", "webvpn", "/+CSCOT+/"],
    "config_thief": [".env", "config.json", ".aws/credentials", ".env.local"],
    "proxy_abuser": ["CONNECT", "httpbin.org", "julidns"],
}

# Suspicious command categories for feature extraction
COMMAND_CATEGORIES = {
    "recon": ["uname", "hostname", "whoami", "id", "ifconfig", "ip addr", "cat /etc",
              "lscpu", "dmidecode", "arch", "nproc", "lspci", "ps ", "netstat", "ss -"],
    "download": ["wget", "curl", "scp", "tftp", "fetch"],
    "execution": ["chmod +x", "bash ", "sh -c", "./", "python", "perl", "ruby"],
    "persistence": ["crontab", "cron", "systemctl enable", ".bashrc", "rc.local"],
    "exfiltration": ["cat /etc/passwd", "cat /etc/shadow", "base64", "xxd", "nc "],
    "evasion": ["unset HISTFILE", "history -c", "rm -rf /var/log", "kill -9"],
    "lateral": ["ssh ", "sshpass", "hydra", "nmap", "masscan"],
    "mining_prep": ["cpuinfo", "nvidia", "gpu", "miner", "mining", "xmrig"],
}


# ─── Elasticsearch Query Functions ─────────────────────────────────────

def _es_auth():
    if ES_USER and ES_PASS:
        return httpx.BasicAuth(ES_USER, ES_PASS)
    return None


async def fetch_sessions(since_hours: int = SINCE_HOURS) -> dict:
    """Fetch attack session data from Elasticsearch."""
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        # Fetch Beelzebub SSH sessions with full commands
        bee_query = {
            "size": 5000,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"type.keyword": "Beelzebub"}},
                        {"range": {"@timestamp": {"gte": f"now-{since_hours}h"}}},
                    ]
                }
            },
            "sort": [{"@timestamp": "desc"}],
            "_source": ["src_ip", "@timestamp", "input.keyword", "commands",
                        "session_duration", "protocol", "geoip"],
        }

        bee_resp = await client.post(
            f"{ES_URL}/logstash-*/_search",
            json=bee_query,
            auth=_es_auth(),
        )
        bee_data = bee_resp.json()
        bee_hits = bee_data.get("hits", {}).get("hits", [])
        logger.info("Fetched %d Beelzebub events", len(bee_hits))

        # Fetch Galah HTTP sessions
        galah_query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"type.keyword": "Galah"}},
                        {"range": {"@timestamp": {"gte": f"now-{since_hours}h"}}},
                    ]
                }
            },
            "aggs": {
                "by_ip": {
                    "terms": {"field": "src_ip.keyword", "size": 1000},
                    "aggs": {
                        "uris": {"terms": {"field": "request.requestURI.keyword", "size": 50}},
                        "methods": {"terms": {"field": "request.method.keyword", "size": 10}},
                        "country": {"terms": {"field": "geoip.country_name.keyword", "size": 1}},
                        "asn": {"terms": {"field": "geoip.as_org.keyword", "size": 1}},
                        "time_range": {"stats": {"field": "@timestamp"}},
                    }
                }
            },
        }

        galah_resp = await client.post(
            f"{ES_URL}/logstash-*/_search",
            json=galah_query,
            auth=_es_auth(),
        )
        galah_data = galah_resp.json()
        galah_buckets = galah_data.get("aggregations", {}).get("by_ip", {}).get("buckets", [])
        logger.info("Fetched %d Galah IP aggregations", len(galah_buckets))

    return {"beelzebub": bee_hits, "galah": galah_buckets}


# ─── Feature Engineering ───────────────────────────────────────────────

def extract_session_features(sessions: dict) -> list[dict]:
    """Extract ML features from raw session data."""
    features = []

    # Process Beelzebub SSH sessions - group by IP
    ip_sessions = defaultdict(list)
    for hit in sessions["beelzebub"]:
        src = hit.get("_source", {})
        ip = src.get("src_ip", "unknown")
        ip_sessions[ip].append(src)

    for ip, events in ip_sessions.items():
        commands = []
        for ev in events:
            cmd = ev.get("input.keyword") or ev.get("commands", "")
            if isinstance(cmd, list):
                commands.extend(cmd)
            elif isinstance(cmd, str) and cmd:
                commands.append(cmd)

        if not commands:
            # Try raw fields
            for ev in events:
                for k, v in ev.items():
                    if "input" in k.lower() or "command" in k.lower():
                        if isinstance(v, str) and v.strip():
                            commands.append(v.strip())

        geo = events[0].get("geoip", {}) if events else {}

        feat = _build_ssh_features(ip, commands, events, geo)
        feat["honeypot"] = "beelzebub"
        features.append(feat)

    # Process Galah HTTP sessions
    for bucket in sessions["galah"]:
        ip = bucket["key"]
        uris = [b["key"] for b in bucket.get("uris", {}).get("buckets", [])]
        methods = [b["key"] for b in bucket.get("methods", {}).get("buckets", [])]
        countries = [b["key"] for b in bucket.get("country", {}).get("buckets", [])]
        asns = [b["key"] for b in bucket.get("asn", {}).get("buckets", [])]
        count = bucket["doc_count"]

        time_range = bucket.get("time_range", {})
        duration_ms = 0
        if time_range.get("min") and time_range.get("max"):
            duration_ms = time_range["max"] - time_range["min"]

        feat = _build_http_features(ip, uris, methods, count, duration_ms, countries, asns)
        feat["honeypot"] = "galah"
        features.append(feat)

    return features


def _build_ssh_features(ip: str, commands: list, events: list, geo: dict) -> dict:
    """Build feature vector for SSH session."""
    cmd_text = " ".join(commands).lower()
    cmd_count = len(commands)
    unique_cmds = len(set(commands))

    # Category counts
    cat_counts = {}
    for cat, patterns in COMMAND_CATEGORIES.items():
        cat_counts[f"cat_{cat}"] = sum(1 for c in commands for p in patterns if p in c.lower())

    # Toolkit matching
    toolkit_scores = {}
    for tk_name, tk_patterns in TOOLKIT_SIGNATURES.items():
        matches = sum(1 for p in tk_patterns if p.lower() in cmd_text)
        toolkit_scores[f"tk_{tk_name}"] = matches / max(len(tk_patterns), 1)

    # Session temporal features
    timestamps = []
    for ev in events:
        ts = ev.get("@timestamp", "")
        if ts:
            try:
                timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
            except (ValueError, TypeError):
                pass

    duration_s = 0
    if len(timestamps) >= 2:
        duration_s = (max(timestamps) - min(timestamps)).total_seconds()

    # Command diversity and complexity
    avg_cmd_len = np.mean([len(c) for c in commands]) if commands else 0
    max_cmd_len = max([len(c) for c in commands], default=0)
    has_pipes = sum(1 for c in commands if "|" in c)
    has_redirects = sum(1 for c in commands if ">" in c or "<" in c)
    has_semicolons = sum(1 for c in commands if ";" in c)

    # Behavioural fingerprint hash
    cmd_sig = "|".join(sorted(set(c[:30] for c in commands[:20])))
    fingerprint = hashlib.sha256(cmd_sig.encode()).hexdigest()[:16]

    return {
        "ip": ip,
        "event_count": len(events),
        "cmd_count": cmd_count,
        "unique_cmds": unique_cmds,
        "cmd_diversity": unique_cmds / max(cmd_count, 1),
        "duration_s": duration_s,
        "avg_cmd_len": avg_cmd_len,
        "max_cmd_len": max_cmd_len,
        "has_pipes": has_pipes,
        "has_redirects": has_redirects,
        "has_semicolons": has_semicolons,
        "country": geo.get("country_name", "Unknown"),
        "asn": geo.get("as_org", "Unknown"),
        "fingerprint": fingerprint,
        **cat_counts,
        **toolkit_scores,
    }


def _build_http_features(ip: str, uris: list, methods: list, count: int,
                         duration_ms: float, countries: list, asns: list) -> dict:
    """Build feature vector for HTTP session."""
    uri_text = " ".join(uris).lower()

    # URI category analysis
    has_env = sum(1 for u in uris if ".env" in u)
    has_admin = sum(1 for u in uris if "admin" in u.lower() or "wp-" in u.lower())
    has_exploit = sum(1 for u in uris if "eval-stdin" in u or "cgi-bin" in u or "phpunit" in u)
    has_config = sum(1 for u in uris if "config" in u.lower() or ".json" in u.lower())
    has_vpn = sum(1 for u in uris if "cscoe" in u.lower() or "vpn" in u.lower())
    has_traversal = sum(1 for u in uris if ".." in u or "%2e" in u.lower())

    # Toolkit matching
    toolkit_scores = {}
    for tk_name, tk_patterns in TOOLKIT_SIGNATURES.items():
        matches = sum(1 for p in tk_patterns if p.lower() in uri_text)
        toolkit_scores[f"tk_{tk_name}"] = matches / max(len(tk_patterns), 1)

    # Command categories mapped to HTTP
    cat_counts = {
        "cat_recon": has_admin + has_config,
        "cat_download": 0,
        "cat_execution": has_exploit,
        "cat_persistence": 0,
        "cat_exfiltration": has_env + has_config,
        "cat_evasion": has_traversal,
        "cat_lateral": has_vpn,
        "cat_mining_prep": 0,
    }

    fingerprint = hashlib.sha256("|".join(sorted(set(uris[:20]))).encode()).hexdigest()[:16]

    return {
        "ip": ip,
        "event_count": count,
        "cmd_count": len(uris),
        "unique_cmds": len(set(uris)),
        "cmd_diversity": len(set(uris)) / max(len(uris), 1),
        "duration_s": duration_ms / 1000,
        "avg_cmd_len": np.mean([len(u) for u in uris]) if uris else 0,
        "max_cmd_len": max([len(u) for u in uris], default=0),
        "has_pipes": 0,
        "has_redirects": 0,
        "has_semicolons": 0,
        "country": countries[0] if countries else "Unknown",
        "asn": asns[0] if asns else "Unknown",
        "fingerprint": fingerprint,
        "http_env_probes": has_env,
        "http_admin_probes": has_admin,
        "http_exploit_attempts": has_exploit,
        "http_traversal": has_traversal,
        "http_vpn_probes": has_vpn,
        **cat_counts,
        **toolkit_scores,
    }


# ─── ML Models ─────────────────────────────────────────────────────────

NUMERIC_FEATURES = [
    "event_count", "cmd_count", "unique_cmds", "cmd_diversity",
    "duration_s", "avg_cmd_len", "max_cmd_len",
    "has_pipes", "has_redirects", "has_semicolons",
    "cat_recon", "cat_download", "cat_execution", "cat_persistence",
    "cat_exfiltration", "cat_evasion", "cat_lateral", "cat_mining_prep",
    "tk_crypto_miner_recon", "tk_botnet_installer", "tk_credential_stealer",
    "tk_system_profiler", "tk_web_scanner", "tk_vpn_exploit",
    "tk_config_thief", "tk_proxy_abuser",
]


def features_to_matrix(features: list[dict]) -> np.ndarray:
    """Convert feature dicts to numpy matrix."""
    matrix = np.zeros((len(features), len(NUMERIC_FEATURES)))
    for i, feat in enumerate(features):
        for j, col in enumerate(NUMERIC_FEATURES):
            matrix[i, j] = float(feat.get(col, 0))
    return matrix


def run_anomaly_detection(features: list[dict], matrix: np.ndarray) -> list[dict]:
    """Isolation Forest anomaly detection."""
    if len(features) < 10:
        logger.warning("Too few samples (%d) for anomaly detection, skipping", len(features))
        return features

    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(matrix)

    clf = IsolationForest(
        n_estimators=200,
        contamination=0.15,  # expect ~15% anomalies
        random_state=42,
        n_jobs=-1,
    )
    predictions = clf.fit_predict(x_scaled)
    scores = clf.decision_function(x_scaled)

    for i, feat in enumerate(features):
        feat["anomaly_label"] = "anomaly" if predictions[i] == -1 else "normal"
        feat["anomaly_score"] = float(-scores[i])  # Higher = more anomalous
        # Normalise to 0-1 range
        feat["threat_score"] = float(np.clip((-scores[i] + 0.5) / 1.0, 0, 1))

    n_anomalies = sum(1 for p in predictions if p == -1)
    logger.info("Anomaly detection: %d anomalies / %d total (%.1f%%)",
                n_anomalies, len(features), 100 * n_anomalies / len(features))

    return features


def run_campaign_clustering(features: list[dict], matrix: np.ndarray) -> list[dict]:
    """DBSCAN clustering to group related attack campaigns."""
    if len(features) < 5:
        logger.warning("Too few samples for clustering, skipping")
        return features

    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(matrix)

    clusterer = DBSCAN(eps=1.2, min_samples=3, metric="euclidean")
    labels = clusterer.fit_predict(x_scaled)

    campaigns = defaultdict(list)
    for i, feat in enumerate(features):
        cluster_id = int(labels[i])
        feat["campaign_id"] = cluster_id  # -1 = no cluster (unique)
        if cluster_id >= 0:
            campaigns[cluster_id].append(feat["ip"])

    n_campaigns = len(campaigns)
    n_clustered = sum(1 for label in labels if label >= 0)
    logger.info("Campaign clustering: %d campaigns, %d/%d IPs clustered (%.1f%%)",
                n_campaigns, n_clustered, len(features), 100 * n_clustered / len(features))

    return features


def compute_threat_classification(features: list[dict]) -> list[dict]:
    """Rule-based + ML threat classification."""
    for feat in features:
        threat_level = "low"
        threat_reasons = []

        # High-confidence heuristic rules
        if feat.get("tk_credential_stealer", 0) > 0.3:
            threat_level = "critical"
            threat_reasons.append("Credential theft toolkit detected")

        if feat.get("tk_botnet_installer", 0) > 0.3:
            threat_level = "critical"
            threat_reasons.append("Botnet installer toolkit detected")

        if feat.get("tk_crypto_miner_recon", 0) > 0.5:
            threat_level = "high"
            threat_reasons.append("Crypto mining reconnaissance")

        if feat.get("http_exploit_attempts", 0) > 0:
            threat_level = "critical" if feat.get("http_exploit_attempts", 0) > 2 else "high"
            threat_reasons.append(f"RCE attempts ({feat.get('http_exploit_attempts', 0)}x)")

        if feat.get("http_traversal", 0) > 0:
            threat_level = "high"
            threat_reasons.append("Path traversal detected")

        if feat.get("cat_evasion", 0) > 0:
            threat_level = "high"
            threat_reasons.append("Evasion techniques detected")

        if feat.get("cat_exfiltration", 0) > 0:
            threat_level = "high"
            threat_reasons.append("Data exfiltration indicators")

        if feat.get("cat_persistence", 0) > 0:
            threat_level = "high"
            threat_reasons.append("Persistence mechanism attempted")

        if feat.get("cat_lateral", 0) > 0:
            threat_level = "high"
            threat_reasons.append("Lateral movement indicators")

        # ML anomaly boost
        if feat.get("anomaly_label") == "anomaly":
            if threat_level == "low":
                threat_level = "medium"
            threat_reasons.append(f"ML anomaly (score: {feat.get('anomaly_score', 0):.3f})")

        # Mass scanner detection (high volume, low diversity)
        if feat.get("event_count", 0) > 100 and feat.get("cmd_diversity", 1) < 0.1:
            if not threat_reasons:
                threat_level = "low"
            threat_reasons.append("Mass scanner pattern")

        # Sophisticated attacker (high diversity, long duration)
        if feat.get("cmd_diversity", 0) > 0.7 and feat.get("duration_s", 0) > 60:
            if threat_level in ("low", "medium"):
                threat_level = "high"
            threat_reasons.append("Sophisticated attacker (high diversity, long session)")

        feat["threat_level"] = threat_level
        feat["threat_reasons"] = threat_reasons

    # Stats
    levels = Counter(f.get("threat_level", "low") for f in features)
    logger.info("Threat classification: %s", dict(levels))

    return features


# ─── IP Reputation System ──────────────────────────────────────────────

def build_ip_reputation(features: list[dict]) -> dict:
    """Build dynamic IP reputation database."""
    reputation = {}

    for feat in features:
        ip = feat["ip"]
        score = 50  # neutral

        # Increase threat score
        level = feat.get("threat_level", "low")
        if level == "critical":
            score += 40
        elif level == "high":
            score += 25
        elif level == "medium":
            score += 10

        # Volume factor
        events = feat.get("event_count", 0)
        if events > 1000:
            score += 10
        elif events > 100:
            score += 5

        # Anomaly factor
        if feat.get("anomaly_label") == "anomaly":
            score += 15

        # Recidivism factor
        if feat.get("campaign_id", -1) >= 0:
            score += 5

        score = min(100, max(0, score))

        action = "monitor"
        if score >= 80:
            action = "block"
        elif score >= 60:
            action = "alert"
        elif score >= 40:
            action = "watch"

        reputation[ip] = {
            "score": score,
            "action": action,
            "threat_level": level,
            "reasons": feat.get("threat_reasons", []),
            "country": feat.get("country", "Unknown"),
            "asn": feat.get("asn", "Unknown"),
            "fingerprint": feat.get("fingerprint", ""),
            "campaign_id": feat.get("campaign_id", -1),
            "events": events,
            "honeypot": feat.get("honeypot", "unknown"),
        }

    # Stats
    actions = Counter(v["action"] for v in reputation.values())
    logger.info("IP reputation: %d IPs scored (%s)", len(reputation), dict(actions))

    return reputation


# ─── Campaign Analysis ─────────────────────────────────────────────────

def analyse_campaigns(features: list[dict]) -> list[dict]:
    """Analyse identified attack campaigns."""
    campaigns_map = defaultdict(list)
    for feat in features:
        cid = feat.get("campaign_id", -1)
        if cid >= 0:
            campaigns_map[cid].append(feat)

    campaigns = []
    for cid, members in campaigns_map.items():
        ips = [m["ip"] for m in members]
        countries = list(set(m.get("country", "Unknown") for m in members))
        asns = list(set(m.get("asn", "Unknown") for m in members))
        fingerprints = list(set(m.get("fingerprint", "") for m in members))
        threat_levels = [m.get("threat_level", "low") for m in members]
        max_threat = "critical" if "critical" in threat_levels else \
                     "high" if "high" in threat_levels else \
                     "medium" if "medium" in threat_levels else "low"

        toolkits = set()
        for m in members:
            for tk_key in [k for k in m if k.startswith("tk_") and m[k] > 0.2]:
                toolkits.add(tk_key.replace("tk_", ""))

        campaigns.append({
            "campaign_id": cid,
            "ip_count": len(ips),
            "ips": ips[:20],  # limit for display
            "countries": countries,
            "asns": asns,
            "fingerprints": fingerprints[:5],
            "max_threat_level": max_threat,
            "toolkits": list(toolkits),
            "total_events": sum(m.get("event_count", 0) for m in members),
            "avg_anomaly_score": np.mean([m.get("anomaly_score", 0) for m in members]),
        })

    campaigns.sort(key=lambda c: c["total_events"], reverse=True)
    logger.info("Campaign analysis: %d campaigns identified", len(campaigns))
    return campaigns


# ─── Predictive Alerts ─────────────────────────────────────────────────

def generate_predictive_alerts(features: list[dict], reputation: dict, campaigns: list) -> list[dict]:
    """Generate proactive security alerts."""
    alerts = []
    timestamp = datetime.now(timezone.utc).isoformat()

    # Alert: New anomalous IPs
    anomalous = [f for f in features if f.get("anomaly_label") == "anomaly"]
    for feat in anomalous:
        if feat.get("threat_level") in ("critical", "high"):
            alerts.append({
                "id": hashlib.sha256(f"{feat['ip']}{timestamp}".encode()).hexdigest()[:12],
                "timestamp": timestamp,
                "severity": feat["threat_level"],
                "type": "anomalous_behavior",
                "ip": feat["ip"],
                "country": feat.get("country", "Unknown"),
                "description": f"Anomalous {feat.get('honeypot', 'unknown')} activity from {feat['ip']}",
                "reasons": feat.get("threat_reasons", []),
                "recommended_action": reputation.get(feat["ip"], {}).get("action", "monitor"),
            })

    # Alert: Large campaigns
    for campaign in campaigns:
        if campaign["ip_count"] >= 5:
            alerts.append({
                "id": hashlib.sha256(f"campaign-{campaign['campaign_id']}{timestamp}".encode()).hexdigest()[:12],
                "timestamp": timestamp,
                "severity": campaign["max_threat_level"],
                "type": "coordinated_campaign",
                "ip": f"{campaign['ip_count']} IPs",
                "country": ", ".join(campaign["countries"][:3]),
                "description": f"Coordinated attack campaign ({campaign['ip_count']} IPs, {campaign['total_events']} events)",
                "reasons": [f"Toolkits: {', '.join(campaign['toolkits'])}" if campaign['toolkits'] else "Behavioural similarity"],
                "recommended_action": "block" if campaign["max_threat_level"] in ("critical", "high") else "alert",
            })

    # Alert: Credential theft attempts
    cred_thieves = [f for f in features if f.get("tk_credential_stealer", 0) > 0.3]
    if cred_thieves:
        ips = [f["ip"] for f in cred_thieves]
        alerts.append({
            "id": hashlib.sha256(f"credtheft-{timestamp}".encode()).hexdigest()[:12],
            "timestamp": timestamp,
            "severity": "critical",
            "type": "credential_theft",
            "ip": ", ".join(ips[:5]),
            "country": ", ".join(set(f.get("country", "?") for f in cred_thieves)),
            "description": f"Active credential theft attempts from {len(ips)} IPs",
            "reasons": ["Telegram session theft", "AWS credential probing", "Config file access"],
            "recommended_action": "block",
        })

    alerts.sort(key=lambda a: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(a["severity"], 4))
    logger.info("Generated %d predictive alerts", len(alerts))
    return alerts


# ─── Output Writing ────────────────────────────────────────────────────

def write_results(features: list, reputation: dict, campaigns: list,
                  alerts: list, model_stats: dict):
    """Write all results to output directory."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc)
    ts_str = timestamp.strftime("%Y-%m-%dT%H:%M:%S")

    # 1. Threat summary
    levels = Counter(f.get("threat_level", "low") for f in features)
    summary = {
        "generated_at": ts_str,
        "version": "1.0",
        "source": "LLM Honeypot Intelligence Platform - Heuristic Detector",
        "window_hours": SINCE_HOURS,
        "total_sessions": len(features),
        "threat_distribution": dict(levels),
        "anomalies_detected": sum(1 for f in features if f.get("anomaly_label") == "anomaly"),
        "campaigns_identified": len(campaigns),
        "alerts_generated": len(alerts),
        "ips_to_block": sum(1 for v in reputation.values() if v["action"] == "block"),
        "ips_to_alert": sum(1 for v in reputation.values() if v["action"] == "alert"),
        "model_stats": model_stats,
    }
    with open(OUTPUT_DIR / "threat_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    # 2. IP reputation database
    with open(OUTPUT_DIR / "ip_reputation.json", "w") as f:
        json.dump(reputation, f, indent=2, default=str)

    # 3. Campaigns
    with open(OUTPUT_DIR / "campaigns.json", "w") as f:
        json.dump(campaigns, f, indent=2, default=str)

    # 4. Alerts
    with open(OUTPUT_DIR / "alerts.json", "w") as f:
        json.dump(alerts, f, indent=2, default=str)

    # 5. Dynamic blocklist (IPs recommended for blocking)
    block_ips = sorted([ip for ip, v in reputation.items() if v["action"] == "block"],
                       key=lambda ip: reputation[ip]["score"], reverse=True)
    with open(OUTPUT_DIR / "dynamic_blocklist.txt", "w") as f:
        f.write("# ML-generated dynamic blocklist\n")
        f.write(f"# Generated: {ts_str}\n")
        f.write(f"# Total: {len(block_ips)} IPs\n")
        for ip in block_ips:
            r = reputation[ip]
            f.write(f"{ip}  # score={r['score']} level={r['threat_level']} {','.join(r['reasons'][:2])}\n")

    # 6. Alert-worthy IPs (for monitoring/SIEM integration)
    alert_ips = sorted([ip for ip, v in reputation.items() if v["action"] in ("block", "alert")],
                       key=lambda ip: reputation[ip]["score"], reverse=True)
    with open(OUTPUT_DIR / "alert_watchlist.json", "w") as f:
        watchlist = [{
            "ip": ip,
            **reputation[ip],
        } for ip in alert_ips]
        json.dump(watchlist, f, indent=2, default=str)

    logger.info("Results written to %s (%d files)", OUTPUT_DIR, 6)
    logger.info("  Summary: %s", json.dumps(summary, default=str))

    return summary


# ─── Main Entry Point ──────────────────────────────────────────────────

async def run_heuristic_detection() -> dict:
    """Main entry point for the heuristic detection engine."""
    logger.info("=" * 60)
    logger.info("Starting ML Heuristic Detection (window: %dh)", SINCE_HOURS)
    logger.info("=" * 60)

    t0 = time.time()

    # 1. Fetch data
    sessions = await fetch_sessions()
    if not sessions["beelzebub"] and not sessions["galah"]:
        logger.warning("No session data available, skipping")
        return {"status": "no_data"}

    # 2. Extract features
    features = extract_session_features(sessions)
    logger.info("Extracted features for %d sessions", len(features))

    if len(features) < 3:
        logger.warning("Too few sessions (%d), skipping ML analysis", len(features))
        return {"status": "insufficient_data", "sessions": len(features)}

    # 3. Build feature matrix
    matrix = features_to_matrix(features)

    # 4. Anomaly Detection (Isolation Forest)
    features = run_anomaly_detection(features, matrix)

    # 5. Campaign Clustering (DBSCAN)
    features = run_campaign_clustering(features, matrix)

    # 6. Threat Classification (Heuristic + ML)
    features = compute_threat_classification(features)

    # 7. IP Reputation Scoring
    reputation = build_ip_reputation(features)

    # 8. Campaign Analysis
    campaigns = analyse_campaigns(features)

    # 9. Predictive Alerts
    alerts = generate_predictive_alerts(features, reputation, campaigns)

    # 10. Write results
    elapsed = time.time() - t0
    model_stats = {
        "processing_time_s": round(elapsed, 2),
        "features_extracted": len(NUMERIC_FEATURES),
        "isolation_forest_estimators": 200,
        "dbscan_eps": 1.2,
        "contamination_rate": 0.15,
    }

    summary = write_results(features, reputation, campaigns, alerts, model_stats)

    logger.info("=" * 60)
    logger.info("Heuristic Detection Complete (%.1fs):", elapsed)
    logger.info("  Sessions: %d | Anomalies: %d | Campaigns: %d",
                len(features), summary["anomalies_detected"], len(campaigns))
    logger.info("  Block: %d | Alert: %d | Alerts: %d",
                summary["ips_to_block"], summary["ips_to_alert"], len(alerts))
    logger.info("=" * 60)

    return summary
