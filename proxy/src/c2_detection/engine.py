"""
C2 Detection Engine - Main orchestrator.

Runs periodic analysis cycles on Suricata data in Elasticsearch,
scoring source IPs for C2 likelihood across multiple detection layers.
"""

import asyncio
import json
import logging
import math
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone

import httpx

logger = logging.getLogger("c2-detection")

PRIVATE_IP_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "0.", "169.254.",
    "fe80:", "fc00:", "fd00:", "::1",
)


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    return any(ip.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES)


ES_URL = os.environ.get("ES_URL", "https://localhost:64297/es")
ES_USER = os.environ.get("ES_USER", "")
ES_PASS = os.environ.get("ES_PASS", "")
C2_INDEX = "honeypot-c2-indicators"
INTERVAL = int(os.environ.get("C2_INTERVAL", "300"))
WINDOW_MINUTES = int(os.environ.get("C2_WINDOW", "60"))


def _auth():
    return (ES_USER, ES_PASS) if ES_USER else None


async def _es_search(client: httpx.AsyncClient, index: str, body: dict) -> dict:
    """Execute an ES search."""
    resp = await client.post(
        f"{ES_URL}/{index}/_search",
        json=body,
        headers={"Content-Type": "application/json"},
    )
    if resp.status_code != 200:
        logger.warning("ES search failed on %s: %s", index, resp.text[:200])
        return {"hits": {"hits": [], "total": {"value": 0}}}
    return resp.json()


# ──────────────────────────────────────────────────────────────────────
# Layer 1: Beaconing Detection
# ──────────────────────────────────────────────────────────────────────

async def detect_beaconing(client: httpx.AsyncClient, window_min: int) -> list[dict]:
    """
    Detect beaconing patterns by analyzing flow inter-arrival times.

    C2 beacons have regular callback intervals (e.g. every 60s ± jitter).
    We detect this by:
    1. Grouping flows by src_ip
    2. Calculating inter-arrival times between connections
    3. Computing interval regularity (low std-dev = beaconing)
    4. Scoring based on regularity, count, and duration
    """
    query = {
        "size": 0,
        "query": {"bool": {"must": [
            {"term": {"type.keyword": "Suricata"}},
            {"term": {"event_type.keyword": "flow"}},
            {"range": {"@timestamp": {"gte": f"now-{window_min}m"}}},
        ]}},
        "aggs": {
            "by_src": {
                "terms": {"field": "src_ip.keyword", "size": 200, "min_doc_count": 5},
                "aggs": {
                    "timestamps": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "10s",
                            "min_doc_count": 1,
                        }
                    },
                    "dest_ips": {"cardinality": {"field": "dest_ip.keyword"}},
                    "dest_ports": {"cardinality": {"field": "dest_port"}},
                    "protocols": {"terms": {"field": "proto.keyword", "size": 5}},
                    "total_bytes_in": {"sum": {"field": "flow.bytes_toclient"}},
                    "total_bytes_out": {"sum": {"field": "flow.bytes_toserver"}},
                    "avg_duration": {"avg": {"field": "flow.age"}},
                }
            }
        }
    }

    data = await _es_search(client, "logstash-*", query)
    results = []

    for bucket in data.get("aggregations", {}).get("by_src", {}).get("buckets", []):
        src_ip = bucket["key"]
        if _is_private_ip(src_ip):
            continue
        flow_count = bucket["doc_count"]
        dest_count = bucket["dest_ips"]["value"]
        port_count = bucket["dest_ports"]["value"]

        # Extract timestamps from histogram buckets
        ts_buckets = bucket["timestamps"]["buckets"]
        if len(ts_buckets) < 3:
            continue

        timestamps = [b["key"] for b in ts_buckets if b["doc_count"] > 0]
        if len(timestamps) < 3:
            continue

        # Calculate inter-arrival times (in seconds)
        intervals = []
        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i - 1]) / 1000.0
            if 0 < delta < 600:  # Ignore gaps > 10min
                intervals.append(delta)

        if len(intervals) < 2:
            continue

        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)

        # Coefficient of variation (lower = more regular = more suspicious)
        cv = std_dev / mean_interval if mean_interval > 0 else 999

        # Beaconing score: low CV + many connections + few destinations = high score
        regularity_score = max(0, 1.0 - cv) * 100
        volume_score = min(flow_count / 20.0, 1.0) * 30
        focus_penalty = min(dest_count / 5.0, 1.0) * 20  # Many dests = less suspicious

        beacon_score = regularity_score + volume_score - focus_penalty
        beacon_score = max(0, min(100, beacon_score))

        if beacon_score < 20:
            continue

        # Determine primary protocol
        protos = bucket["protocols"]["buckets"]
        primary_proto = protos[0]["key"] if protos else "unknown"

        bytes_in = bucket["total_bytes_in"]["value"] or 0
        bytes_out = bucket["total_bytes_out"]["value"] or 0

        results.append({
            "src_ip": src_ip,
            "detection_type": "beaconing",
            "beacon_score": round(beacon_score, 1),
            "mean_interval_sec": round(mean_interval, 1),
            "interval_std_dev": round(std_dev, 1),
            "coefficient_of_variation": round(cv, 3),
            "flow_count": flow_count,
            "unique_destinations": dest_count,
            "unique_ports": port_count,
            "primary_protocol": primary_proto,
            "bytes_inbound": int(bytes_in),
            "bytes_outbound": int(bytes_out),
            "byte_ratio": round(bytes_out / max(bytes_in, 1), 2),
            "avg_flow_duration_sec": round(bucket["avg_duration"]["value"] or 0, 1),
            "mitre_techniques": ["T1071", "T1573", "T1571"],
        })

    results.sort(key=lambda x: x["beacon_score"], reverse=True)
    logger.info("Beaconing: %d suspects (top score: %.1f)",
                len(results), results[0]["beacon_score"] if results else 0)
    return results


# ──────────────────────────────────────────────────────────────────────
# Layer 2: DNS Anomaly Detection
# ──────────────────────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    """Shannon entropy of a string (higher = more random = more suspicious)."""
    if not s:
        return 0.0
    freq = Counter(s.lower())
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


async def detect_dns_anomalies(client: httpx.AsyncClient, window_min: int) -> list[dict]:
    """
    Detect DNS tunneling indicators:
    - High query frequency per source
    - Long subdomain names (high entropy = encoded data)
    - Unusual record types (TXT, NULL, CNAME heavy = tunneling)
    - Large response sizes
    """
    query = {
        "size": 500,
        "query": {"bool": {"must": [
            {"term": {"type.keyword": "Suricata"}},
            {"term": {"event_type.keyword": "dns"}},
            {"range": {"@timestamp": {"gte": f"now-{window_min}m"}}},
        ]}},
        "_source": ["src_ip", "dns.query", "dns.rrtype", "dns.rdata",
                     "dns.type", "@timestamp"],
        "sort": [{"@timestamp": "desc"}],
    }

    data = await _es_search(client, "logstash-*", query)
    hits = data.get("hits", {}).get("hits", [])

    if not hits:
        logger.info("DNS anomaly: no DNS events found in window")
        return []

    # Group by source IP
    ip_data = defaultdict(lambda: {
        "queries": [], "rrtype_counts": Counter(), "timestamps": [],
        "query_lengths": [], "entropies": [], "rdata_sizes": [],
    })

    for h in hits:
        s = h["_source"]
        ip = s.get("src_ip", "")
        if not ip or _is_private_ip(ip):
            continue

        dns = s.get("dns", {}) if isinstance(s.get("dns"), dict) else {}
        query_name = dns.get("query", s.get("dns.query", ""))
        rrtype = dns.get("rrtype", s.get("dns.rrtype", ""))
        rdata = dns.get("rdata", s.get("dns.rdata", ""))

        d = ip_data[ip]
        d["queries"].append(query_name)
        d["timestamps"].append(s.get("@timestamp", ""))

        if query_name:
            d["query_lengths"].append(len(query_name))
            # Calculate entropy of the subdomain part
            parts = query_name.split(".")
            if len(parts) > 2:
                subdomain = ".".join(parts[:-2])
                d["entropies"].append(_entropy(subdomain))

        if rrtype:
            d["rrtype_counts"][rrtype] += 1

        if rdata:
            d["rdata_sizes"].append(len(str(rdata)))

    results = []
    for ip, d in ip_data.items():
        query_count = len(d["queries"])
        if query_count < 3:
            continue

        # Scoring factors
        score = 0
        indicators = []

        # Factor 1: Query frequency (>10 in window = suspicious for honeypot)
        if query_count > 10:
            score += min(query_count / 5.0, 30)
            indicators.append(f"high_query_volume({query_count})")

        # Factor 2: Average subdomain entropy (>3.5 = likely encoded)
        avg_entropy = sum(d["entropies"]) / len(d["entropies"]) if d["entropies"] else 0
        if avg_entropy > 3.5:
            score += min((avg_entropy - 3.0) * 20, 30)
            indicators.append(f"high_entropy({avg_entropy:.2f})")

        # Factor 3: Average query length (>30 chars = tunneling)
        avg_length = sum(d["query_lengths"]) / len(d["query_lengths"]) if d["query_lengths"] else 0
        if avg_length > 25:
            score += min((avg_length - 20) * 2, 25)
            indicators.append(f"long_queries(avg={avg_length:.0f})")

        # Factor 4: Unusual record types (TXT, NULL, CNAME dominant)
        total_rr = sum(d["rrtype_counts"].values())
        unusual_types = sum(d["rrtype_counts"].get(t, 0) for t in ["TXT", "NULL", "CNAME", "MX"])
        if total_rr > 0 and unusual_types / total_rr > 0.5:
            score += 20
            indicators.append(f"unusual_rrtype_ratio({unusual_types}/{total_rr})")

        # Factor 5: Large response data
        if d["rdata_sizes"]:
            avg_rdata = sum(d["rdata_sizes"]) / len(d["rdata_sizes"])
            if avg_rdata > 100:
                score += min((avg_rdata - 80) * 0.5, 15)
                indicators.append(f"large_rdata(avg={avg_rdata:.0f})")

        score = max(0, min(100, score))
        if score < 15:
            continue

        results.append({
            "src_ip": ip,
            "detection_type": "dns_tunneling",
            "dns_score": round(score, 1),
            "query_count": query_count,
            "avg_query_length": round(avg_length, 1),
            "avg_subdomain_entropy": round(avg_entropy, 2),
            "rrtype_distribution": dict(d["rrtype_counts"]),
            "indicators": indicators,
            "mitre_techniques": ["T1071.004", "T1572"],
        })

    results.sort(key=lambda x: x["dns_score"], reverse=True)
    logger.info("DNS anomaly: %d suspects (top score: %.1f)",
                len(results), results[0]["dns_score"] if results else 0)
    return results


# ──────────────────────────────────────────────────────────────────────
# Layer 3: Protocol & Traffic Anomalies
# ──────────────────────────────────────────────────────────────────────

async def detect_protocol_anomalies(client: httpx.AsyncClient, window_min: int) -> list[dict]:
    """
    Detect protocol-level anomalies indicative of covert channels:
    - ICMP with large payloads (tunneling)
    - Unusual protocol distributions per source
    - Anomalous byte ratios (C2 has asymmetric traffic)
    - Connections to non-standard ports
    """
    query = {
        "size": 0,
        "query": {"bool": {"must": [
            {"term": {"type.keyword": "Suricata"}},
            {"term": {"event_type.keyword": "flow"}},
            {"range": {"@timestamp": {"gte": f"now-{window_min}m"}}},
        ]}},
        "aggs": {
            "by_src": {
                "terms": {"field": "src_ip.keyword", "size": 100, "min_doc_count": 3},
                "aggs": {
                    "protocols": {"terms": {"field": "proto.keyword", "size": 10}},
                    "dest_ports": {
                        "terms": {"field": "dest_port", "size": 20, "order": {"_count": "desc"}}
                    },
                    "icmp_count": {
                        "filter": {"terms": {"proto.keyword": ["ICMP", "IPv6-ICMP"]}}
                    },
                    "total_bytes_in": {"sum": {"field": "flow.bytes_toclient"}},
                    "total_bytes_out": {"sum": {"field": "flow.bytes_toserver"}},
                    "avg_pkt_toclient": {"avg": {"field": "flow.pkts_toclient"}},
                    "avg_pkt_toserver": {"avg": {"field": "flow.pkts_toserver"}},
                }
            }
        }
    }

    data = await _es_search(client, "logstash-*", query)
    results = []

    for bucket in data.get("aggregations", {}).get("by_src", {}).get("buckets", []):
        src_ip = bucket["key"]
        if _is_private_ip(src_ip):
            continue
        flow_count = bucket["doc_count"]
        score = 0
        indicators = []

        # Factor 1: ICMP usage (any ICMP to honeypot is suspicious)
        icmp_count = bucket["icmp_count"]["doc_count"]
        if icmp_count > 2:
            score += min(icmp_count * 5, 30)
            indicators.append(f"icmp_traffic({icmp_count})")

        # Factor 2: Non-standard port concentration
        ports = bucket["dest_ports"]["buckets"]
        non_standard = sum(
            p["doc_count"] for p in ports
            if p["key"] not in [22, 80, 443, 53, 25, 110, 143, 993, 995,
                                 21, 23, 445, 3389, 8080, 8443, 5060, 5061]
        )
        if non_standard > 3:
            score += min(non_standard * 2, 20)
            indicators.append(f"non_standard_ports({non_standard})")

        # Factor 3: Asymmetric byte ratio (C2: small out, large in for downloads)
        bytes_in = bucket["total_bytes_in"]["value"] or 0
        bytes_out = bucket["total_bytes_out"]["value"] or 0
        if bytes_in > 0 and bytes_out > 0:
            ratio = bytes_out / bytes_in
            if ratio > 10 or ratio < 0.1:
                score += 15
                indicators.append(f"asymmetric_traffic(ratio={ratio:.2f})")

        # Factor 4: Protocol diversity (using many protocols = reconnaissance)
        proto_count = len(bucket["protocols"]["buckets"])
        if proto_count >= 3:
            score += min(proto_count * 5, 15)
            indicators.append(f"protocol_diversity({proto_count})")

        # Factor 5: Small, frequent packets (beaconing/keepalive pattern)
        avg_pkts_in = bucket["avg_pkt_toclient"]["value"] or 0
        avg_pkts_out = bucket["avg_pkt_toserver"]["value"] or 0
        if 1 <= avg_pkts_in <= 3 and 1 <= avg_pkts_out <= 3 and flow_count > 10:
            score += 15
            indicators.append("small_frequent_flows")

        score = max(0, min(100, score))
        if score < 10:
            continue

        proto_dist = {p["key"]: p["doc_count"] for p in bucket["protocols"]["buckets"]}
        port_dist = {str(p["key"]): p["doc_count"] for p in ports[:10]}

        results.append({
            "src_ip": src_ip,
            "detection_type": "protocol_anomaly",
            "anomaly_score": round(score, 1),
            "flow_count": flow_count,
            "protocol_distribution": proto_dist,
            "port_distribution": port_dist,
            "icmp_flow_count": icmp_count,
            "bytes_inbound": int(bytes_in),
            "bytes_outbound": int(bytes_out),
            "indicators": indicators,
            "mitre_techniques": ["T1095", "T1572", "T1571"],
        })

    results.sort(key=lambda x: x["anomaly_score"], reverse=True)
    logger.info("Protocol anomaly: %d suspects (top score: %.1f)",
                len(results), results[0]["anomaly_score"] if results else 0)
    return results


# ──────────────────────────────────────────────────────────────────────
# Layer 4: Suricata Alert Correlation
# ──────────────────────────────────────────────────────────────────────

async def correlate_alerts(client: httpx.AsyncClient, window_min: int) -> list[dict]:
    """
    Correlate Suricata alerts to identify multi-stage attack patterns
    and C2-related alert combinations.
    """
    query = {
        "size": 0,
        "query": {"bool": {"must": [
            {"term": {"type.keyword": "Suricata"}},
            {"term": {"event_type.keyword": "alert"}},
            {"range": {"@timestamp": {"gte": f"now-{window_min}m"}}},
        ], "must_not": [
            {"terms": {"alert.category.keyword": [
                "Generic Protocol Command Decode",
                "Not Suspicious Traffic",
            ]}},
        ]}},
        "aggs": {
            "by_src": {
                "terms": {"field": "src_ip.keyword", "size": 100, "min_doc_count": 2},
                "aggs": {
                    "categories": {
                        "terms": {"field": "alert.category.keyword", "size": 10}
                    },
                    "signatures": {
                        "terms": {"field": "alert.signature.keyword", "size": 15}
                    },
                    "severity_dist": {
                        "terms": {"field": "alert.severity", "size": 5}
                    },
                }
            }
        }
    }

    data = await _es_search(client, "logstash-*", query)
    results = []

    c2_categories = {
        "command-and-control", "trojan-activity",
        "A Network Trojan was detected",
    }
    attack_categories = {
        "Attempted Administrator Privilege Gain",
        "Successful Administrator Privilege Gain",
        "Web Application Attack",
        "Misc Attack",
    }

    for bucket in data.get("aggregations", {}).get("by_src", {}).get("buckets", []):
        src_ip = bucket["key"]
        if _is_private_ip(src_ip):
            continue
        alert_count = bucket["doc_count"]
        score = 0
        indicators = []

        categories = {c["key"]: c["doc_count"] for c in bucket["categories"]["buckets"]}
        signatures = {s["key"]: s["doc_count"] for s in bucket["signatures"]["buckets"]}

        # C2-specific alerts
        c2_alerts = sum(categories.get(c, 0) for c in c2_categories)
        if c2_alerts > 0:
            score += min(c2_alerts * 10, 40)
            indicators.append(f"c2_alerts({c2_alerts})")

        # Attack-related alerts (may indicate post-exploitation)
        attack_alerts = sum(categories.get(c, 0) for c in attack_categories)
        if attack_alerts > 0:
            score += min(attack_alerts * 5, 25)
            indicators.append(f"attack_alerts({attack_alerts})")

        # Alert diversity (many categories from one IP = advanced attacker)
        if len(categories) >= 3:
            score += min(len(categories) * 5, 20)
            indicators.append(f"alert_diversity({len(categories)})")

        # Severity weighting
        sev = {s["key"]: s["doc_count"] for s in bucket["severity_dist"]["buckets"]}
        high_sev = sev.get(1, 0) + sev.get(2, 0)  # Severity 1 and 2
        if high_sev > 0:
            score += min(high_sev * 3, 15)
            indicators.append(f"high_severity_alerts({high_sev})")

        score = max(0, min(100, score))
        if score < 10:
            continue

        results.append({
            "src_ip": src_ip,
            "detection_type": "alert_correlation",
            "correlation_score": round(score, 1),
            "alert_count": alert_count,
            "alert_categories": categories,
            "top_signatures": dict(list(signatures.items())[:5]),
            "indicators": indicators,
            "mitre_techniques": ["T1071", "T1059", "T1190"],
        })

    results.sort(key=lambda x: x["correlation_score"], reverse=True)
    logger.info("Alert correlation: %d suspects (top score: %.1f)",
                len(results), results[0]["correlation_score"] if results else 0)
    return results


# ──────────────────────────────────────────────────────────────────────
# Orchestrator: Combine all layers and push to ES
# ──────────────────────────────────────────────────────────────────────

async def _ensure_index(client: httpx.AsyncClient):
    """Create the C2 indicators index if it doesn't exist."""
    mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "src_ip": {"type": "ip"},
                "detection_type": {"type": "keyword"},
                "detection_types": {"type": "keyword"},
                "composite_score": {"type": "float"},
                "beacon_score": {"type": "float"},
                "dns_score": {"type": "float"},
                "anomaly_score": {"type": "float"},
                "correlation_score": {"type": "float"},
                "threat_level": {"type": "keyword"},
                "flow_count": {"type": "integer"},
                "alert_count": {"type": "integer"},
                "query_count": {"type": "integer"},
                "indicators": {"type": "keyword"},
                "mitre_techniques": {"type": "keyword"},
                "primary_protocol": {"type": "keyword"},
                "bytes_inbound": {"type": "long"},
                "bytes_outbound": {"type": "long"},
                "byte_ratio": {"type": "float"},
                "mean_interval_sec": {"type": "float"},
                "coefficient_of_variation": {"type": "float"},
                "avg_query_length": {"type": "float"},
                "avg_subdomain_entropy": {"type": "float"},
                "unique_destinations": {"type": "integer"},
                "unique_ports": {"type": "integer"},
                "protocol_distribution": {"type": "object", "enabled": False},
                "port_distribution": {"type": "object", "enabled": False},
                "rrtype_distribution": {"type": "object", "enabled": False},
                "alert_categories": {"type": "object", "enabled": False},
                "top_signatures": {"type": "object", "enabled": False},
            }
        }
    }
    resp = await client.put(f"{ES_URL}/{C2_INDEX}", json=mapping)
    if resp.status_code == 200:
        logger.info("Created index %s", C2_INDEX)
    elif "resource_already_exists" in (resp.text or ""):
        pass  # Already exists
    else:
        logger.debug("Index creation: %s", resp.text[:200])


def _threat_level(score: float) -> str:
    """Classify composite score into threat level.
    Thresholds calibrated for honeypot context where max realistic
    composite is ~50 (beacon 100 * 0.35 + anomaly 30 * 0.20 + alerts 40 * 0.20).
    """
    if score >= 40:
        return "critical"
    elif score >= 28:
        return "high"
    elif score >= 15:
        return "medium"
    return "low"


def _primary_detection_type(scores: dict) -> str:
    """Determine the primary detection type based on highest layer score."""
    layer_scores = [
        (scores["beacon"], "beaconing"),
        (scores["dns"], "dns_tunneling"),
        (scores["anomaly"], "protocol_anomaly"),
        (scores["correlation"], "alert_correlation"),
    ]
    layer_scores.sort(key=lambda x: x[0], reverse=True)
    # Return the highest-scoring layer, or "multi_layer" if top 2 are close
    if layer_scores[0][0] == 0:
        return "unknown"
    if len(layer_scores) > 1 and layer_scores[1][0] > 0:
        if layer_scores[1][0] / max(layer_scores[0][0], 1) > 0.7:
            return "multi_layer"
    return layer_scores[0][1]


async def run_detection_cycle():
    """Run one complete C2 detection cycle across all layers."""
    logger.info("Starting C2 detection cycle (window: %dm)", WINDOW_MINUTES)

    auth = _auth()
    async with httpx.AsyncClient(timeout=30.0, verify=False, auth=auth) as client:
        await _ensure_index(client)

        # Run all detectors in parallel
        beacon_results, dns_results, proto_results, alert_results = await asyncio.gather(
            detect_beaconing(client, WINDOW_MINUTES),
            detect_dns_anomalies(client, WINDOW_MINUTES),
            detect_protocol_anomalies(client, WINDOW_MINUTES),
            correlate_alerts(client, WINDOW_MINUTES),
        )

        # Merge results by IP for composite scoring
        ip_scores = defaultdict(lambda: {
            "beacon": 0, "dns": 0, "anomaly": 0, "correlation": 0,
            "data": {}, "all_indicators": [], "all_mitre": set(),
        })

        for r in beacon_results:
            ip = r["src_ip"]
            ip_scores[ip]["beacon"] = r["beacon_score"]
            ip_scores[ip]["data"].update(r)
            ip_scores[ip]["all_indicators"].extend(
                r.get("indicators", [f"beacon_score={r['beacon_score']}"]))
            ip_scores[ip]["all_mitre"].update(r.get("mitre_techniques", []))

        for r in dns_results:
            ip = r["src_ip"]
            ip_scores[ip]["dns"] = r["dns_score"]
            ip_scores[ip]["data"].update(r)
            ip_scores[ip]["all_indicators"].extend(r.get("indicators", []))
            ip_scores[ip]["all_mitre"].update(r.get("mitre_techniques", []))

        for r in proto_results:
            ip = r["src_ip"]
            ip_scores[ip]["anomaly"] = r["anomaly_score"]
            ip_scores[ip]["data"].update(r)
            ip_scores[ip]["all_indicators"].extend(r.get("indicators", []))
            ip_scores[ip]["all_mitre"].update(r.get("mitre_techniques", []))

        for r in alert_results:
            ip = r["src_ip"]
            ip_scores[ip]["correlation"] = r["correlation_score"]
            ip_scores[ip]["data"].update(r)
            ip_scores[ip]["all_indicators"].extend(r.get("indicators", []))
            ip_scores[ip]["all_mitre"].update(r.get("mitre_techniques", []))

        # Build and push composite documents
        now = datetime.now(timezone.utc).isoformat()
        bulk_body = ""
        count = 0

        for ip, scores in ip_scores.items():
            # Weighted composite score
            composite = (
                scores["beacon"] * 0.35
                + scores["dns"] * 0.25
                + scores["anomaly"] * 0.20
                + scores["correlation"] * 0.20
            )

            if composite < 5:
                continue

            # Determine detection types
            active_layers = []
            if scores["beacon"] > 0:
                active_layers.append("beaconing")
            if scores["dns"] > 0:
                active_layers.append("dns_tunneling")
            if scores["anomaly"] > 0:
                active_layers.append("protocol_anomaly")
            if scores["correlation"] > 0:
                active_layers.append("alert_correlation")

            doc = {
                "@timestamp": now,
                "src_ip": ip,
                "composite_score": round(composite, 1),
                "beacon_score": round(scores["beacon"], 1),
                "dns_score": round(scores["dns"], 1),
                "anomaly_score": round(scores["anomaly"], 1),
                "correlation_score": round(scores["correlation"], 1),
                "threat_level": _threat_level(composite),
                "detection_type": _primary_detection_type(scores),
                "detection_types": active_layers,
                "indicators": list(set(scores["all_indicators"]))[:20],
                "mitre_techniques": sorted(scores["all_mitre"]),
            }

            # Merge in details from individual detectors
            for key in ["flow_count", "alert_count", "query_count",
                        "primary_protocol", "bytes_inbound", "bytes_outbound",
                        "byte_ratio", "mean_interval_sec", "coefficient_of_variation",
                        "avg_query_length", "avg_subdomain_entropy",
                        "unique_destinations", "unique_ports",
                        "protocol_distribution", "port_distribution",
                        "rrtype_distribution", "alert_categories", "top_signatures"]:
                if key in scores["data"]:
                    doc[key] = scores["data"][key]

            bulk_body += json.dumps({"index": {"_index": C2_INDEX}}) + "\n"
            bulk_body += json.dumps(doc) + "\n"
            count += 1

        if bulk_body:
            resp = await client.post(
                f"{ES_URL}/_bulk",
                content=bulk_body,
                headers={"Content-Type": "application/x-ndjson"},
            )
            if resp.status_code in (200, 201):
                errs = resp.json().get("errors", False)
                if errs:
                    logger.warning("C2 ES bulk push had errors: %d items", count)
                else:
                    logger.info("C2 indicators pushed: %d documents", count)
            else:
                logger.warning("C2 ES bulk failed: %s", resp.text[:200])
        else:
            logger.info("C2 detection: no indicators above threshold")

    logger.info("C2 detection cycle complete: %d IPs flagged", count)
    return count


async def run_loop():
    """Run detection cycles in a loop."""
    while True:
        try:
            await run_detection_cycle()
        except Exception as e:
            logger.error("C2 detection cycle failed: %s", e, exc_info=True)
        await asyncio.sleep(INTERVAL)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    asyncio.run(run_detection_cycle())
