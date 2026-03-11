"""
Automated Security Rule Generator v2

Queries Elasticsearch for honeypot attack data and generates:
- Sigma Rules (SIEM-vendor-agnostic)
- YARA Rules (malware/payload detection)
- Suricata Rules (IDS/IPS)
- Firewall Blocklists (iptables/nftables/plain)
- IOC Lists (IPs, domains, hashes, URLs)
- Threat Intelligence Report (Markdown)
- STIX 2.1 Bundle (machine-readable threat intel)

v2 improvements:
- Command normalisation: breaks multi-line scripts into atomic sub-commands
- Automatic MITRE ATT&CK mapping per command pattern
- GeoIP / ASN enrichment from Elasticsearch
- IOC extraction from payloads (URLs, domains, hashes, IPs)
- Threat Intelligence Report with executive summary
- STIX 2.1 bundle for automated sharing
- Proper Sigma/YARA/Suricata syntax (no oversized patterns)
"""

import hashlib
import json
import logging
import os
import re
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger("ollama-proxy.rule_generator")

ES_URL = os.environ.get("ES_URL", "https://localhost:64297/es")
ES_USER = os.environ.get("ES_USER", "")
ES_PASS = os.environ.get("ES_PASS", "")
RULES_DIR = Path(os.environ.get("RULES_DIR", "/data/ollama-proxy/generated-rules"))
SINCE_HOURS = int(os.environ.get("RULEGEN_SINCE_HOURS", "24"))

MIN_HITS_FOR_BLOCKLIST = 3
MIN_HITS_FOR_RULE = 2
MIN_UNIQUE_IPS_FOR_SIGMA = 1

# ─── MITRE ATT&CK Mapping ────────────────────────────────────────────

MITRE_MAP = {
    # Discovery
    "uname":        ("T1082", "System Information Discovery", "discovery"),
    "hostname":     ("T1082", "System Information Discovery", "discovery"),
    "arch":         ("T1082", "System Information Discovery", "discovery"),
    "lscpu":        ("T1082", "System Information Discovery", "discovery"),
    "dmidecode":    ("T1082", "System Information Discovery", "discovery"),
    "cat /proc":    ("T1082", "System Information Discovery", "discovery"),
    "nproc":        ("T1082", "System Information Discovery", "discovery"),
    "/proc/cpuinfo":("T1082", "System Information Discovery", "discovery"),
    "/proc/uptime": ("T1082", "System Information Discovery", "discovery"),
    "uptime":       ("T1082", "System Information Discovery", "discovery"),
    "ifconfig":     ("T1016", "System Network Configuration Discovery", "discovery"),
    "ip addr":      ("T1016", "System Network Configuration Discovery", "discovery"),
    "ip route":     ("T1016", "System Network Configuration Discovery", "discovery"),
    "whoami":       ("T1033", "System Owner/User Discovery", "discovery"),
    "id ":          ("T1033", "System Owner/User Discovery", "discovery"),
    "last":         ("T1033", "System Owner/User Discovery", "discovery"),
    "w ":           ("T1033", "System Owner/User Discovery", "discovery"),
    "ps ":          ("T1057", "Process Discovery", "discovery"),
    "ps -":         ("T1057", "Process Discovery", "discovery"),
    "lspci":        ("T1082", "System Information Discovery", "discovery"),
    "lsmod":        ("T1082", "System Information Discovery", "discovery"),
    "nvidia":       ("T1082", "System Information Discovery", "discovery"),
    "gpu":          ("T1082", "System Information Discovery", "discovery"),
    "cat --help":   ("T1082", "System Information Discovery", "discovery"),
    "ls --help":    ("T1082", "System Information Discovery", "discovery"),

    # Credential Access
    "/etc/shadow":  ("T1552.001", "Credentials In Files", "credential_access"),
    "/etc/passwd":  ("T1552.001", "Credentials In Files", "credential_access"),
    ".ssh":         ("T1552.004", "Private Keys", "credential_access"),
    "authorized_keys": ("T1552.004", "Private Keys", "credential_access"),
    "wallet":       ("T1552.001", "Credentials In Files", "credential_access"),
    "metamask":     ("T1552.001", "Credentials In Files", "credential_access"),
    ".aws":         ("T1552.001", "Credentials In Files", "credential_access"),
    "token":        ("T1528", "Steal Application Access Token", "credential_access"),

    # Collection
    "telegram":     ("T1005", "Data from Local System", "collection"),
    "TelegramDesktop": ("T1005", "Data from Local System", "collection"),
    "sms":          ("T1005", "Data from Local System", "collection"),
    "ttyGSM":       ("T1005", "Data from Local System", "collection"),
    "ttyUSB":       ("T1005", "Data from Local System", "collection"),
    "modem":        ("T1005", "Data from Local System", "collection"),
    "locate ":      ("T1005", "Data from Local System", "collection"),

    # Execution / Resource Hijacking
    "miner":        ("T1496", "Resource Hijacking", "impact"),
    "xmrig":        ("T1496", "Resource Hijacking", "impact"),
    "Miner":        ("T1496", "Resource Hijacking", "impact"),
    "hashrate":     ("T1496", "Resource Hijacking", "impact"),
    "nicehash":     ("T1496", "Resource Hijacking", "impact"),

    # Persistence
    "crontab":      ("T1053.003", "Cron", "persistence"),
    "rc.local":     ("T1037.004", "RC Scripts", "persistence"),
    "systemctl":    ("T1543.002", "Systemd Service", "persistence"),
    "chmod +x":     ("T1222.002", "Linux File Permissions Modification", "defense_evasion"),
    "chattr":       ("T1222.002", "Linux File Permissions Modification", "defense_evasion"),

    # Command and Control / Lateral Movement
    "wget ":        ("T1105", "Ingress Tool Transfer", "command_and_control"),
    "curl ":        ("T1105", "Ingress Tool Transfer", "command_and_control"),
    "curl http":    ("T1105", "Ingress Tool Transfer", "command_and_control"),
    "tftp":         ("T1105", "Ingress Tool Transfer", "command_and_control"),
    "scp ":         ("T1105", "Ingress Tool Transfer", "command_and_control"),
    "/tmp/":        ("T1059.004", "Unix Shell", "execution"),
    "chmod 777":    ("T1222.002", "Linux File Permissions Modification", "defense_evasion"),
    "echo ":        ("T1059.004", "Unix Shell", "execution"),

    # Initial Access (HTTP)
    ".env":         ("T1190", "Exploit Public-Facing Application", "initial_access"),
    "wp-config":    ("T1190", "Exploit Public-Facing Application", "initial_access"),
    ".git":         ("T1190", "Exploit Public-Facing Application", "initial_access"),
    "jndi":         ("T1190", "Exploit Public-Facing Application", "initial_access"),
    "log4j":        ("T1190", "Exploit Public-Facing Application", "initial_access"),
    "shell":        ("T1059", "Command and Scripting Interpreter", "execution"),
    "/cgi-bin/":    ("T1190", "Exploit Public-Facing Application", "initial_access"),
    "phpinfo":      ("T1082", "System Information Discovery", "discovery"),
    "/ip cloud":    ("T1082", "System Information Discovery", "discovery"),
}

# Known mass-scanner prefixes
KNOWN_SCANNER_PREFIXES = [
    "71.6.135.", "71.6.146.", "71.6.147.",
    "162.142.125.", "167.94.138.", "167.94.145.", "167.94.146.",
    "198.235.24.", "193.163.125.", "205.210.31.",
    "74.82.47.", "184.105.",
    "66.240.192.", "66.240.205.", "66.240.219.",
    "80.82.77.", "80.82.78.", "185.142.236.",
    "198.20.69.", "198.20.70.", "198.20.87.",
]


# ─── Command Normalisation ───────────────────────────────────────────

def normalise_commands(raw_commands: list[dict]) -> list[dict]:
    """
    Break multi-line scripts into atomic sub-commands.
    Each returned dict has: cmd, ip, mitre (list), category
    """
    result = []
    for entry in raw_commands:
        raw = entry.get("cmd", "").strip()
        ip = entry.get("ip", "")
        if not raw:
            continue

        # Split multi-line scripts into individual commands
        lines = raw.replace(";", "\n").split("\n")
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Skip pure variable assignments with subshells
            # but extract the actual commands inside $( )
            subshell_cmds = re.findall(r'\$\(\s*([^)]+)\)', line)
            if subshell_cmds and line.count("=") >= 1:
                for sc in subshell_cmds:
                    # Further split on pipe and ||
                    for part in re.split(r'\s*(?:\|\||&&|\|)\s*', sc):
                        part = part.strip()
                        if len(part) >= 3 and not part.startswith("echo") and not part.startswith("awk"):
                            atom = _make_atom(part, ip)
                            if atom:
                                result.append(atom)
                continue

            # Split piped commands
            parts = re.split(r'\s*(?:\|\||&&|\|)\s*', line)
            for part in parts:
                part = part.strip()
                if len(part) >= 3:
                    atom = _make_atom(part, ip)
                    if atom:
                        result.append(atom)

    return result


def _make_atom(cmd: str, ip: str) -> Optional[dict]:
    """Create an atomic command entry with MITRE mapping."""
    cmd = cmd.strip()
    # Strip leading shell noise
    cmd = re.sub(r'^[\s()\'"]+', '', cmd)
    cmd = re.sub(r'[\s()\'"]+$', '', cmd)
    cmd = cmd.strip()

    if len(cmd) < 5:
        return None

    # Skip noise: text processors, shell fragments, redirections
    NOISE_PREFIXES = ("awk ", "sed ", "tr ", "cut ", "head ", "tail ", "sort ",
                      "wc ", "print ", "exit", "gsub", "NF{", "2>/dev/null",
                      "done", "fi", "then", "else", "for ", "do ", "while ",
                      "s/", "//", "}", "{", "||", "&&")
    if any(cmd.startswith(p) for p in NOISE_PREFIXES):
        return None

    # Skip pure regex/awk fragments, variable assignments, or punctuation
    if re.match(r'^[\$\{\}\(\)\'"\\/ +=*\-|&<>.,;:!?@#%^~`]+$', cmd):
        return None
    if re.match(r'^\w+\}\s*$', cmd):
        return None
    # Skip variable references without commands
    if re.match(r'^\$\w+', cmd) and ' ' not in cmd:
        return None
    # Skip awk/sed inline expressions
    if re.match(r'^["\']?[/\\]', cmd) and len(cmd) < 20:
        return None
    # Skip fragments that are mostly special characters (>50%)
    special = sum(1 for c in cmd if c in '{}()$"\'/\\|&<>=+*;,')
    if len(cmd) > 0 and special / len(cmd) > 0.5:
        return None

    mitre = []
    category = "unknown"
    for pattern, (tid, name, tactic) in MITRE_MAP.items():
        if pattern in cmd.lower() or pattern in cmd:
            mitre.append({"id": tid, "name": name, "tactic": tactic})
            category = tactic
    # Deduplicate
    seen = set()
    unique_mitre = []
    for m in mitre:
        if m["id"] not in seen:
            seen.add(m["id"])
            unique_mitre.append(m)
            category = m["tactic"]

    return {
        "cmd": cmd[:200],
        "ip": ip,
        "mitre": unique_mitre,
        "category": category,
    }


# ─── IOC Extraction ──────────────────────────────────────────────────

def extract_iocs(data: dict) -> dict:
    """Extract Indicators of Compromise from all attack data."""
    iocs = {
        "ipv4": Counter(),
        "urls": set(),
        "domains": set(),
        "hashes_sha256": set(),
        "hashes_md5": set(),
        "emails": set(),
        "file_paths": set(),
        "malware_urls": set(),
    }

    # IP addresses (all attackers)
    for ip, count in data["all_src_ips"].items():
        if ip and not ip.startswith("192.168.") and not ip.startswith("10."):
            iocs["ipv4"][ip] = count

    # Collect all text for pattern extraction
    all_text = ""
    for entry in data.get("normalised_commands", []):
        all_text += entry["cmd"] + "\n"

    # Also include HTTP URIs (these contain malware URLs, exploit paths, etc.)
    for entry in data.get("http_requests", []):
        uri = entry.get("uri", "")
        all_text += uri + "\n"

    # Include HTTP POST bodies
    for body in data.get("http_post_bodies", []):
        all_text += body + "\n"

    # URLs (from SSH commands AND HTTP URIs)
    for url in re.findall(r'https?://[^\s\'"<>)]+', all_text):
        url_clean = url.rstrip(".,;:)")
        iocs["urls"].add(url_clean[:500])
        # URLs that point to downloads are malware
        if any(ext in url_clean.lower() for ext in [".zip", ".exe", ".sh", ".bin",
                ".elf", ".pl", ".py", ".gz", ".tar", ".rpm", ".deb"]):
            iocs["malware_urls"].add(url_clean[:500])

    # Domains from URLs
    for url in iocs["urls"]:
        m = re.match(r'https?://([^/:]+)', url)
        if m:
            domain = m.group(1)
            # Skip IP-only domains
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                iocs["domains"].add(domain)

    # Domains from CONNECT requests (proxy abuse)
    for entry in data.get("http_requests", []):
        uri = entry.get("uri", "")
        # CONNECT targets like "google.com:443" or "api.ipify.org:443"
        m = re.match(r'^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(:\d+)?$', uri)
        if m:
            iocs["domains"].add(m.group(1))

    # SHA256 hashes
    for h in re.findall(r'\b[a-fA-F0-9]{64}\b', all_text):
        iocs["hashes_sha256"].add(h.lower())

    # MD5 hashes
    for h in re.findall(r'\b[a-fA-F0-9]{32}\b', all_text):
        if '-' not in h and h not in iocs["hashes_sha256"]:
            iocs["hashes_md5"].add(h.lower())

    # File paths (from SSH)
    for p in re.findall(r'(?:/[a-zA-Z0-9._%-]+){2,}', all_text):
        if any(k in p for k in ["/tmp/", "/var/", "/etc/", "/home/", "/root/",
                                 ".ssh", ".local", ".aws", ".env", ".git",
                                 "vendor/", "cgi-bin/", "wp-"]):
            iocs["file_paths"].add(p[:200])

    # Exploited web paths from HTTP URIs
    for entry in data.get("http_requests", []):
        uri = entry.get("uri", "")
        if uri.startswith("/") and len(uri) > 2:
            # Only interesting paths, not bare /
            if any(k in uri.lower() for k in [".env", ".aws", ".git", "config",
                    "cgi-bin", "vendor", "phpunit", "eval", "shell", "cmd",
                    "admin", "backup", "CSCOE", "webvpn", "SDK", "containers",
                    "goform", "GponForm", "think\\app", "pearcmd"]):
                iocs["file_paths"].add(uri[:200])

    # Convert sets to sorted lists for JSON serialisation
    return {k: sorted(v) if isinstance(v, set) else v for k, v in iocs.items()}


# ─── Elasticsearch Queries ───────────────────────────────────────────

async def fetch_attack_data(since_hours: int = SINCE_HOURS) -> dict:
    """Fetch all honeypot events from Elasticsearch for rule generation."""
    since = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
    auth = (ES_USER, ES_PASS) if ES_USER else None

    result = {
        "beelzebub": [],
        "galah": [],
        "all_src_ips": Counter(),
        "ssh_commands": [],
        "http_requests": [],
        "geo_countries": Counter(),
        "geo_asns": Counter(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    async with httpx.AsyncClient(timeout=30.0, verify=False, auth=auth) as client:
        # ─ Beelzebub SSH events ─
        bee_query = {
            "size": 1000,
            "query": {"bool": {"must": [
                {"term": {"type.keyword": "Beelzebub"}},
                {"exists": {"field": "input"}},
                {"range": {"@timestamp": {"gte": since}}},
            ]}},
            "_source": ["src_ip", "input", "output", "session", "@timestamp",
                        "geoip.country_name", "geoip.as_org"],
        }
        try:
            resp = await client.post(f"{ES_URL}/logstash-*/_search", json=bee_query)
            if resp.status_code == 200:
                hits = [h["_source"] for h in resp.json().get("hits", {}).get("hits", [])]
                result["beelzebub"] = hits
                for h in hits:
                    ip = h.get("src_ip", "")
                    if ip:
                        result["all_src_ips"][ip] += 1
                    cmd = h.get("input", "")
                    if cmd and len(cmd.strip()) >= 2:
                        result["ssh_commands"].append({"cmd": cmd.strip(), "ip": ip})
                    geo = h.get("geoip", {})
                    if isinstance(geo, dict):
                        c = geo.get("country_name", "")
                        a = geo.get("as_org", "")
                        if c:
                            result["geo_countries"][c] += 1
                        if a:
                            result["geo_asns"][a] += 1
                logger.info("Fetched %d Beelzebub events", len(hits))
        except Exception as e:
            logger.error("Beelzebub fetch error: %s", e)

        # ─ Galah HTTP: use AGGREGATIONS (raw docs are dominated by top IPs) ─
        # Step 1: Get ALL unique URIs + methods + IPs via aggregation
        galah_agg_query = {
            "size": 0,
            "query": {"bool": {"must": [
                {"term": {"type.keyword": "Galah"}},
                {"range": {"@timestamp": {"gte": since}}},
            ]}},
            "aggs": {
                "uris": {"terms": {"field": "request.requestURI.keyword", "size": 200}},
                "methods": {"terms": {"field": "request.method.keyword", "size": 10}},
                "top_ips": {"terms": {"field": "src_ip.keyword", "size": 200}},
                "countries": {"terms": {"field": "geoip.country_name.keyword", "size": 30}},
                "asns": {"terms": {"field": "geoip.as_org.keyword", "size": 30}},
                "total_events": {"value_count": {"field": "_index"}},
            },
        }
        try:
            resp = await client.post(f"{ES_URL}/logstash-*/_search", json=galah_agg_query)
            if resp.status_code == 200:
                data = resp.json()
                aggs = data.get("aggregations", {})
                total = data.get("hits", {}).get("total", {}).get("value", 0)
                result["galah_total"] = total

                # Process URIs
                for b in aggs.get("uris", {}).get("buckets", []):
                    uri = b["key"]
                    count = b["doc_count"]
                    if uri and uri != "/":
                        result["http_requests"].append({
                            "uri": uri, "method": "GET", "ip": "",
                            "count": count,
                        })
                # Process IPs
                for b in aggs.get("top_ips", {}).get("buckets", []):
                    ip = b["key"]
                    result["all_src_ips"][ip] = max(
                        result["all_src_ips"].get(ip, 0), b["doc_count"])
                # Process methods
                result["http_methods"] = {
                    b["key"]: b["doc_count"]
                    for b in aggs.get("methods", {}).get("buckets", [])
                }
                # GeoIP
                for b in aggs.get("countries", {}).get("buckets", []):
                    result["geo_countries"][b["key"]] = max(
                        result["geo_countries"].get(b["key"], 0), b["doc_count"])
                for b in aggs.get("asns", {}).get("buckets", []):
                    result["geo_asns"][b["key"]] = max(
                        result["geo_asns"].get(b["key"], 0), b["doc_count"])

                logger.info("Galah aggregation: %d total events, %d unique URIs, %d unique IPs, methods=%s",
                            total,
                            len(aggs.get("uris", {}).get("buckets", [])),
                            len(aggs.get("top_ips", {}).get("buckets", [])),
                            result.get("http_methods", {}))

        except Exception as e:
            logger.error("Galah aggregation error: %s", e)

        # Step 2: Fetch a sample of non-root Galah docs for deeper analysis
        galah_detail_query = {
            "size": 200,
            "query": {"bool": {
                "must": [
                    {"term": {"type.keyword": "Galah"}},
                    {"range": {"@timestamp": {"gte": since}}},
                ],
                "must_not": [
                    {"term": {"request.requestURI.keyword": "/"}},
                    {"term": {"request.requestURI.keyword": "/favicon.ico"}},
                ],
            }},
            "sort": [{"@timestamp": "desc"}],
            "_source": ["src_ip", "request.requestURI", "request.method",
                        "request.body", "request.headers.User-Agent",
                        "response.body", "msg", "@timestamp",
                        "geoip.country_name", "geoip.as_org"],
        }
        try:
            resp = await client.post(f"{ES_URL}/logstash-*/_search", json=galah_detail_query)
            if resp.status_code == 200:
                hits = [h["_source"] for h in resp.json().get("hits", {}).get("hits", [])]
                result["galah"] = hits
                logger.info("Fetched %d Galah detail events (non-root URIs)", len(hits))
                for h in hits:
                    ip = h.get("src_ip", "")
                    if ip:
                        result["all_src_ips"][ip] = max(result["all_src_ips"].get(ip, 0), 1)
                    # Extract POST bodies for IOC analysis
                    req = h.get("request", {})
                    body = req.get("body", "") if isinstance(req, dict) else ""
                    if body and len(body.strip()) > 2:
                        result.setdefault("http_post_bodies", []).append(body[:500])
        except Exception as e:
            logger.error("Galah detail fetch error: %s", e)

        # ─ IP Aggregation (broader) ─
        ip_agg_query = {
            "size": 0,
            "query": {"bool": {"must": [
                {"range": {"@timestamp": {"gte": since}}},
                {"bool": {"should": [
                    {"term": {"type.keyword": "Beelzebub"}},
                    {"term": {"type.keyword": "Galah"}},
                    {"term": {"type.keyword": "Cowrie"}},
                    {"term": {"type.keyword": "Dionaea"}},
                    {"term": {"type.keyword": "Honeytrap"}},
                ]}}
            ]}},
            "aggs": {
                "top_ips": {"terms": {"field": "src_ip.keyword", "size": 500}},
                "countries": {"terms": {"field": "geoip.country_name.keyword", "size": 30}},
                "asns": {"terms": {"field": "geoip.as_org.keyword", "size": 30}},
            },
        }
        try:
            resp = await client.post(f"{ES_URL}/logstash-*/_search", json=ip_agg_query)
            if resp.status_code == 200:
                aggs = resp.json().get("aggregations", {})
                for b in aggs.get("top_ips", {}).get("buckets", []):
                    ip = b["key"]
                    count = b["doc_count"]
                    result["all_src_ips"][ip] = max(result["all_src_ips"].get(ip, 0), count)
                for b in aggs.get("countries", {}).get("buckets", []):
                    result["geo_countries"][b["key"]] = max(
                        result["geo_countries"].get(b["key"], 0), b["doc_count"])
                for b in aggs.get("asns", {}).get("buckets", []):
                    result["geo_asns"][b["key"]] = max(
                        result["geo_asns"].get(b["key"], 0), b["doc_count"])
                logger.info("IP aggregation: %d unique IPs, %d countries, %d ASNs",
                            len(aggs.get("top_ips", {}).get("buckets", [])),
                            len(result["geo_countries"]),
                            len(result["geo_asns"]))
        except Exception as e:
            logger.error("IP aggregation error: %s", e)

    # Normalise commands
    result["normalised_commands"] = normalise_commands(result["ssh_commands"])
    logger.info("Normalised %d raw SSH commands -> %d atomic sub-commands",
                len(result["ssh_commands"]), len(result["normalised_commands"]))

    return result


# ─── Sigma Rule Generator ────────────────────────────────────────────

def generate_sigma_rules(data: dict) -> list[dict]:
    """Generate Sigma rules from normalised attack patterns."""
    rules = []
    timestamp = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    atoms = data.get("normalised_commands", [])

    # Group by MITRE tactic
    tactic_groups = defaultdict(list)
    for atom in atoms:
        cat = atom.get("category", "unknown")
        tactic_groups[cat].append(atom)

    # ─ Rule per tactic ─
    tactic_config = {
        "discovery": {
            "title": "Honeypot - SSH System Reconnaissance",
            "level": "medium",
            "tags_prefix": ["attack.discovery"],
            "description_prefix": "System reconnaissance commands observed on SSH honeypot",
        },
        "credential_access": {
            "title": "Honeypot - SSH Credential Theft Attempt",
            "level": "critical",
            "tags_prefix": ["attack.credential_access"],
            "description_prefix": "Credential and sensitive data access patterns from SSH honeypot",
        },
        "collection": {
            "title": "Honeypot - SSH Data Collection/Exfiltration",
            "level": "high",
            "tags_prefix": ["attack.collection"],
            "description_prefix": "Data collection patterns (Telegram, SMS, device access) from SSH honeypot",
        },
        "impact": {
            "title": "Honeypot - SSH Cryptominer Activity",
            "level": "high",
            "tags_prefix": ["attack.impact"],
            "description_prefix": "Cryptominer reconnaissance and deployment from SSH honeypot",
        },
        "persistence": {
            "title": "Honeypot - SSH Persistence Mechanism",
            "level": "high",
            "tags_prefix": ["attack.persistence"],
            "description_prefix": "Persistence setup commands from SSH honeypot",
        },
        "command_and_control": {
            "title": "Honeypot - SSH Tool Download/C2",
            "level": "critical",
            "tags_prefix": ["attack.command_and_control"],
            "description_prefix": "Tool download or C2 related commands from SSH honeypot",
        },
        "defense_evasion": {
            "title": "Honeypot - SSH Defense Evasion",
            "level": "high",
            "tags_prefix": ["attack.defense_evasion"],
            "description_prefix": "Defense evasion techniques from SSH honeypot",
        },
        "execution": {
            "title": "Honeypot - SSH Command Execution",
            "level": "medium",
            "tags_prefix": ["attack.execution"],
            "description_prefix": "Shell command execution patterns from SSH honeypot",
        },
    }

    for tactic, atoms_list in tactic_groups.items():
        if tactic == "unknown" or len(atoms_list) < MIN_HITS_FOR_RULE:
            continue

        cfg = tactic_config.get(tactic)
        if not cfg:
            continue

        # Collect unique short commands (max 120 chars each)
        unique_cmds = list({a["cmd"][:120] for a in atoms_list})[:15]
        unique_ips = {a["ip"] for a in atoms_list if a["ip"]}

        # Collect all MITRE technique IDs
        all_mitre = set()
        for a in atoms_list:
            for m in a.get("mitre", []):
                all_mitre.add(m["id"])

        tags = list(cfg["tags_prefix"])
        for tid in sorted(all_mitre):
            tags.append(f"attack.{tid.lower()}")

        rule = {
            "title": cfg["title"],
            "id": _rule_uuid(f"sigma-{tactic}"),
            "status": "experimental",
            "level": cfg["level"],
            "description": (
                f"{cfg['description_prefix']}. "
                f"{len(atoms_list)} events, {len(unique_ips)} source IPs, "
                f"{len(unique_cmds)} unique patterns."
            ),
            "author": "LLM Honeypot Intelligence Platform (automated)",
            "date": timestamp,
            "references": ["https://attack.mitre.org/"],
            "tags": tags,
            "logsource": {"category": "process_creation", "product": "linux"},
            "detection": {
                "selection": {"CommandLine|contains": unique_cmds},
                "condition": "selection",
            },
            "falsepositives": ["Legitimate system administration"],
        }
        rules.append(rule)

    # ─ HTTP-based rules: classify URIs into attack categories ─
    http_requests = data.get("http_requests", [])
    if http_requests:
        # Classify HTTP attacks into groups
        http_groups = {
            "malware_download": {
                "title": "Honeypot - HTTP Malware Download",
                "level": "critical",
                "tags": ["attack.command_and_control", "attack.t1105"],
                "desc": "Malware download URLs observed on HTTP honeypot",
                "patterns": [],
            },
            "vpn_exploit": {
                "title": "Honeypot - VPN/Gateway Exploitation",
                "level": "critical",
                "tags": ["attack.initial_access", "attack.t1190"],
                "desc": "VPN/gateway exploitation attempts (Cisco, Fortinet, etc.)",
                "patterns": [],
            },
            "config_theft": {
                "title": "Honeypot - HTTP Configuration/Credential Theft",
                "level": "high",
                "tags": ["attack.credential_access", "attack.t1552.001"],
                "desc": "Attempts to steal configuration files and credentials",
                "patterns": [],
            },
            "rce_attempt": {
                "title": "Honeypot - HTTP Remote Code Execution Attempt",
                "level": "critical",
                "tags": ["attack.execution", "attack.t1059", "attack.t1190"],
                "desc": "Remote code execution attempts via web vulnerabilities",
                "patterns": [],
            },
            "web_scan": {
                "title": "Honeypot - HTTP Vulnerability Scanning",
                "level": "medium",
                "tags": ["attack.reconnaissance", "attack.t1595"],
                "desc": "Automated vulnerability scanning patterns",
                "patterns": [],
            },
            "proxy_abuse": {
                "title": "Honeypot - HTTP Proxy Abuse / SSRF",
                "level": "high",
                "tags": ["attack.command_and_control", "attack.t1090"],
                "desc": "Attempts to abuse the server as open proxy or for SSRF",
                "patterns": [],
            },
        }

        for entry in http_requests:
            uri = entry.get("uri", "")
            ul = uri.lower()

            if any(ext in ul for ext in [".zip", ".exe", ".sh", ".bin", ".elf"]):
                http_groups["malware_download"]["patterns"].append(uri)
            elif any(k in ul for k in ["cscoe", "webvpn", "fortinet", "pulse",
                                        "citrix", "/vpn/", "sslvpn"]):
                http_groups["vpn_exploit"]["patterns"].append(uri)
            elif any(k in ul for k in [".env", ".aws", "config.json", ".git/",
                                        "credentials", "wp-config"]):
                http_groups["config_theft"]["patterns"].append(uri)
            elif any(k in ul for k in ["eval-stdin", "cgi-bin/", "shell", "cmd",
                                        "exec", "invokefunction", "pearcmd",
                                        "goform", "gpon", "SDK/webLanguage",
                                        "phpinfo", "recordings/index.php"]):
                http_groups["rce_attempt"]["patterns"].append(uri)
            elif uri.startswith("http://") or uri.startswith("https://") or ":" in uri.split("/")[0]:
                http_groups["proxy_abuse"]["patterns"].append(uri)
            elif any(k in ul for k in ["/admin", "/backup", "/login", "robots.txt",
                                        "security.txt", "/version", "/webui",
                                        "/bin/", "containers/json", ".well-known"]):
                http_groups["web_scan"]["patterns"].append(uri)

        for group_key, grp in http_groups.items():
            patterns = grp["patterns"]
            if len(patterns) < MIN_HITS_FOR_RULE:
                continue
            unique_patterns = list(set(p[:120] for p in patterns))[:20]
            rule = {
                "title": grp["title"],
                "id": _rule_uuid(f"sigma-http-{group_key}"),
                "status": "experimental",
                "level": grp["level"],
                "description": f"{grp['desc']}. {len(patterns)} events, {len(unique_patterns)} patterns.",
                "author": "LLM Honeypot Intelligence Platform (automated)",
                "date": timestamp,
                "references": ["https://attack.mitre.org/"],
                "tags": grp["tags"],
                "logsource": {"category": "webserver"},
                "detection": {
                    "selection": {"cs-uri|contains": unique_patterns},
                    "condition": "selection",
                },
                "falsepositives": ["Authorized penetration testing", "Vulnerability scanners"],
            }
            rules.append(rule)

    return rules


# ─── YARA Rule Generator ─────────────────────────────────────────────

def generate_yara_rules(data: dict) -> list[str]:
    """Generate YARA rules from normalised SSH commands."""
    rules = []
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    atoms = data.get("normalised_commands", [])

    # Group commands by category
    groups = {
        "MinerRecon": [],
        "CredentialTheft": [],
        "SystemRecon": [],
        "Persistence": [],
        "ToolDownload": [],
        "DataCollection": [],
    }

    for atom in atoms:
        cmd = atom["cmd"]
        mitre_ids = {m["id"] for m in atom.get("mitre", [])}

        if "T1496" in mitre_ids:
            groups["MinerRecon"].append(cmd)
        elif any(t in mitre_ids for t in ["T1552.001", "T1552.004", "T1528"]):
            groups["CredentialTheft"].append(cmd)
        elif "T1005" in mitre_ids:
            groups["DataCollection"].append(cmd)
        elif "T1105" in mitre_ids:
            groups["ToolDownload"].append(cmd)
        elif any(t in mitre_ids for t in ["T1053.003", "T1037.004", "T1543.002"]):
            groups["Persistence"].append(cmd)
        elif any(t in mitre_ids for t in ["T1082", "T1016", "T1033", "T1057"]):
            groups["SystemRecon"].append(cmd)

    for group_name, cmds in groups.items():
        if len(cmds) < MIN_HITS_FOR_RULE:
            continue
        unique_cmds = list(set(cmds))[:12]

        # Filter: each string must be >= 5 chars and <= 100 chars
        valid_cmds = [c for c in unique_cmds if 5 <= len(c) <= 100]
        if not valid_cmds:
            continue

        strings_section = "\n".join(
            f'        $s{i} = "{_yara_escape(c)}" ascii nocase'
            for i, c in enumerate(valid_cmds)
        )
        rule = f"""rule Honeypot_{group_name} {{
    meta:
        description = "LLM Honeypot Intelligence - {group_name} pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "{timestamp}"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "{len(cmds)}"
        unique_patterns = "{len(valid_cmds)}"
    strings:
{strings_section}
    condition:
        any of them
}}"""
        rules.append(rule)

    # HTTP-based YARA rules from Galah data
    http_yara_groups = {
        "HTTP_MalwareDownload": {"patterns": [], "desc": "Malware download URLs"},
        "HTTP_VPNExploit": {"patterns": [], "desc": "VPN/gateway exploit paths"},
        "HTTP_ConfigTheft": {"patterns": [], "desc": "Configuration file theft paths"},
        "HTTP_WebRCE": {"patterns": [], "desc": "Remote code execution attempt paths"},
    }

    for entry in data.get("http_requests", []):
        uri = entry.get("uri", "")
        ul = uri.lower()
        if any(ext in ul for ext in [".zip", ".exe", ".sh", ".bin", ".elf"]):
            http_yara_groups["HTTP_MalwareDownload"]["patterns"].append(uri)
        elif any(k in ul for k in ["cscoe", "webvpn"]):
            http_yara_groups["HTTP_VPNExploit"]["patterns"].append(uri)
        elif any(k in ul for k in [".env", ".aws", ".git/", "config.json"]):
            http_yara_groups["HTTP_ConfigTheft"]["patterns"].append(uri)
        elif any(k in ul for k in ["eval-stdin", "cgi-bin/", "invokefunction",
                                     "pearcmd", "goform", "gpon", "SDK/"]):
            http_yara_groups["HTTP_WebRCE"]["patterns"].append(uri)

    for gname, gdata in http_yara_groups.items():
        if len(gdata["patterns"]) < MIN_HITS_FOR_RULE:
            continue
        unique = list(set(gdata["patterns"]))[:12]
        valid = [p for p in unique if 5 <= len(p) <= 100]
        if not valid:
            continue
        strings_section = "\n".join(
            f'        $u{i} = "{_yara_escape(p)}" ascii nocase'
            for i, p in enumerate(valid)
        )
        rule = f"""rule Honeypot_{gname} {{
    meta:
        description = "LLM Honeypot Intelligence - HTTP {gdata['desc']}"
        author = "LLM Honeypot Intelligence Platform"
        date = "{timestamp}"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "{len(gdata['patterns'])}"
    strings:
{strings_section}
    condition:
        any of them
}}"""
        rules.append(rule)

    return rules


# ─── Suricata Rule Generator ─────────────────────────────────────────

def generate_suricata_rules(data: dict) -> list[str]:
    """Generate Suricata IDS/IPS rules from normalised honeypot data."""
    rules = []
    sid_base = 9000001
    atoms = data.get("normalised_commands", [])

    # SSH: use atomic commands only (5-80 chars)
    cmd_counter = Counter()
    cmd_mitre = {}
    for atom in atoms:
        cmd = atom["cmd"]
        if 5 <= len(cmd) <= 80:
            cmd_counter[cmd] += 1
            if cmd not in cmd_mitre:
                cmd_mitre[cmd] = atom.get("mitre", [])

    for i, (cmd, count) in enumerate(cmd_counter.most_common(30)):
        if count < MIN_HITS_FOR_RULE:
            continue

        mitre = cmd_mitre.get(cmd, [])
        cl = cmd.lower()

        # Determine priority from MITRE tactic
        if any(m["tactic"] in ("credential_access", "command_and_control", "impact") for m in mitre):
            priority = 1
            classtype = "trojan-activity"
        elif any(m["tactic"] in ("collection", "persistence") for m in mitre):
            priority = 2
            classtype = "attempted-admin"
        else:
            priority = 3
            classtype = "attempted-recon"

        mitre_ref = ",".join(m["id"] for m in mitre) if mitre else "none"
        escaped = _suricata_escape(cmd)
        msg_clean = _suricata_msg(cmd)

        rule = (
            f'alert tcp any any -> $HOME_NET 22 ('
            f'msg:"HONEYPOT-SSH {msg_clean}"; '
            f'flow:established,to_server; '
            f'content:"{escaped}"; nocase; '
            f'classtype:{classtype}; '
            f'sid:{sid_base + i}; rev:1; '
            f'priority:{priority}; '
            f'metadata:source honeypot_intel, count {count}, '
            f'mitre {mitre_ref}, '
            f'created {datetime.now(timezone.utc).strftime("%Y_%m_%d")};'
            f')'
        )
        rules.append(rule)

    # HTTP: classified by attack type
    uri_counter = Counter()
    for e in data.get("http_requests", []):
        uri = e.get("uri", "")
        count = e.get("count", 1)
        if uri and uri != "/" and uri != "/favicon.ico":
            uri_counter[uri] += count

    for i, (uri, count) in enumerate(uri_counter.most_common(40)):
        if count < MIN_HITS_FOR_RULE or len(uri) < 3 or len(uri) > 80:
            continue

        cl = uri.lower()
        if any(ext in cl for ext in [".zip", ".exe", ".sh", ".bin"]):
            priority = 1
            classtype = "trojan-activity"
            msg_cat = "MALWARE-DL"
        elif any(k in cl for k in ["eval-stdin", "cgi-bin/", "invokefunction",
                                     "pearcmd", "goform", "gpon"]):
            priority = 1
            classtype = "web-application-attack"
            msg_cat = "RCE"
        elif any(k in cl for k in ["cscoe", "webvpn"]):
            priority = 1
            classtype = "web-application-attack"
            msg_cat = "VPN-EXPLOIT"
        elif any(k in cl for k in [".env", ".aws", ".git/", "config.json",
                                    "credentials", "wp-config"]):
            priority = 2
            classtype = "web-application-activity"
            msg_cat = "CONFIG-THEFT"
        elif any(k in cl for k in ["containers/json", "/admin", "/backup"]):
            priority = 2
            classtype = "web-application-activity"
            msg_cat = "RECON"
        else:
            priority = 3
            classtype = "web-application-activity"
            msg_cat = "SCAN"

        escaped = _suricata_escape(uri)
        rule = (
            f'alert http any any -> $HOME_NET any ('
            f'msg:"HONEYPOT-HTTP-{msg_cat} {_suricata_msg(uri)}"; '
            f'flow:established,to_server; '
            f'http.uri; content:"{escaped}"; '
            f'classtype:{classtype}; '
            f'sid:{sid_base + 500 + i}; rev:1; '
            f'priority:{priority}; '
            f'metadata:source honeypot_intel, category {msg_cat.lower()}, count {count}, '
            f'created {datetime.now(timezone.utc).strftime("%Y_%m_%d")};'
            f')'
        )
        rules.append(rule)

    return rules


# ─── Firewall Blocklist Generator ────────────────────────────────────

def generate_firewall_rules(data: dict) -> dict:
    """Generate firewall blocklists and rules from attacker IPs."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    mass_scanners = []
    repeat_offenders = []
    active_attackers = []
    all_attackers = []

    for ip, count in data["all_src_ips"].most_common():
        if not ip or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            continue
        all_attackers.append((ip, count))
        is_scanner = any(ip.startswith(prefix) for prefix in KNOWN_SCANNER_PREFIXES)
        if is_scanner:
            mass_scanners.append((ip, count))
        elif count >= 10:
            repeat_offenders.append((ip, count))
        elif count >= MIN_HITS_FOR_BLOCKLIST:
            active_attackers.append((ip, count))

    result = {}

    # iptables
    lines = [
        "#!/bin/bash",
        "# LLM Honeypot Intelligence - Firewall Blocklist",
        f"# Generated: {timestamp}",
        f"# Total: {len(all_attackers)} IPs | Blocked: "
        f"{len(mass_scanners)} scanners + {len(repeat_offenders)} repeat + {len(active_attackers)} active",
        "",
        "# Mass Scanners (known infrastructure)",
    ]
    for ip, count in mass_scanners:
        lines.append(f"iptables -A INPUT -s {ip} -j DROP  # scanner, {count} hits")
    lines.append("\n# Repeat Offenders (>= 10 hits)")
    for ip, count in repeat_offenders:
        lines.append(f"iptables -A INPUT -s {ip} -j DROP  # {count} hits")
    lines.append(f"\n# Active Attackers (>= {MIN_HITS_FOR_BLOCKLIST} hits)")
    for ip, count in active_attackers:
        lines.append(f"iptables -A INPUT -s {ip} -j DROP  # {count} hits")
    result["iptables"] = "\n".join(lines)

    # nftables
    blocked_ips = [ip for ip, _ in mass_scanners + repeat_offenders + active_attackers]
    nft = [
        "#!/usr/sbin/nft -f",
        "# LLM Honeypot Intelligence - nftables Blocklist",
        f"# Generated: {timestamp}",
        "",
        "table inet honeypot_filter {",
        "    set blocklist {",
        "        type ipv4_addr",
        "        flags interval",
    ]
    if blocked_ips:
        nft.append(f"        elements = {{ {', '.join(blocked_ips)} }}")
    nft.extend([
        "    }",
        "    chain input {",
        "        type filter hook input priority 0; policy accept;",
        "        ip saddr @blocklist counter drop",
        "    }",
        "}",
    ])
    result["nftables"] = "\n".join(nft)

    # Plain blocklist
    plain = ["# LLM Honeypot Intelligence - IP Blocklist", f"# Generated: {timestamp}"]
    for ip, count in sorted(all_attackers, key=lambda x: -x[1]):
        if count >= MIN_HITS_FOR_BLOCKLIST:
            plain.append(ip)
    result["plain_blocklist"] = "\n".join(plain)

    result["stats"] = {
        "total_ips": len(all_attackers),
        "mass_scanners": len(mass_scanners),
        "repeat_offenders": len(repeat_offenders),
        "active_attackers": len(active_attackers),
        "blocked_total": len(blocked_ips),
    }

    return result


# ─── STIX 2.1 Bundle Generator ───────────────────────────────────────

def generate_stix_bundle(data: dict, iocs: dict, sigma_rules: list) -> dict:
    """Generate a STIX 2.1 bundle from the honeypot intelligence."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    objects = []

    # Identity (the honeypot platform)
    identity_id = "identity--" + _stable_uuid("llm-honeypot-platform")
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "LLM Honeypot Intelligence Platform",
        "identity_class": "system",
        "description": "Automated threat intelligence from adaptive LLM honeypots",
    })

    # Attack Patterns (from MITRE mappings)
    seen_techniques = set()
    for atom in data.get("normalised_commands", []):
        for m in atom.get("mitre", []):
            tid = m["id"]
            if tid in seen_techniques:
                continue
            seen_techniques.add(tid)
            ap_id = "attack-pattern--" + _stable_uuid(f"mitre-{tid}")
            objects.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now,
                "modified": now,
                "name": m["name"],
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": tid,
                    "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
                }],
            })

    # Indicators (top attacker IPs)
    for ip, count in sorted(iocs["ipv4"].items(), key=lambda x: -x[1])[:50]:
        if count < MIN_HITS_FOR_BLOCKLIST:
            continue
        ind_id = "indicator--" + _stable_uuid(f"ip-{ip}")
        is_scanner = any(ip.startswith(p) for p in KNOWN_SCANNER_PREFIXES)
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": now,
            "modified": now,
            "name": f"Malicious IP: {ip}",
            "description": f"{'Mass scanner' if is_scanner else 'Attacker'} IP observed {count} times on honeypot",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": now,
            "confidence": min(90, 40 + count),
        })

    # Observed Data summary
    objects.append({
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--" + _stable_uuid(f"summary-{now}"),
        "created": now,
        "modified": now,
        "first_observed": (datetime.now(timezone.utc) - timedelta(hours=SINCE_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_observed": now,
        "number_observed": len(data.get("beelzebub", [])) + len(data.get("galah", [])),
    })

    return {
        "type": "bundle",
        "id": "bundle--" + str(uuid.uuid4()),
        "objects": objects,
    }


# ─── Threat Intelligence Report ──────────────────────────────────────

def generate_threat_report(data: dict, iocs: dict, sigma_count: int,
                            yara_count: int, suricata_count: int,
                            fw_stats: dict) -> str:
    """Generate a Markdown threat intelligence report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    atoms = data.get("normalised_commands", [])
    total_events = len(data.get("beelzebub", [])) + len(data.get("galah", []))

    # MITRE tactic summary
    tactic_counter = Counter()
    technique_counter = Counter()
    for atom in atoms:
        for m in atom.get("mitre", []):
            tactic_counter[m["tactic"]] += 1
            technique_counter[f"{m['id']} ({m['name']})"] += 1

    # Build report
    lines = [
        "# Threat Intelligence Report",
        "",
        f"**Generated**: {now}  ",
        "**Source**: LLM Honeypot Intelligence Platform  ",
        f"**Window**: Last {SINCE_HOURS} hours  ",
        "**Classification**: TLP:AMBER",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"In the past {SINCE_HOURS} hours, the honeypot platform observed **{total_events:,} events** "
        f"from **{len(data['all_src_ips']):,} unique source IPs** across "
        f"**{len(data['geo_countries'])} countries** and **{len(data['geo_asns'])} autonomous systems**.",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| SSH Events (Beelzebub) | {len(data.get('beelzebub', [])):,} |",
        f"| HTTP Events (Galah) | {len(data.get('galah', [])):,} |",
        f"| Unique Attacker IPs | {len(data['all_src_ips']):,} |",
        f"| Atomic Attack Patterns | {len(atoms)} |",
        f"| MITRE ATT&CK Techniques | {len(technique_counter)} |",
        f"| Generated Sigma Rules | {sigma_count} |",
        f"| Generated YARA Rules | {yara_count} |",
        f"| Generated Suricata Rules | {suricata_count} |",
        f"| Blocked IPs (Firewall) | {fw_stats.get('blocked_total', 0)} |",
        "",
        "---",
        "",
        "## MITRE ATT&CK Mapping",
        "",
    ]

    if technique_counter:
        lines.append("| Technique | Name | Count |")
        lines.append("|-----------|------|-------|")
        for tech, count in technique_counter.most_common(20):
            lines.append(f"| {tech} | | {count} |")
        lines.append("")

    if tactic_counter:
        lines.append("### Tactics Distribution")
        lines.append("")
        for tactic, count in tactic_counter.most_common():
            bar = "█" * min(40, count // 2)
            lines.append(f"- **{tactic}**: {count} events {bar}")
        lines.append("")

    # Geographic Distribution
    lines.extend([
        "---",
        "",
        "## Geographic Distribution",
        "",
        "### Top Source Countries",
        "",
        "| Country | Events |",
        "|---------|--------|",
    ])
    for country, count in data["geo_countries"].most_common(15):
        lines.append(f"| {country} | {count:,} |")

    lines.extend([
        "",
        "### Top ASNs (Autonomous Systems)",
        "",
        "| ASN | Events |",
        "|-----|--------|",
    ])
    for asn, count in data["geo_asns"].most_common(15):
        lines.append(f"| {asn} | {count:,} |")

    # Top Attacker IPs
    lines.extend([
        "",
        "---",
        "",
        "## Top Attacker IPs",
        "",
        "| IP | Hits | Category |",
        "|----|----- |----------|",
    ])
    for ip, count in data["all_src_ips"].most_common(20):
        if ip.startswith("192.168.") or ip.startswith("10."):
            continue
        cat = "Scanner" if any(ip.startswith(p) for p in KNOWN_SCANNER_PREFIXES) else "Attacker"
        lines.append(f"| `{ip}` | {count:,} | {cat} |")

    # IOC Summary
    lines.extend([
        "",
        "---",
        "",
        "## Indicators of Compromise (IOCs)",
        "",
        "| Type | Count |",
        "|------|-------|",
        f"| IPv4 Addresses | {len(iocs['ipv4'])} |",
        f"| URLs | {len(iocs['urls'])} |",
        f"| Domains | {len(iocs['domains'])} |",
        f"| SHA256 Hashes | {len(iocs['hashes_sha256'])} |",
        f"| File Paths | {len(iocs['file_paths'])} |",
    ])

    if iocs["file_paths"]:
        lines.extend(["", "### Targeted File Paths", ""])
        for p in sorted(iocs["file_paths"])[:20]:
            lines.append(f"- `{p}`")

    if iocs["urls"]:
        lines.extend(["", "### Extracted URLs", ""])
        for u in sorted(iocs["urls"])[:10]:
            lines.append(f"- `{u}`")

    # Top Attack Patterns
    lines.extend([
        "",
        "---",
        "",
        "## Top Attack Patterns (SSH)",
        "",
    ])
    cmd_counter = Counter(a["cmd"] for a in atoms)
    for cmd, count in cmd_counter.most_common(15):
        lines.append(f"- [{count}x] `{cmd[:100]}`")

    # HTTP Attack Patterns
    http_requests = data.get("http_requests", [])
    if http_requests:
        lines.extend([
            "",
            "## Top Attack Patterns (HTTP)",
            "",
            "| URI | Hits | Category |",
            "|-----|------|----------|",
        ])
        for entry in sorted(http_requests, key=lambda x: -x.get("count", 1))[:25]:
            uri = entry.get("uri", "")
            count = entry.get("count", 1)
            ul = uri.lower()
            if any(ext in ul for ext in [".zip", ".exe", ".sh", ".bin"]):
                cat = "Malware Download"
            elif any(k in ul for k in ["cscoe", "webvpn"]):
                cat = "VPN Exploit"
            elif any(k in ul for k in [".env", ".aws", ".git/", "config"]):
                cat = "Config Theft"
            elif any(k in ul for k in ["eval-stdin", "cgi-bin", "invoke", "pearcmd", "goform", "gpon"]):
                cat = "RCE Attempt"
            elif uri.startswith("http") or ":" in uri.split("/")[0]:
                cat = "Proxy Abuse"
            else:
                cat = "Web Scan"
            lines.append(f"| `{uri[:80]}` | {count:,} | {cat} |")

        # HTTP Methods breakdown
        methods = data.get("http_methods", {})
        if methods:
            lines.extend(["", "### HTTP Methods", ""])
            for method, count in sorted(methods.items(), key=lambda x: -x[1]):
                lines.append(f"- **{method}**: {count:,}")

    lines.extend([
        "",
        "---",
        "",
        "## Generated Rules Summary",
        "",
        "All rules are stored in: `/data/ollama-proxy/generated-rules/`",
        "",
        "| Format | Count | Path |",
        "|--------|-------|------|",
        f"| Sigma (SIEM) | {sigma_count} | `sigma/*.yml` |",
        f"| YARA (Payload) | {yara_count} | `yara/*.yar` |",
        f"| Suricata (IDS/IPS) | {suricata_count} | `suricata/honeypot.rules` |",
        f"| Firewall (iptables) | {fw_stats.get('blocked_total', 0)} IPs | `firewall/blocklist_*.sh` |",
        "| STIX 2.1 Bundle | 1 | `stix/bundle.json` |",
        "| IOC List | 1 | `iocs/ioc_list.json` |",
        "",
        "---",
        "",
        "*Report generated automatically by LLM Honeypot Intelligence Platform*",
    ])

    return "\n".join(lines)


# ─── File Output ──────────────────────────────────────────────────────

def write_rules(sigma_rules: list, yara_rules: list, suricata_rules: list,
                firewall: dict, stix_bundle: dict, iocs: dict,
                report: str, data: dict) -> dict:
    """Write all generated rules and reports to files."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    summary = {"files": [], "counts": {}}

    for subdir in ["sigma", "yara", "suricata", "firewall", "stix", "iocs", "reports"]:
        d = RULES_DIR / subdir
        d.mkdir(parents=True, exist_ok=True)
        # Clean old files before writing new ones
        for old_file in d.iterdir():
            if old_file.is_file():
                old_file.unlink()

    # Sigma Rules
    if sigma_rules:
        import yaml
        for rule in sigma_rules:
            slug = re.sub(r'[^a-z0-9]+', '_', rule["title"].lower())[:60]
            path = RULES_DIR / "sigma" / f"{slug}.yml"
            with open(path, "w") as f:
                yaml.dump(rule, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            summary["files"].append(str(path))
        summary["counts"]["sigma"] = len(sigma_rules)
        logger.info("Wrote %d Sigma rules", len(sigma_rules))

    # YARA Rules
    if yara_rules:
        path = RULES_DIR / "yara" / "honeypot_rules.yar"
        with open(path, "w") as f:
            f.write("// LLM Honeypot Intelligence Platform - YARA Rules\n")
            f.write(f"// Generated: {timestamp}\n")
            f.write(f"// Source: Elasticsearch honeypot data ({SINCE_HOURS}h window)\n\n")
            f.write("\n\n".join(yara_rules))
        summary["files"].append(str(path))
        summary["counts"]["yara"] = len(yara_rules)
        logger.info("Wrote %d YARA rules", len(yara_rules))

    # Suricata Rules
    if suricata_rules:
        path = RULES_DIR / "suricata" / "honeypot.rules"
        with open(path, "w") as f:
            f.write("# LLM Honeypot Intelligence Platform - Suricata Rules\n")
            f.write(f"# Generated: {timestamp}\n")
            f.write(f"# {len(suricata_rules)} rules from honeypot data\n\n")
            f.write("\n".join(suricata_rules))
        summary["files"].append(str(path))
        summary["counts"]["suricata"] = len(suricata_rules)
        logger.info("Wrote %d Suricata rules", len(suricata_rules))

    # Firewall
    if firewall:
        for fmt in ["iptables", "nftables", "plain_blocklist"]:
            if fmt in firewall:
                ext = {"iptables": "sh", "nftables": "nft", "plain_blocklist": "txt"}[fmt]
                path = RULES_DIR / "firewall" / f"blocklist_{fmt}.{ext}"
                with open(path, "w") as f:
                    f.write(firewall[fmt])
                summary["files"].append(str(path))
        summary["counts"]["firewall_ips"] = firewall.get("stats", {}).get("blocked_total", 0)
        logger.info("Wrote firewall rules (%d IPs blocked)", firewall.get("stats", {}).get("blocked_total", 0))

    # STIX Bundle
    if stix_bundle:
        path = RULES_DIR / "stix" / "bundle.json"
        with open(path, "w") as f:
            json.dump(stix_bundle, f, indent=2)
        summary["files"].append(str(path))
        summary["counts"]["stix_objects"] = len(stix_bundle.get("objects", []))
        logger.info("Wrote STIX bundle (%d objects)", summary["counts"]["stix_objects"])

    # IOC List
    if iocs:
        path = RULES_DIR / "iocs" / "ioc_list.json"
        serialisable_iocs = {}
        for k, v in iocs.items():
            if isinstance(v, Counter):
                serialisable_iocs[k] = dict(v.most_common(200))
            elif isinstance(v, (list, set)):
                serialisable_iocs[k] = sorted(v) if isinstance(v, set) else v
            else:
                serialisable_iocs[k] = v
        with open(path, "w") as f:
            json.dump(serialisable_iocs, f, indent=2)
        summary["files"].append(str(path))
        summary["counts"]["iocs"] = sum(
            len(v) if isinstance(v, (list, dict)) else 0
            for v in serialisable_iocs.values()
        )
        logger.info("Wrote IOC list (%d indicators)", summary["counts"]["iocs"])

    # Threat Intelligence Report
    if report:
        path = RULES_DIR / "reports" / "threat_intel_report.md"
        with open(path, "w") as f:
            f.write(report)
        summary["files"].append(str(path))
        summary["counts"]["report"] = 1
        logger.info("Wrote Threat Intelligence Report")

    # Manifest
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "LLM Honeypot Intelligence Platform",
        "version": "2.0",
        "window_hours": SINCE_HOURS,
        "input_events": {
            "beelzebub": len(data.get("beelzebub", [])),
            "galah": len(data.get("galah", [])),
            "unique_ips": len(data.get("all_src_ips", {})),
            "normalised_commands": len(data.get("normalised_commands", [])),
            "countries": len(data.get("geo_countries", {})),
            "asns": len(data.get("geo_asns", {})),
        },
        "output": summary["counts"],
        "files": summary["files"],
    }
    manifest_path = RULES_DIR / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    summary["files"].append(str(manifest_path))

    return summary


# ─── Helpers ──────────────────────────────────────────────────────────

def _rule_uuid(seed: str) -> str:
    h = hashlib.md5(seed.encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def _stable_uuid(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"honeypot:{seed}"))

def _yara_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")[:100]

def _suricata_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace(";", "\\;").replace("|", "\\|")[:80]

def _suricata_msg(s: str) -> str:
    clean = re.sub(r'[^a-zA-Z0-9/_.\- ]', '', s)[:50].strip()
    return clean or "suspicious-pattern"


# ─── Main Entry Point ────────────────────────────────────────────────

async def run_rule_generation() -> dict:
    """Run a complete rule generation cycle. Returns summary."""
    logger.info("=" * 60)
    logger.info("Starting Rule Generation Cycle v2")
    logger.info("Window: last %d hours | Output: %s", SINCE_HOURS, RULES_DIR)

    # 1. Fetch + normalise attack data
    data = await fetch_attack_data(SINCE_HOURS)
    total_events = len(data["beelzebub"]) + len(data["galah"])
    if total_events == 0:
        logger.info("No attack data found in the last %d hours. Skipping.", SINCE_HOURS)
        return {"status": "no_data"}

    logger.info("Input: %d events (%d SSH, %d HTTP), %d unique IPs, %d normalised commands",
                total_events, len(data["beelzebub"]), len(data["galah"]),
                len(data["all_src_ips"]), len(data["normalised_commands"]))

    # 2. Extract IOCs
    iocs = extract_iocs(data)
    logger.info("IOCs: %d IPs, %d URLs, %d domains, %d hashes, %d paths",
                len(iocs["ipv4"]), len(iocs["urls"]), len(iocs["domains"]),
                len(iocs["hashes_sha256"]), len(iocs["file_paths"]))

    # 3. Generate rules
    sigma_rules = generate_sigma_rules(data)
    yara_rules = generate_yara_rules(data)
    suricata_rules = generate_suricata_rules(data)
    firewall = generate_firewall_rules(data)

    # 4. Generate STIX bundle
    stix_bundle = generate_stix_bundle(data, iocs, sigma_rules)

    # 5. Generate threat intel report
    report = generate_threat_report(
        data, iocs,
        sigma_count=len(sigma_rules),
        yara_count=len(yara_rules),
        suricata_count=len(suricata_rules),
        fw_stats=firewall.get("stats", {}),
    )

    # 6. Write everything to disk
    summary = write_rules(sigma_rules, yara_rules, suricata_rules,
                          firewall, stix_bundle, iocs, report, data)

    logger.info("=" * 60)
    logger.info("Rule Generation Complete:")
    logger.info("  Sigma: %d | YARA: %d | Suricata: %d | FW IPs: %d",
                summary["counts"].get("sigma", 0),
                summary["counts"].get("yara", 0),
                summary["counts"].get("suricata", 0),
                summary["counts"].get("firewall_ips", 0))
    logger.info("  STIX objects: %d | IOCs: %d | Report: yes",
                summary["counts"].get("stix_objects", 0),
                summary["counts"].get("iocs", 0))
    logger.info("=" * 60)

    return summary
