# Threat Intelligence Report

**Generated**: 2026-03-25 13:58 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **72 events** from **501 unique source IPs** across **30 countries** and **32 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 72 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 501 |
| Atomic Attack Patterns | 724 |
| MITRE ATT&CK Techniques | 6 |
| Generated Sigma Rules | 3 |
| Generated YARA Rules | 2 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 143 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 401 |
| T1059.004 (Unix Shell) | | 274 |
| T1033 (System Owner/User Discovery) | | 42 |
| T1005 (Data from Local System) | | 2 |
| T1016 (System Network Configuration Discovery) | | 1 |
| T1057 (Process Discovery) | | 1 |

### Tactics Distribution

- **discovery**: 445 events ████████████████████████████████████████
- **execution**: 274 events ████████████████████████████████████████
- **collection**: 2 events █

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| France | 1,488 |
| United States | 1,394 |
| Indonesia | 357 |
| The Netherlands | 319 |
| Germany | 123 |
| Chile | 103 |
| Hong Kong | 52 |
| China | 45 |
| Pakistan | 38 |
| United Kingdom | 28 |
| Portugal | 24 |
| Bulgaria | 24 |
| Nigeria | 23 |
| Switzerland | 19 |
| Canada | 18 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Modat B.V. | 1,408 |
| DigitalOcean, LLC | 614 |
| PT Cloud Hosting Indonesia | 357 |
| NewVM B.V. | 279 |
| GoDaddy.com, LLC | 238 |
| ONYPHE SAS | 175 |
| Omegatech LTD | 147 |
| Telefonica del Sur S.A. | 103 |
| Censys, Inc. | 80 |
| Vpsvault.host Ltd | 73 |
| Hurricane Electric LLC | 64 |
| Amazon.com, Inc. | 62 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 57 |
| Akamai Connected Cloud | 54 |
| Microsoft Corporation | 54 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `107.180.88.176` | 238 | Attacker |
| `203.145.34.82` | 238 | Attacker |
| `31.14.32.6` | 217 | Attacker |
| `134.209.166.254` | 162 | Attacker |
| `134.199.196.64` | 161 | Attacker |
| `91.92.243.116` | 147 | Attacker |
| `85.217.140.8` | 136 | Attacker |
| `103.179.56.44` | 119 | Attacker |
| `68.183.66.16` | 112 | Attacker |
| `85.217.140.37` | 112 | Attacker |
| `216.155.93.75` | 103 | Attacker |
| `85.217.140.50` | 99 | Attacker |
| `85.217.140.40` | 93 | Attacker |
| `85.217.140.9` | 70 | Attacker |
| `129.212.184.91` | 67 | Attacker |
| `85.217.140.46` | 63 | Attacker |
| `85.217.140.1` | 54 | Attacker |
| `85.217.140.31` | 54 | Attacker |
| `31.14.32.4` | 51 | Attacker |
| `85.217.140.44` | 44 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 501 |
| URLs | 0 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 5 |

### Targeted File Paths

- `/.local/share/TelegramDesktop/tdata`
- `/etc/smsd.conf`
- `/var/log/smsd.log`
- `/var/qmux_connect`
- `/var/spool/sms`

---

## Top Attack Patterns (SSH)

- [42x] `$f" 2>/dev/null`
- [42x] `echo 0`
- [42x] `echo 1`
- [21x] `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH`
- [21x] `uname -s -v -n -m 2>/dev/null`
- [21x] `uname -m 2>/dev/null`
- [21x] `cat /proc/uptime 2>/dev/null`
- [21x] `nproc 2>/dev/null`
- [21x] `/usr/bin/nproc 2>/dev/null`
- [21x] `grep -c "^processor" /proc/cpuinfo 2>/dev/null`
- [21x] `cpu_model=$( (grep -m1 -E "model name`
- [21x] `Hardware" /proc/cpuinfo`
- [21x] `lscpu 2>/dev/null`
- [21x] `dmidecode -s processor-version 2>/dev/null`
- [21x] `uname -p 2>/dev/null`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 3 | `sigma/*.yml` |
| YARA (Payload) | 2 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 143 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*