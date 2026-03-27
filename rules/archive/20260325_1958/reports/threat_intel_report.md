# Threat Intelligence Report

**Generated**: 2026-03-25 19:58 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **359 events** from **523 unique source IPs** across **33 countries** and **44 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 359 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 523 |
| Atomic Attack Patterns | 2829 |
| MITRE ATT&CK Techniques | 8 |
| Generated Sigma Rules | 5 |
| Generated YARA Rules | 4 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 318 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 1570 |
| T1059.004 (Unix Shell) | | 1013 |
| T1033 (System Owner/User Discovery) | | 162 |
| T1105 (Ingress Tool Transfer) | | 4 |
| T1016 (System Network Configuration Discovery) | | 3 |
| T1057 (Process Discovery) | | 2 |
| T1552.001 (Credentials In Files) | | 2 |
| T1005 (Data from Local System) | | 2 |

### Tactics Distribution

- **discovery**: 1737 events ████████████████████████████████████████
- **execution**: 1013 events ████████████████████████████████████████
- **command_and_control**: 4 events ██
- **credential_access**: 2 events █
- **collection**: 2 events █

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 4,100 |
| France | 1,919 |
| Indonesia | 1,537 |
| China | 1,032 |
| United Kingdom | 527 |
| The Netherlands | 415 |
| South Korea | 412 |
| Peru | 307 |
| Switzerland | 300 |
| India | 291 |
| Germany | 280 |
| Russia | 246 |
| Canada | 209 |
| Romania | 196 |
| Seychelles | 144 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Modat B.V. | 1,673 |
| DigitalOcean, LLC | 1,625 |
| PT Cloud Hosting Indonesia | 833 |
| Omegatech LTD | 549 |
| ONYPHE SAS | 503 |
| Amazon.com, Inc. | 427 |
| Microsoft Corporation | 324 |
| Google LLC | 311 |
| INTEGRATEL PERU S.A.A. | 307 |
| PT Aplikanusa Lintasarta | 307 |
| PDR | 282 |
| Private Layer INC | 280 |
| NewVM B.V. | 279 |
| GoDaddy.com, LLC | 238 |
| Domain names registrar REG.RU, Ltd | 213 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `91.92.243.116` | 538 | Attacker |
| `134.199.196.64` | 458 | Attacker |
| `134.209.166.254` | 458 | Attacker |
| `203.145.34.82` | 407 | Attacker |
| `103.191.14.210` | 307 | Attacker |
| `103.63.25.171` | 307 | Attacker |
| `170.79.37.88` | 307 | Attacker |
| `119.18.55.118` | 282 | Attacker |
| `46.19.137.194` | 280 | Attacker |
| `34.39.58.191` | 257 | Attacker |
| `107.180.88.176` | 238 | Attacker |
| `68.183.66.16` | 231 | Attacker |
| `31.14.32.6` | 217 | Attacker |
| `193.227.241.201` | 213 | Attacker |
| `129.212.184.91` | 192 | Attacker |
| `76.79.213.69` | 187 | Attacker |
| `20.26.135.100` | 169 | Attacker |
| `221.139.88.149` | 169 | Attacker |
| `36.64.68.99` | 169 | Attacker |
| `2.57.122.238` | 165 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 523 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 13 |

### Targeted File Paths

- `/.local/share/TelegramDesktop/tdata`
- `/etc/hostname`
- `/etc/netplan`
- `/etc/network/interfaces`
- `/etc/passwd`
- `/etc/shadow`
- `/etc/smsd.conf`
- `/etc/sysconfig/network-scripts`
- `/tmp/test`
- `/tmp/test_1774464627`
- `/var/log/smsd.log`
- `/var/qmux_connect`
- `/var/spool/sms`

### Extracted URLs

- `https://31.57.216.121/sh`

---

## Top Attack Patterns (SSH)

- [152x] `$f" 2>/dev/null`
- [152x] `echo 0`
- [152x] `echo 1`
- [78x] `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH`
- [78x] `uname -s -v -n -m 2>/dev/null`
- [78x] `uname -m 2>/dev/null`
- [78x] `cat /proc/uptime 2>/dev/null`
- [78x] `nproc 2>/dev/null`
- [78x] `/usr/bin/nproc 2>/dev/null`
- [78x] `grep -c "^processor" /proc/cpuinfo 2>/dev/null`
- [78x] `cpu_model=$( (grep -m1 -E "model name`
- [78x] `Hardware" /proc/cpuinfo`
- [78x] `lscpu 2>/dev/null`
- [78x] `dmidecode -s processor-version 2>/dev/null`
- [78x] `uname -p 2>/dev/null`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 5 | `sigma/*.yml` |
| YARA (Payload) | 4 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 318 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*