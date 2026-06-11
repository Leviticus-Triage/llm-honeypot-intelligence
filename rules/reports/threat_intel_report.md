# Threat Intelligence Report

**Generated**: 2026-06-11 08:09 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,035 events** from **566 unique source IPs** across **32 countries** and **48 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 35 |
| Unique Attacker IPs | 566 |
| Atomic Attack Patterns | 1922 |
| MITRE ATT&CK Techniques | 9 |
| Generated Sigma Rules | 5 |
| Generated YARA Rules | 4 |
| Generated Suricata Rules | 31 |
| Blocked IPs (Firewall) | 503 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 821 |
| T1105 (Ingress Tool Transfer) | | 125 |
| T1059.004 (Unix Shell) | | 95 |
| T1033 (System Owner/User Discovery) | | 69 |
| T1057 (Process Discovery) | | 40 |
| T1053.003 (Cron) | | 18 |
| T1552.001 (Credentials In Files) | | 6 |
| T1016 (System Network Configuration Discovery) | | 6 |
| T1543.002 (Systemd Service) | | 3 |

### Tactics Distribution

- **discovery**: 936 events ████████████████████████████████████████
- **command_and_control**: 125 events ████████████████████████████████████████
- **execution**: 95 events ████████████████████████████████████████
- **persistence**: 21 events ██████████
- **credential_access**: 6 events ███

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| The Netherlands | 10,916 |
| United States | 6,721 |
| France | 5,802 |
| Taiwan | 2,358 |
| China | 1,677 |
| Romania | 1,289 |
| Bulgaria | 1,209 |
| Pakistan | 536 |
| Singapore | 483 |
| Germany | 442 |
| Belgium | 300 |
| Hong Kong | 294 |
| Luxembourg | 226 |
| United Kingdom | 217 |
| Russia | 198 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Pfcloud UG (haftungsbeschrankt) | 10,689 |
| Modat B.V. | 5,246 |
| Feo Prest SRL | 2,351 |
| ReliableSite.Net LLC | 1,911 |
| Media Sat Srl | 1,279 |
| Google LLC | 1,198 |
| ONYPHE SAS | 1,140 |
| LLC Vash Kredit Bank | 1,111 |
| Chinanet | 877 |
| Vpsvault.host Ltd | 817 |
| Amazon.com, Inc. | 731 |
| Alibaba (US) Technology Co., Ltd. | 656 |
| DigitalOcean, LLC | 528 |
| Censys, Inc. | 517 |
| Cyber Internet Services (Pvt) Ltd. | 404 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `45.153.34.235` | 10,525 | Attacker |
| `213.209.159.115` | 2,350 | Attacker |
| `86.107.235.218` | 1,279 | Attacker |
| `185.150.191.236` | 944 | Attacker |
| `104.243.35.94` | 898 | Attacker |
| `218.67.82.174` | 779 | Attacker |
| `85.11.167.11` | 686 | Attacker |
| `85.217.140.42` | 511 | Attacker |
| `85.217.140.16` | 498 | Attacker |
| `85.217.140.10` | 432 | Attacker |
| `85.217.140.39` | 411 | Attacker |
| `85.11.167.7` | 375 | Attacker |
| `45.198.224.18` | 362 | Attacker |
| `85.217.140.19` | 359 | Attacker |
| `188.166.223.76` | 327 | Attacker |
| `85.217.140.13` | 321 | Attacker |
| `85.217.140.43` | 272 | Attacker |
| `85.217.140.5` | 227 | Attacker |
| `85.217.140.38` | 189 | Attacker |
| `60.23.234.61` | 183 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 566 |
| URLs | 0 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 43 |

### Targeted File Paths

- `/etc/netplan`
- `/etc/network/interfaces`
- `/etc/passwd`
- `/etc/shadow`
- `/etc/sysconfig/network-scripts`
- `/tmp/.`
- `/tmp/AQmZULGJ`
- `/tmp/FDQFSWqU`
- `/tmp/WYapxxyu`
- `/tmp/XUAcnsJa`
- `/tmp/ZHqZKpXP`
- `/tmp/ZnwuAQGi`
- `/tmp/bnvNKYGu`
- `/tmp/cache`
- `/tmp/cjWesWdE`
- `/tmp/d.log`
- `/tmp/fMODHgdf`
- `/tmp/fZaoNBwM`
- `/tmp/fulgDKwU`
- `/tmp/isAjkxaK`

---

## Top Attack Patterns (SSH)

- [216x] `lspci`
- [160x] `nvidia-smi -q`
- [160x] `grep "Product Name`
- [147x] `egrep VGA`
- [81x] `curl ipinfo.io/org`
- [78x] `grep Radeon`
- [76x] `uname -n`
- [76x] `lscpu`
- [76x] `egrep "Model name:`
- [75x] `uname -r`
- [72x] `xargs rm -f 2>/dev/null`
- [69x] `grep 3D`
- [58x] `nproc`
- [54x] `uptime`
- [54x] `kill -9 $pid 2>/dev/null`

## Top Attack Patterns (HTTP)

| URI | Hits | Category |
|-----|------|----------|
| `/SDK/webLanguage` | 35 | Web Scan |

### HTTP Methods

- **GET**: 170
- **PROPFIND**: 6
- **HEAD**: 2
- **POST**: 2
- **CONNECT**: 1

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 5 | `sigma/*.yml` |
| YARA (Payload) | 4 | `yara/*.yar` |
| Suricata (IDS/IPS) | 31 | `suricata/honeypot.rules` |
| Firewall (iptables) | 503 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*