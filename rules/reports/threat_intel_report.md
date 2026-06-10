# Threat Intelligence Report

**Generated**: 2026-06-10 06:05 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,006 events** from **532 unique source IPs** across **30 countries** and **38 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 6 |
| Unique Attacker IPs | 532 |
| Atomic Attack Patterns | 2196 |
| MITRE ATT&CK Techniques | 6 |
| Generated Sigma Rules | 4 |
| Generated YARA Rules | 3 |
| Generated Suricata Rules | 31 |
| Blocked IPs (Firewall) | 393 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 820 |
| T1059.004 (Unix Shell) | | 189 |
| T1105 (Ingress Tool Transfer) | | 172 |
| T1033 (System Owner/User Discovery) | | 117 |
| T1057 (Process Discovery) | | 78 |
| T1053.003 (Cron) | | 39 |

### Tactics Distribution

- **discovery**: 1015 events ████████████████████████████████████████
- **execution**: 189 events ████████████████████████████████████████
- **command_and_control**: 172 events ████████████████████████████████████████
- **persistence**: 39 events ███████████████████

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| Bulgaria | 8,745 |
| United States | 4,201 |
| France | 529 |
| China | 516 |
| Pakistan | 379 |
| United Kingdom | 226 |
| The Netherlands | 185 |
| Singapore | 183 |
| Germany | 177 |
| Luxembourg | 177 |
| India | 135 |
| Hong Kong | 84 |
| Japan | 82 |
| Malaysia | 57 |
| Portugal | 44 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| LLC Vash Kredit Bank | 8,610 |
| ReliableSite.Net LLC | 1,707 |
| Google LLC | 626 |
| ONYPHE SAS | 535 |
| CHINA UNICOM China169 Backbone | 366 |
| Alibaba (US) Technology Co., Ltd. | 323 |
| Vpsvault.host Ltd | 298 |
| DigitalOcean, LLC | 295 |
| Amazon.com, Inc. | 288 |
| Modat B.V. | 286 |
| Censys, Inc. | 239 |
| UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED | 227 |
| Microsoft Corporation | 198 |
| Offshore LC | 176 |
| Akamai Connected Cloud | 149 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `91.92.42.227` | 7,764 | Attacker |
| `104.243.43.7` | 1,018 | Attacker |
| `85.11.167.11` | 665 | Attacker |
| `175.149.183.33` | 323 | Attacker |
| `185.150.191.236` | 321 | Attacker |
| `45.198.224.18` | 162 | Attacker |
| `85.11.167.7` | 160 | Attacker |
| `176.65.139.41` | 154 | Attacker |
| `139.135.59.149` | 136 | Attacker |
| `188.166.223.76` | 136 | Attacker |
| `103.248.94.15` | 118 | Attacker |
| `104.243.35.104` | 118 | Attacker |
| `103.74.20.164` | 117 | Attacker |
| `223.123.38.125` | 117 | Attacker |
| `85.217.140.37` | 100 | Attacker |
| `66.228.43.62` | 78 | Attacker |
| `198.46.134.48` | 70 | Attacker |
| `104.243.35.94` | 69 | Attacker |
| `94.156.152.234` | 67 | Attacker |
| `45.205.1.5` | 62 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 532 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 74 |

### Targeted File Paths

- `/tmp/.`
- `/tmp/BNJlmgJt`
- `/tmp/BUQpxVoz`
- `/tmp/ERULxxVH`
- `/tmp/EudxNXcS`
- `/tmp/HPhlkviJ`
- `/tmp/HwCXCjiW`
- `/tmp/ICBGCYCR`
- `/tmp/LWaDdmKD`
- `/tmp/MqmuOTsZ`
- `/tmp/NCXUNYAO`
- `/tmp/ODERQJus`
- `/tmp/QVNgdjAP`
- `/tmp/RkwJoufT`
- `/tmp/SOlDtuIq`
- `/tmp/VPSiCabe`
- `/tmp/WQrCjTYA`
- `/tmp/WnqGShwL`
- `/tmp/YEssrtBj`
- `/tmp/ZpRQCSfY`

### Extracted URLs

- `https://80.27.83.195/sh`

---

## Top Attack Patterns (SSH)

- [201x] `lspci`
- [156x] `xargs rm -f 2>/dev/null`
- [132x] `egrep VGA`
- [130x] `nvidia-smi -q`
- [130x] `grep "Product Name`
- [117x] `kill -9 $pid 2>/dev/null`
- [78x] `ps aux`
- [78x] `$11 !~ /sshd/ {print $2}`
- [75x] `uname -s -v -n -r -m`
- [74x] `uptime`
- [74x] `grep -ohe 'up .*`
- [72x] `uname -m`
- [71x] `nproc`
- [70x] `lscpu`
- [70x] `egrep "Model name:`

## Top Attack Patterns (HTTP)

| URI | Hits | Category |
|-----|------|----------|
| `/SDK/webLanguage` | 6 | Web Scan |

### HTTP Methods

- **GET**: 64
- **PROPFIND**: 3

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 4 | `sigma/*.yml` |
| YARA (Payload) | 3 | `yara/*.yar` |
| Suricata (IDS/IPS) | 31 | `suricata/honeypot.rules` |
| Firewall (iptables) | 393 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*