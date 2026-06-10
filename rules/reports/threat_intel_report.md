# Threat Intelligence Report

**Generated**: 2026-06-10 15:23 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,025 events** from **561 unique source IPs** across **32 countries** and **47 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 25 |
| Unique Attacker IPs | 561 |
| Atomic Attack Patterns | 2109 |
| MITRE ATT&CK Techniques | 9 |
| Generated Sigma Rules | 5 |
| Generated YARA Rules | 4 |
| Generated Suricata Rules | 31 |
| Blocked IPs (Firewall) | 499 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 775 |
| T1059.004 (Unix Shell) | | 183 |
| T1105 (Ingress Tool Transfer) | | 161 |
| T1033 (System Owner/User Discovery) | | 118 |
| T1057 (Process Discovery) | | 74 |
| T1053.003 (Cron) | | 36 |
| T1016 (System Network Configuration Discovery) | | 4 |
| T1552.001 (Credentials In Files) | | 4 |
| T1543.002 (Systemd Service) | | 2 |

### Tactics Distribution

- **discovery**: 971 events ████████████████████████████████████████
- **execution**: 183 events ████████████████████████████████████████
- **command_and_control**: 161 events ████████████████████████████████████████
- **persistence**: 38 events ███████████████████
- **credential_access**: 4 events ██

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| Germany | 11,082 |
| Bulgaria | 9,229 |
| United States | 7,941 |
| France | 3,638 |
| Taiwan | 2,811 |
| China | 775 |
| Pakistan | 594 |
| Singapore | 350 |
| The Netherlands | 341 |
| United Kingdom | 268 |
| Belgium | 234 |
| Luxembourg | 230 |
| India | 148 |
| Japan | 143 |
| Hong Kong | 133 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Pfcloud UG (haftungsbeschrankt) | 10,821 |
| LLC Vash Kredit Bank | 9,063 |
| ReliableSite.Net LLC | 3,614 |
| Modat B.V. | 3,200 |
| Feo Prest SRL | 2,801 |
| Google LLC | 992 |
| ONYPHE SAS | 934 |
| Amazon.com, Inc. | 665 |
| Vpsvault.host Ltd | 618 |
| Alibaba (US) Technology Co., Ltd. | 560 |
| DigitalOcean, LLC | 547 |
| Censys, Inc. | 409 |
| CHINA UNICOM China169 Backbone | 392 |
| Cyber Internet Services (Pvt) Ltd. | 351 |
| Microsoft Corporation | 314 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `176.65.132.129` | 10,708 | Attacker |
| `91.92.42.227` | 7,764 | Attacker |
| `213.209.159.115` | 2,801 | Attacker |
| `185.150.191.236` | 1,265 | Attacker |
| `104.243.43.7` | 1,018 | Attacker |
| `104.243.35.94` | 967 | Attacker |
| `85.11.167.11` | 918 | Attacker |
| `85.217.140.39` | 411 | Attacker |
| `85.11.167.7` | 341 | Attacker |
| `175.149.183.33` | 323 | Attacker |
| `85.217.140.42` | 321 | Attacker |
| `85.217.140.13` | 320 | Attacker |
| `45.198.224.18` | 301 | Attacker |
| `188.166.223.76` | 249 | Attacker |
| `85.217.140.43` | 235 | Attacker |
| `85.217.140.37` | 216 | Attacker |
| `85.217.140.5` | 184 | Attacker |
| `176.65.139.41` | 182 | Attacker |
| `85.217.140.30` | 178 | Attacker |
| `85.217.140.12` | 160 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 561 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 78 |

### Targeted File Paths

- `/etc/netplan`
- `/etc/network/interfaces`
- `/etc/passwd`
- `/etc/shadow`
- `/etc/sysconfig/network-scripts`
- `/tmp/.`
- `/tmp/BNJlmgJt`
- `/tmp/BUQpxVoz`
- `/tmp/ERULxxVH`
- `/tmp/EudxNXcS`
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

### Extracted URLs

- `https://80.27.83.195/sh`

---

## Top Attack Patterns (SSH)

- [187x] `lspci`
- [144x] `xargs rm -f 2>/dev/null`
- [123x] `egrep VGA`
- [122x] `nvidia-smi -q`
- [122x] `grep "Product Name`
- [108x] `kill -9 $pid 2>/dev/null`
- [74x] `ps aux`
- [72x] `$11 !~ /sshd/ {print $2}`
- [71x] `uptime`
- [70x] `uname -s -v -n -r -m`
- [69x] `grep -ohe 'up .*`
- [67x] `uname -m`
- [66x] `nproc`
- [64x] `grep 3D`
- [64x] `lscpu`

## Top Attack Patterns (HTTP)

| URI | Hits | Category |
|-----|------|----------|
| `/SDK/webLanguage` | 25 | Web Scan |

### HTTP Methods

- **GET**: 132
- **PROPFIND**: 6
- **POST**: 2
- **HEAD**: 1

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 5 | `sigma/*.yml` |
| YARA (Payload) | 4 | `yara/*.yar` |
| Suricata (IDS/IPS) | 31 | `suricata/honeypot.rules` |
| Firewall (iptables) | 499 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*