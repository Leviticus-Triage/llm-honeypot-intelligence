# Threat Intelligence Report

**Generated**: 2026-06-11 02:09 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,043 events** from **570 unique source IPs** across **32 countries** and **48 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 43 |
| Unique Attacker IPs | 570 |
| Atomic Attack Patterns | 2028 |
| MITRE ATT&CK Techniques | 9 |
| Generated Sigma Rules | 5 |
| Generated YARA Rules | 4 |
| Generated Suricata Rules | 31 |
| Blocked IPs (Firewall) | 503 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 750 |
| T1059.004 (Unix Shell) | | 175 |
| T1105 (Ingress Tool Transfer) | | 158 |
| T1033 (System Owner/User Discovery) | | 111 |
| T1057 (Process Discovery) | | 68 |
| T1053.003 (Cron) | | 32 |
| T1552.001 (Credentials In Files) | | 6 |
| T1016 (System Network Configuration Discovery) | | 6 |
| T1543.002 (Systemd Service) | | 3 |

### Tactics Distribution

- **discovery**: 935 events ████████████████████████████████████████
- **execution**: 175 events ████████████████████████████████████████
- **command_and_control**: 158 events ████████████████████████████████████████
- **persistence**: 35 events █████████████████
- **credential_access**: 6 events ███

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| Germany | 11,168 |
| United States | 7,461 |
| The Netherlands | 7,198 |
| France | 5,933 |
| Taiwan | 2,959 |
| China | 1,491 |
| Bulgaria | 1,321 |
| Romania | 458 |
| Singapore | 442 |
| Pakistan | 278 |
| Luxembourg | 237 |
| Belgium | 234 |
| Russia | 205 |
| United Kingdom | 190 |
| Hong Kong | 167 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Pfcloud UG (haftungsbeschrankt) | 17,662 |
| Modat B.V. | 5,419 |
| Feo Prest SRL | 2,954 |
| ReliableSite.Net LLC | 2,815 |
| LLC Vash Kredit Bank | 1,228 |
| ONYPHE SAS | 1,106 |
| Google LLC | 963 |
| Chinanet | 872 |
| Vpsvault.host Ltd | 785 |
| Amazon.com, Inc. | 742 |
| Alibaba (US) Technology Co., Ltd. | 592 |
| DigitalOcean, LLC | 571 |
| Censys, Inc. | 479 |
| Media Sat Srl | 444 |
| Microsoft Corporation | 351 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `176.65.132.129` | 10,708 | Attacker |
| `45.153.34.235` | 6,794 | Attacker |
| `213.209.159.115` | 2,953 | Attacker |
| `185.150.191.236` | 944 | Attacker |
| `104.243.43.7` | 900 | Attacker |
| `104.243.35.94` | 898 | Attacker |
| `85.11.167.11` | 860 | Attacker |
| `218.67.82.174` | 779 | Attacker |
| `85.217.140.42` | 511 | Attacker |
| `85.217.140.16` | 498 | Attacker |
| `85.217.140.10` | 457 | Attacker |
| `86.107.235.218` | 444 | Attacker |
| `85.217.140.39` | 411 | Attacker |
| `85.217.140.19` | 359 | Attacker |
| `45.198.224.18` | 348 | Attacker |
| `85.217.140.13` | 321 | Attacker |
| `85.11.167.7` | 314 | Attacker |
| `188.166.223.76` | 306 | Attacker |
| `85.217.140.43` | 294 | Attacker |
| `85.217.140.5` | 268 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 570 |
| URLs | 0 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 79 |

### Targeted File Paths

- `/etc/netplan`
- `/etc/network/interfaces`
- `/etc/passwd`
- `/etc/shadow`
- `/etc/sysconfig/network-scripts`
- `/tmp/.`
- `/tmp/AQmZULGJ`
- `/tmp/LijMNGmc`
- `/tmp/OmCCGYFf`
- `/tmp/QKpRzdfK`
- `/tmp/QxdtihDT`
- `/tmp/SzviIgNp`
- `/tmp/TiRkqsNn`
- `/tmp/UFhAUzbP`
- `/tmp/XPrKPXZl`
- `/tmp/ZZvOKcrk`
- `/tmp/aUsfEEVb`
- `/tmp/cHRzStnQ`
- `/tmp/cache`
- `/tmp/ckVUlPbQ`

---

## Top Attack Patterns (SSH)

- [182x] `lspci`
- [128x] `xargs rm -f 2>/dev/null`
- [121x] `egrep VGA`
- [121x] `nvidia-smi -q`
- [121x] `grep "Product Name`
- [96x] `kill -9 $pid 2>/dev/null`
- [67x] `ps aux`
- [64x] `uptime`
- [64x] `$11 !~ /sshd/ {print $2}`
- [63x] `uname -r`
- [61x] `uname -m`
- [61x] `lscpu`
- [61x] `egrep "Model name:`
- [61x] `uname -s -v -n -r -m`
- [61x] `grep -ohe 'up .*`

## Top Attack Patterns (HTTP)

| URI | Hits | Category |
|-----|------|----------|
| `/SDK/webLanguage` | 43 | Web Scan |

### HTTP Methods

- **GET**: 179
- **PROPFIND**: 6
- **HEAD**: 3
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