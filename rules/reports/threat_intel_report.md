# Threat Intelligence Report

**Generated**: 2026-06-11 14:10 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,021 events** from **565 unique source IPs** across **32 countries** and **46 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 21 |
| Unique Attacker IPs | 565 |
| Atomic Attack Patterns | 1990 |
| MITRE ATT&CK Techniques | 6 |
| Generated Sigma Rules | 4 |
| Generated YARA Rules | 3 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 504 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 900 |
| T1105 (Ingress Tool Transfer) | | 136 |
| T1059.004 (Unix Shell) | | 89 |
| T1033 (System Owner/User Discovery) | | 58 |
| T1057 (Process Discovery) | | 38 |
| T1053.003 (Cron) | | 19 |

### Tactics Distribution

- **discovery**: 996 events ████████████████████████████████████████
- **command_and_control**: 136 events ████████████████████████████████████████
- **execution**: 89 events ████████████████████████████████████████
- **persistence**: 19 events █████████

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| The Netherlands | 10,966 |
| France | 6,508 |
| United States | 5,076 |
| China | 2,344 |
| Romania | 1,601 |
| Bulgaria | 1,030 |
| Taiwan | 661 |
| Pakistan | 631 |
| Singapore | 531 |
| Germany | 424 |
| United Kingdom | 328 |
| Hong Kong | 306 |
| Belgium | 230 |
| Luxembourg | 204 |
| Russia | 184 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Pfcloud UG (haftungsbeschrankt) | 10,690 |
| Modat B.V. | 5,925 |
| Media Sat Srl | 1,585 |
| Chinanet | 1,582 |
| Google LLC | 1,395 |
| ONYPHE SAS | 1,220 |
| LLC Vash Kredit Bank | 928 |
| Vpsvault.host Ltd | 819 |
| Amazon.com, Inc. | 746 |
| Alibaba (US) Technology Co., Ltd. | 674 |
| Feo Prest SRL | 654 |
| DigitalOcean, LLC | 607 |
| Censys, Inc. | 514 |
| UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED | 454 |
| Microsoft Corporation | 353 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `45.153.34.235` | 10,525 | Attacker |
| `86.107.235.218` | 1,585 | Attacker |
| `218.67.82.174` | 1,479 | Attacker |
| `85.217.140.47` | 749 | Attacker |
| `213.209.159.115` | 653 | Attacker |
| `85.11.167.11` | 507 | Attacker |
| `85.217.140.16` | 498 | Attacker |
| `85.217.140.10` | 413 | Attacker |
| `188.166.223.76` | 384 | Attacker |
| `45.198.224.18` | 372 | Attacker |
| `85.11.167.7` | 371 | Attacker |
| `85.217.140.19` | 352 | Attacker |
| `85.217.140.30` | 317 | Attacker |
| `85.217.140.28` | 258 | Attacker |
| `85.217.140.41` | 246 | Attacker |
| `85.217.140.42` | 234 | Attacker |
| `85.217.140.38` | 207 | Attacker |
| `85.217.140.13` | 203 | Attacker |
| `85.217.140.43` | 184 | Attacker |
| `60.23.234.61` | 183 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 565 |
| URLs | 0 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 38 |

### Targeted File Paths

- `/tmp/.`
- `/tmp/FDQFSWqU`
- `/tmp/WXokeHMD`
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
- `/tmp/rFsjWJKC`
- `/tmp/uQKhLBsT`
- `/tmp/zJICTzVj`
- `/var/tmp`
- `/var/tmp/.`

---

## Top Attack Patterns (SSH)

- [230x] `lspci`
- [171x] `nvidia-smi -q`
- [171x] `grep "Product Name`
- [157x] `egrep VGA`
- [86x] `curl ipinfo.io/org`
- [84x] `grep Radeon`
- [81x] `lscpu`
- [81x] `egrep "Model name:`
- [79x] `uname -n`
- [76x] `xargs rm -f 2>/dev/null`
- [75x] `uname -r`
- [73x] `grep 3D`
- [69x] `uname -s -v -n -r -m`
- [66x] `uptime`
- [66x] `grep -ohe 'up .*`

## Top Attack Patterns (HTTP)

| URI | Hits | Category |
|-----|------|----------|
| `/SDK/webLanguage` | 21 | Web Scan |

### HTTP Methods

- **GET**: 157
- **PROPFIND**: 5
- **HEAD**: 2
- **POST**: 2
- **CONNECT**: 1

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 4 | `sigma/*.yml` |
| YARA (Payload) | 3 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 504 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*