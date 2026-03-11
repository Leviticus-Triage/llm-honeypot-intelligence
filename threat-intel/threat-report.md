# Threat Intelligence Report

**Generated**: 2026-03-02 07:40 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,002 events** from **511 unique source IPs** across **33 countries** and **36 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 2 |
| Unique Attacker IPs | 511 |
| Atomic Attack Patterns | 1971 |
| MITRE ATT&CK Techniques | 6 |
| Generated Sigma Rules | 5 |
| Generated YARA Rules | 4 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 214 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 1039 |
| T1105 (Ingress Tool Transfer) | | 119 |
| T1059.004 (Unix Shell) | | 117 |
| T1033 (System Owner/User Discovery) | | 45 |
| T1057 (Process Discovery) | | 22 |
| T1053.003 (Cron) | | 11 |

### Tactics Distribution

- **discovery**: 1106 events ████████████████████████████████████████
- **command_and_control**: 119 events ████████████████████████████████████████
- **execution**: 117 events ████████████████████████████████████████
- **persistence**: 11 events █████

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| Australia | 39,660 |
| Romania | 5,802 |
| United States | 1,834 |
| Germany | 1,096 |
| Netherlands | 685 |
| Brazil | 551 |
| Singapore | 428 |
| United Kingdom | 342 |
| Switzerland | 305 |
| Canada | 170 |
| India | 108 |
| China | 55 |
| Portugal | 52 |
| Russia | 46 |
| France | 44 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| DigitalOcean, LLC | 42,740 |
| Unmanaged Ltd | 5,662 |
| BR.Digital Telecom | 537 |
| Google LLC | 402 |
| Private Layer INC | 305 |
| Amazon.com, Inc. | 249 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 153 |
| SS-Net | 140 |
| Hurricane Electric LLC | 132 |
| Akamai Connected Cloud | 115 |
| Vpsvault.host Ltd | 112 |
| Censys, Inc. | 110 |
| ONYPHE SAS | 83 |
| Microsoft Corporation | 74 |
| IP Volume inc | 43 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `209.38.90.100` | 39,615 | Attacker |
| `80.94.93.5` | 5,639 | Attacker |
| `64.227.122.184` | 642 | Attacker |
| `68.183.13.228` | 561 | Attacker |
| `200.143.111.222` | 537 | Attacker |
| `64.225.109.41` | 348 | Attacker |
| `46.19.137.194` | 305 | Attacker |
| `162.243.107.122` | 281 | Attacker |
| `159.223.73.165` | 197 | Attacker |
| `167.71.193.206` | 185 | Attacker |
| `138.197.159.252` | 150 | Attacker |
| `80.94.95.238` | 140 | Attacker |
| `178.128.168.2` | 131 | Attacker |
| `45.205.1.5` | 112 | Attacker |
| `129.212.184.91` | 95 | Attacker |
| `192.81.129.77` | 78 | Attacker |
| `18.116.101.220` | 72 | Attacker |
| `138.68.135.125` | 68 | Attacker |
| `167.71.239.88` | 63 | Attacker |
| `3.129.187.38` | 63 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 511 |
| URLs | 0 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 37 |

### Targeted File Paths

- `/.env.development`
- `/tmp/.`
- `/tmp/JEhfkQaw`
- `/tmp/LYWReJFh`
- `/tmp/PlZQJNQz`
- `/tmp/QcYboytJ`
- `/tmp/XkuxolTk`
- `/tmp/aWNDudBJ`
- `/tmp/afwlZnfp`
- `/tmp/bMqovOUy`
- `/tmp/cCgroCyR`
- `/tmp/cache`
- `/tmp/d.log`
- `/tmp/iJFdXVzH`
- `/tmp/nNqBeDpX`
- `/tmp/nrhixWZc`
- `/tmp/uBJTtvJJ`
- `/tmp/upBYvzPB`
- `/tmp/vowsGiID`
- `/var/tmp`

---

## Top Attack Patterns (SSH)

- [214x] `lspci`
- [143x] `nvidia-smi -q`
- [143x] `grep "Product Name`
- [142x] `egrep VGA`
- [139x] `uname -m`
- [75x] `uname -s -v -n -r -m`
- [73x] `uptime`
- [73x] `grep -ohe 'up .*`
- [72x] `curl ipinfo.io/org`
- [72x] `grep 3D`
- [72x] `lscpu`
- [72x] `egrep "Model name:`
- [72x] `nproc`
- [70x] `grep Radeon`
- [69x] `uname -r`

## Top Attack Patterns (HTTP)

| URI | Hits | Category |
|-----|------|----------|
| `/.env.development` | 1 | Config Theft |
| `/www/.env.prod` | 1 | Config Theft |

### HTTP Methods

- **GET**: 28
- **PROPFIND**: 1

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 5 | `sigma/*.yml` |
| YARA (Payload) | 4 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 214 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*