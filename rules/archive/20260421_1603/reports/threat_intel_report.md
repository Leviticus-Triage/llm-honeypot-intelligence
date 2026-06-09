# Threat Intelligence Report

**Generated**: 2026-04-21 16:03 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,000 events** from **552 unique source IPs** across **32 countries** and **44 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 552 |
| Atomic Attack Patterns | 1000 |
| MITRE ATT&CK Techniques | 1 |
| Generated Sigma Rules | 1 |
| Generated YARA Rules | 1 |
| Generated Suricata Rules | 4 |
| Blocked IPs (Firewall) | 500 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 1000 |

### Tactics Distribution

- **discovery**: 1000 events ████████████████████████████████████████

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 23,195 |
| Luxembourg | 9,066 |
| Germany | 5,427 |
| India | 2,685 |
| France | 2,300 |
| Netherlands | 2,258 |
| Australia | 1,915 |
| Mexico | 1,902 |
| United Kingdom | 1,319 |
| Poland | 1,290 |
| Bulgaria | 1,189 |
| Romania | 320 |
| China | 291 |
| Pakistan | 280 |
| Russia | 262 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| ReliableSite.Net LLC | 18,408 |
| Offshore LC | 9,064 |
| DigitalOcean, LLC | 8,733 |
| Hydra Communications Ltd | 2,227 |
| Sierra Madre Internet SA de CV | 1,849 |
| OVH SAS | 1,553 |
| Pfcloud UG (haftungsbeschrankt) | 1,442 |
| ISAEV Igor | 1,270 |
| ColocaTel Inc. | 1,141 |
| Amazon.com, Inc. | 1,075 |
| Google LLC | 1,010 |
| ONYPHE SAS | 980 |
| Alibaba US Technology Co., Ltd. | 697 |
| Censys, Inc. | 543 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 487 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `176.65.139.103` | 9,062 | Attacker |
| `104.243.32.126` | 4,833 | Attacker |
| `104.243.35.94` | 3,257 | Attacker |
| `104.243.35.92` | 2,273 | Attacker |
| `104.243.32.235` | 2,015 | Attacker |
| `177.125.137.18` | 1,849 | Attacker |
| `51.68.207.118` | 1,549 | Attacker |
| `104.243.43.7` | 1,499 | Attacker |
| `45.156.87.99` | 1,370 | Attacker |
| `165.227.156.190` | 1,266 | Attacker |
| `209.38.95.158` | 1,266 | Attacker |
| `87.251.64.159` | 1,265 | Attacker |
| `64.227.186.247` | 1,263 | Attacker |
| `68.183.77.93` | 1,263 | Attacker |
| `142.93.222.251` | 1,261 | Attacker |
| `167.172.175.156` | 1,260 | Attacker |
| `206.221.176.60` | 1,260 | Attacker |
| `85.11.167.11` | 1,092 | Attacker |
| `104.243.34.165` | 1,088 | Attacker |
| `170.64.177.137` | 643 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 552 |
| URLs | 0 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 0 |

---

## Top Attack Patterns (SSH)

- [479x] `uname -m`
- [471x] `uname -s -v -n -r -m`
- [36x] `uname -a`
- [13x] `/bin/./uname -s -v -n -r -m`
- [1x] `uname -s -m`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 1 | `sigma/*.yml` |
| YARA (Payload) | 1 | `yara/*.yar` |
| Suricata (IDS/IPS) | 4 | `suricata/honeypot.rules` |
| Firewall (iptables) | 500 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*