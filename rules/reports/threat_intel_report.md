# Threat Intelligence Report

**Generated**: 2026-06-11 20:10 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **11 events** from **562 unique source IPs** across **32 countries** and **44 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 0 |
| HTTP Events (Galah) | 11 |
| Unique Attacker IPs | 562 |
| Atomic Attack Patterns | 0 |
| MITRE ATT&CK Techniques | 0 |
| Generated Sigma Rules | 0 |
| Generated YARA Rules | 0 |
| Generated Suricata Rules | 1 |
| Blocked IPs (Firewall) | 506 |

---

## MITRE ATT&CK Mapping

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| The Netherlands | 11,027 |
| France | 6,257 |
| United States | 5,600 |
| Bulgaria | 3,869 |
| Romania | 1,929 |
| China | 1,549 |
| Pakistan | 716 |
| Singapore | 619 |
| United Kingdom | 414 |
| Hong Kong | 393 |
| Germany | 389 |
| Belgium | 233 |
| Portugal | 191 |
| Russia | 176 |
| Poland | 158 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Pfcloud UG (haftungsbeschrankt) | 10,686 |
| Modat B.V. | 5,616 |
| LLC Vash Kredit Bank | 3,767 |
| Google LLC | 1,795 |
| Media Sat Srl | 1,598 |
| ONYPHE SAS | 1,258 |
| Amazon.com, Inc. | 897 |
| Chinanet | 791 |
| Alibaba (US) Technology Co., Ltd. | 744 |
| DigitalOcean, LLC | 733 |
| Vpsvault.host Ltd | 703 |
| UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED | 607 |
| Censys, Inc. | 520 |
| CHINA UNICOM China169 Backbone | 473 |
| Microsoft Corporation | 369 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `45.153.34.235` | 10,525 | Attacker |
| `91.92.42.19` | 2,590 | Attacker |
| `86.107.235.218` | 1,598 | Attacker |
| `85.217.140.3` | 776 | Attacker |
| `218.67.82.174` | 700 | Attacker |
| `85.217.140.47` | 683 | Attacker |
| `85.11.167.11` | 667 | Attacker |
| `85.217.140.48` | 577 | Attacker |
| `85.11.167.7` | 457 | Attacker |
| `85.217.140.41` | 438 | Attacker |
| `188.166.223.76` | 379 | Attacker |
| `45.198.224.18` | 379 | Attacker |
| `85.217.140.16` | 377 | Attacker |
| `85.217.140.51` | 370 | Attacker |
| `80.94.95.34` | 255 | Attacker |
| `85.217.140.28` | 248 | Attacker |
| `85.217.140.42` | 220 | Attacker |
| `85.217.140.34` | 216 | Attacker |
| `85.217.140.38` | 207 | Attacker |
| `60.23.234.61` | 183 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 562 |
| URLs | 0 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 0 |

---

## Top Attack Patterns (SSH)


## Top Attack Patterns (HTTP)

| URI | Hits | Category |
|-----|------|----------|
| `/SDK/webLanguage` | 11 | Web Scan |

### HTTP Methods

- **GET**: 150
- **PROPFIND**: 5
- **CONNECT**: 1

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 0 | `sigma/*.yml` |
| YARA (Payload) | 0 | `yara/*.yar` |
| Suricata (IDS/IPS) | 1 | `suricata/honeypot.rules` |
| Firewall (iptables) | 506 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*