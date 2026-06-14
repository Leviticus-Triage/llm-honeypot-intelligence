# Threat Intelligence Report

**Generated**: 2026-06-14 08:04 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **388 events** from **574 unique source IPs** across **33 countries** and **46 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 388 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 574 |
| Atomic Attack Patterns | 2881 |
| MITRE ATT&CK Techniques | 5 |
| Generated Sigma Rules | 3 |
| Generated YARA Rules | 2 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 499 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 1854 |
| T1059.004 (Unix Shell) | | 817 |
| T1033 (System Owner/User Discovery) | | 162 |
| T1057 (Process Discovery) | | 4 |
| T1105 (Ingress Tool Transfer) | | 4 |

### Tactics Distribution

- **discovery**: 2020 events ████████████████████████████████████████
- **execution**: 817 events ████████████████████████████████████████
- **command_and_control**: 4 events ██

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 23,289 |
| Bulgaria | 13,362 |
| France | 5,652 |
| Taiwan | 4,235 |
| Germany | 2,975 |
| Finland | 1,447 |
| Pakistan | 637 |
| The Netherlands | 629 |
| United Kingdom | 578 |
| China | 331 |
| Belgium | 310 |
| Russia | 232 |
| Portugal | 187 |
| Hong Kong | 168 |
| Seychelles | 160 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| ReliableSite.Net LLC | 17,879 |
| FOP Dmytro Nedilskyi | 11,181 |
| Modat B.V. | 5,432 |
| Feo Prest SRL | 4,226 |
| Google LLC | 3,547 |
| WIIT AG | 2,189 |
| Mitko.Com Ltd. | 1,424 |
| DigitalOcean, LLC | 938 |
| Amazon.com, Inc. | 800 |
| Vpsvault.host Ltd | 664 |
| LLC Vash Kredit Bank | 655 |
| UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED | 582 |
| Alibaba (US) Technology Co., Ltd. | 502 |
| Censys, Inc. | 481 |
| Microsoft Corporation | 379 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `104.243.35.104` | 4,900 | Attacker |
| `213.209.159.115` | 4,226 | Attacker |
| `104.243.32.126` | 3,376 | Attacker |
| `104.243.32.235` | 2,561 | Attacker |
| `104.243.43.7` | 2,493 | Attacker |
| `104.243.35.94` | 2,333 | Attacker |
| `85.14.245.122` | 2,189 | Attacker |
| `34.88.9.230` | 1,443 | Attacker |
| `194.169.90.34` | 1,424 | Attacker |
| `85.217.140.32` | 1,200 | Attacker |
| `194.113.39.10` | 1,134 | Attacker |
| `194.113.39.14` | 1,127 | Attacker |
| `194.113.39.18` | 1,125 | Attacker |
| `194.113.39.26` | 1,124 | Attacker |
| `194.113.39.38` | 1,124 | Attacker |
| `194.113.39.30` | 1,123 | Attacker |
| `194.113.39.34` | 1,121 | Attacker |
| `194.113.39.22` | 1,119 | Attacker |
| `194.113.39.6` | 1,116 | Attacker |
| `194.113.39.2` | 1,068 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 573 |
| URLs | 0 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 1 |

### Targeted File Paths

- `/etc/os-release`

---

## Top Attack Patterns (SSH)

- [102x] `lspci`
- [85x] `uname -m 2>/dev/null`
- [85x] `nproc 2>/dev/null`
- [81x] `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH`
- [81x] `uname -s -v -n -m 2>/dev/null`
- [81x] `cat /proc/uptime 2>/dev/null`
- [81x] `/usr/bin/nproc 2>/dev/null`
- [81x] `grep -c "^processor" /proc/cpuinfo 2>/dev/null`
- [81x] `cpu_model=$( (grep -m1 -E "model name`
- [81x] `Hardware" /proc/cpuinfo`
- [81x] `lscpu 2>/dev/null`
- [81x] `dmidecode -s processor-version 2>/dev/null`
- [81x] `uname -p 2>/dev/null`
- [81x] `gpu_info=$( (lspci 2>/dev/null`
- [81x] `grep -i vga`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 3 | `sigma/*.yml` |
| YARA (Payload) | 2 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 499 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*