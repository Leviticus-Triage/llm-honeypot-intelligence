# Threat Intelligence Report

**Generated**: 2026-06-14 14:58 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,000 events** from **567 unique source IPs** across **35 countries** and **45 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 567 |
| Atomic Attack Patterns | 3874 |
| MITRE ATT&CK Techniques | 6 |
| Generated Sigma Rules | 4 |
| Generated YARA Rules | 3 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 498 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 2289 |
| T1059.004 (Unix Shell) | | 755 |
| T1033 (System Owner/User Discovery) | | 190 |
| T1105 (Ingress Tool Transfer) | | 117 |
| T1057 (Process Discovery) | | 24 |
| T1053.003 (Cron) | | 12 |

### Tactics Distribution

- **discovery**: 2503 events ████████████████████████████████████████
- **execution**: 755 events ████████████████████████████████████████
- **command_and_control**: 117 events ████████████████████████████████████████
- **persistence**: 12 events ██████

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 31,792 |
| Germany | 11,842 |
| Taiwan | 8,623 |
| Bulgaria | 7,592 |
| France | 3,805 |
| Finland | 1,445 |
| Pakistan | 1,058 |
| The Netherlands | 978 |
| United Kingdom | 683 |
| Belgium | 462 |
| China | 284 |
| Russia | 247 |
| Seychelles | 235 |
| Portugal | 199 |
| Hong Kong | 182 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| ReliableSite.Net LLC | 26,445 |
| Pfcloud UG (haftungsbeschrankt) | 9,593 |
| Feo Prest SRL | 8,621 |
| Modat B.V. | 3,641 |
| Google LLC | 3,549 |
| FOP Dmytro Nedilskyi | 3,386 |
| Mitko.Com Ltd. | 3,333 |
| WIIT AG | 2,189 |
| DigitalOcean, LLC | 787 |
| Amazon.com, Inc. | 754 |
| LLC Vash Kredit Bank | 752 |
| Vpsvault.host Ltd | 608 |
| UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED | 576 |
| Alibaba (US) Technology Co., Ltd. | 505 |
| Censys, Inc. | 463 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `176.65.132.22` | 9,200 | Attacker |
| `213.209.159.115` | 8,621 | Attacker |
| `104.243.32.126` | 6,241 | Attacker |
| `104.243.35.104` | 5,768 | Attacker |
| `104.243.43.7` | 4,422 | Attacker |
| `194.169.90.34` | 3,333 | Attacker |
| `104.243.32.235` | 2,561 | Attacker |
| `104.243.35.94` | 2,403 | Attacker |
| `85.14.245.122` | 2,189 | Attacker |
| `206.221.176.60` | 1,820 | Attacker |
| `104.243.35.120` | 1,615 | Attacker |
| `34.88.9.230` | 1,443 | Attacker |
| `85.217.140.16` | 936 | Attacker |
| `185.150.191.236` | 660 | Attacker |
| `209.222.101.194` | 609 | Attacker |
| `85.217.140.37` | 412 | Attacker |
| `85.217.140.11` | 410 | Attacker |
| `67.205.146.126` | 381 | Attacker |
| `85.217.140.28` | 362 | Attacker |
| `85.217.140.6` | 362 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 566 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 35 |

### Targeted File Paths

- `/tmp/.`
- `/tmp/DNqgjaNK`
- `/tmp/DqhjlBDR`
- `/tmp/GnHyjver`
- `/tmp/PlRKnTbE`
- `/tmp/YzuvpyqM`
- `/tmp/cache`
- `/tmp/d.log`
- `/tmp/dms55c76xpps2yz3u0j18tgwhu`
- `/tmp/ePZBBbBI`
- `/tmp/jcYCWDOB`
- `/tmp/kvFAhbJE`
- `/tmp/lKxXPpzx`
- `/tmp/oLvWOoKY`
- `/tmp/osyfKuoH`
- `/tmp/vuldQlDy`
- `/tmp/wDNCJKjh`
- `/tmp/waUncNSL`
- `/tmp/zrzTuicO`
- `/var/tmp`

### Extracted URLs

- `https://217.60.195.113/sh`

---

## Top Attack Patterns (SSH)

- [206x] `lspci`
- [147x] `nvidia-smi -q`
- [147x] `grep "Product Name`
- [144x] `egrep VGA`
- [82x] `grep Radeon`
- [81x] `uname -n`
- [81x] `uname -r`
- [76x] `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH`
- [76x] `uname -s -v -n -m 2>/dev/null`
- [76x] `uname -m 2>/dev/null`
- [76x] `cat /proc/uptime 2>/dev/null`
- [76x] `nproc 2>/dev/null`
- [76x] `/usr/bin/nproc 2>/dev/null`
- [76x] `grep -c "^processor" /proc/cpuinfo 2>/dev/null`
- [76x] `cpu_model=$( (grep -m1 -E "model name`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 4 | `sigma/*.yml` |
| YARA (Payload) | 3 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 498 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*