# Threat Intelligence Report

**Generated**: 2026-03-26 01:58 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **406 events** from **541 unique source IPs** across **33 countries** and **50 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 406 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 541 |
| Atomic Attack Patterns | 2892 |
| MITRE ATT&CK Techniques | 8 |
| Generated Sigma Rules | 5 |
| Generated YARA Rules | 4 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 503 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 1602 |
| T1059.004 (Unix Shell) | | 1016 |
| T1033 (System Owner/User Discovery) | | 162 |
| T1105 (Ingress Tool Transfer) | | 11 |
| T1005 (Data from Local System) | | 4 |
| T1016 (System Network Configuration Discovery) | | 4 |
| T1057 (Process Discovery) | | 3 |
| T1552.001 (Credentials In Files) | | 2 |

### Tactics Distribution

- **discovery**: 1771 events ████████████████████████████████████████
- **execution**: 1016 events ████████████████████████████████████████
- **command_and_control**: 11 events █████
- **collection**: 4 events ██
- **credential_access**: 2 events █

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 6,912 |
| France | 2,685 |
| Indonesia | 2,302 |
| Pakistan | 1,877 |
| China | 1,459 |
| The Netherlands | 1,210 |
| India | 1,061 |
| Singapore | 1,024 |
| Switzerland | 927 |
| Germany | 915 |
| United Kingdom | 780 |
| South Korea | 579 |
| Canada | 516 |
| Russia | 484 |
| Hong Kong | 471 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| DigitalOcean, LLC | 2,747 |
| Modat B.V. | 1,702 |
| Ghosty Networks LLC | 1,639 |
| PT Cloud Hosting Indonesia | 1,273 |
| Google LLC | 896 |
| Private Layer INC | 888 |
| ONYPHE SAS | 835 |
| Microsoft Corporation | 581 |
| Omegatech LTD | 569 |
| Netiface Limited | 514 |
| Amazon.com, Inc. | 512 |
| OVH SAS | 471 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 420 |
| Byteplus Pte. Ltd. | 403 |
| Cloud Host Pte Ltd | 401 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `46.19.137.194` | 888 | Attacker |
| `134.199.196.64` | 755 | Attacker |
| `134.209.166.254` | 755 | Attacker |
| `91.92.243.116` | 538 | Attacker |
| `203.145.34.82` | 407 | Attacker |
| `119.18.55.118` | 376 | Attacker |
| `193.227.241.201` | 376 | Attacker |
| `68.183.66.16` | 322 | Attacker |
| `129.212.184.91` | 316 | Attacker |
| `103.191.14.210` | 307 | Attacker |
| `103.63.25.171` | 307 | Attacker |
| `156.236.75.188` | 307 | Attacker |
| `170.79.37.88` | 307 | Attacker |
| `34.39.58.191` | 257 | Attacker |
| `69.149.23.135` | 257 | Attacker |
| `107.180.88.176` | 238 | Attacker |
| `57.134.214.95` | 237 | Attacker |
| `31.14.32.6` | 217 | Attacker |
| `101.47.141.125` | 187 | Attacker |
| `76.79.213.69` | 187 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 541 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 15 |

### Targeted File Paths

- `/.local/share/TelegramDesktop/tdata`
- `/etc/hostname`
- `/etc/netplan`
- `/etc/network/interfaces`
- `/etc/passwd`
- `/etc/shadow`
- `/etc/smsd.conf`
- `/etc/sysconfig/network-scripts`
- `/tmp/ltyu2gbpejb4dog81ohvxsrwvs`
- `/tmp/test`
- `/tmp/test_1774464627`
- `/var/log/smsd.log`
- `/var/qmux_connect`
- `/var/spool/sms`
- `/var/tmp/ltyu2gbpejb4dog81ohvxsrwvs`

### Extracted URLs

- `https://31.57.216.121/sh`

---

## Top Attack Patterns (SSH)

- [152x] `$f" 2>/dev/null`
- [152x] `echo 0`
- [152x] `echo 1`
- [78x] `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH`
- [78x] `uname -s -v -n -m 2>/dev/null`
- [78x] `uname -m 2>/dev/null`
- [78x] `cat /proc/uptime 2>/dev/null`
- [78x] `nproc 2>/dev/null`
- [78x] `/usr/bin/nproc 2>/dev/null`
- [78x] `grep -c "^processor" /proc/cpuinfo 2>/dev/null`
- [78x] `cpu_model=$( (grep -m1 -E "model name`
- [78x] `Hardware" /proc/cpuinfo`
- [78x] `lscpu 2>/dev/null`
- [78x] `dmidecode -s processor-version 2>/dev/null`
- [78x] `uname -p 2>/dev/null`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 5 | `sigma/*.yml` |
| YARA (Payload) | 4 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 503 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*