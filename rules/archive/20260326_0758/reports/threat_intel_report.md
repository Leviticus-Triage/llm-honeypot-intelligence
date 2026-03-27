# Threat Intelligence Report

**Generated**: 2026-03-26 07:58 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **959 events** from **571 unique source IPs** across **37 countries** and **57 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 959 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 571 |
| Atomic Attack Patterns | 3479 |
| MITRE ATT&CK Techniques | 9 |
| Generated Sigma Rules | 6 |
| Generated YARA Rules | 4 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 514 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 1607 |
| T1059.004 (Unix Shell) | | 1553 |
| T1033 (System Owner/User Discovery) | | 162 |
| T1105 (Ingress Tool Transfer) | | 35 |
| T1222.002 (Linux File Permissions Modification) | | 8 |
| T1005 (Data from Local System) | | 4 |
| T1016 (System Network Configuration Discovery) | | 4 |
| T1057 (Process Discovery) | | 3 |
| T1552.001 (Credentials In Files) | | 2 |

### Tactics Distribution

- **discovery**: 1776 events ████████████████████████████████████████
- **execution**: 1553 events ████████████████████████████████████████
- **command_and_control**: 35 events █████████████████
- **defense_evasion**: 8 events ████
- **collection**: 4 events ██
- **credential_access**: 2 events █

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United Arab Emirates | 26,440 |
| United States | 9,991 |
| Indonesia | 4,530 |
| France | 4,024 |
| Pakistan | 2,204 |
| Germany | 2,058 |
| India | 1,942 |
| China | 1,927 |
| South Korea | 1,768 |
| Singapore | 1,728 |
| United Kingdom | 1,467 |
| Hong Kong | 1,464 |
| The Netherlands | 1,397 |
| Switzerland | 1,054 |
| Vietnam | 988 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Emirates Telecommunications Group Company (etisalat Group) Pjsc | 26,252 |
| DigitalOcean, LLC | 4,385 |
| PT Cloud Hosting Indonesia | 2,367 |
| Modat B.V. | 1,952 |
| Ghosty Networks LLC | 1,948 |
| Google LLC | 1,515 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 1,301 |
| ONYPHE SAS | 1,139 |
| OVH SAS | 1,104 |
| Microsoft Corporation | 1,049 |
| Korea Telecom | 925 |
| Byteplus Pte. Ltd. | 852 |
| Alibaba US Technology Co., Ltd. | 837 |
| Amazon.com, Inc. | 835 |
| Private Layer INC | 812 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `94.56.40.180` | 26,252 | Attacker |
| `134.199.196.64` | 1,049 | Attacker |
| `134.209.166.254` | 1,049 | Attacker |
| `46.19.137.194` | 935 | Attacker |
| `91.92.243.116` | 538 | Attacker |
| `68.183.66.16` | 490 | Attacker |
| `129.212.184.91` | 439 | Attacker |
| `203.145.34.82` | 407 | Attacker |
| `119.18.55.118` | 376 | Attacker |
| `193.227.241.201` | 376 | Attacker |
| `103.147.150.236` | 360 | Attacker |
| `103.191.14.210` | 307 | Attacker |
| `103.63.25.171` | 307 | Attacker |
| `156.236.75.188` | 307 | Attacker |
| `170.79.37.88` | 307 | Attacker |
| `8.219.156.182` | 300 | Attacker |
| `37.59.110.4` | 282 | Attacker |
| `34.39.58.191` | 257 | Attacker |
| `69.149.23.135` | 257 | Attacker |
| `103.103.245.61` | 256 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 571 |
| URLs | 2 |
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

- `http://88.214.20.143/sshbins.sh`
- `https://31.57.216.121/sh`

---

## Top Attack Patterns (SSH)

- [535x] `echo -e "\x6F\x6B`
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

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 6 | `sigma/*.yml` |
| YARA (Payload) | 4 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 514 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*