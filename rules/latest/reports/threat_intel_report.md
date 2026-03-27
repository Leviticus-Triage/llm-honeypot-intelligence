# Threat Intelligence Report

**Generated**: 2026-03-27 09:37 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,000 events** from **566 unique source IPs** across **37 countries** and **56 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 566 |
| Atomic Attack Patterns | 1759 |
| MITRE ATT&CK Techniques | 11 |
| Generated Sigma Rules | 6 |
| Generated YARA Rules | 5 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 514 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 776 |
| T1059.004 (Unix Shell) | | 284 |
| T1105 (Ingress Tool Transfer) | | 13 |
| T1033 (System Owner/User Discovery) | | 9 |
| T1552.004 (Private Keys) | | 6 |
| T1016 (System Network Configuration Discovery) | | 4 |
| T1057 (Process Discovery) | | 3 |
| T1552.001 (Credentials In Files) | | 2 |
| T1543.002 (Systemd Service) | | 2 |
| T1005 (Data from Local System) | | 2 |
| T1222.002 (Linux File Permissions Modification) | | 1 |

### Tactics Distribution

- **discovery**: 792 events ████████████████████████████████████████
- **execution**: 284 events ████████████████████████████████████████
- **command_and_control**: 13 events ██████
- **credential_access**: 8 events ████
- **persistence**: 2 events █
- **collection**: 2 events █
- **defense_evasion**: 1 events 

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United Arab Emirates | 20,005 |
| United States | 10,885 |
| Brazil | 8,206 |
| Indonesia | 3,745 |
| Singapore | 2,956 |
| Hong Kong | 2,490 |
| India | 2,458 |
| China | 2,255 |
| France | 2,077 |
| Germany | 2,035 |
| South Korea | 1,571 |
| United Kingdom | 1,476 |
| Romania | 812 |
| Switzerland | 667 |
| Colombia | 522 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Emirates Telecommunications Group Company (etisalat Group) Pjsc | 19,887 |
| LANTEC COMUNICACAO MULTIMIDIA LTDA | 6,303 |
| DigitalOcean, LLC | 5,066 |
| Alibaba US Technology Co., Ltd. | 2,475 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 2,340 |
| PT Cloud Hosting Indonesia | 1,922 |
| Google LLC | 1,911 |
| Microsoft Corporation | 1,579 |
| Amazon.com, Inc. | 1,366 |
| Korea Telecom | 1,333 |
| ONYPHE SAS | 1,143 |
| Unmanaged Ltd | 1,031 |
| Modat B.V. | 967 |
| CHINA UNICOM China169 Backbone | 844 |
| IONOS SE | 813 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `94.56.40.180` | 19,811 | Attacker |
| `187.108.1.130` | 6,303 | Attacker |
| `134.199.196.64` | 1,185 | Attacker |
| `134.209.166.254` | 1,180 | Attacker |
| `68.183.66.16` | 693 | Attacker |
| `46.19.137.194` | 517 | Attacker |
| `129.212.184.91` | 494 | Attacker |
| `221.161.235.168` | 305 | Attacker |
| `103.105.176.70` | 304 | Attacker |
| `168.167.228.123` | 304 | Attacker |
| `201.77.124.248` | 300 | Attacker |
| `116.193.190.100` | 298 | Attacker |
| `187.120.41.39` | 298 | Attacker |
| `201.186.40.161` | 298 | Attacker |
| `36.91.166.34` | 298 | Attacker |
| `45.205.1.110` | 287 | Attacker |
| `41.203.213.8` | 250 | Attacker |
| `150.136.129.10` | 249 | Attacker |
| `103.194.243.196` | 236 | Attacker |
| `47.83.130.34` | 236 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 565 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 17 |

### Targeted File Paths

- `/.local/share/TelegramDesktop/tdata`
- `/etc/hostname`
- `/etc/netplan`
- `/etc/network/interfaces`
- `/etc/os-release`
- `/etc/passwd`
- `/etc/shadow`
- `/etc/smsd.conf`
- `/etc/sysconfig/network-scripts`
- `/tmp/test`
- `/tmp/test_1774550975`
- `/tmp/test_1774565799`
- `/tmp/zbgjp0yc6izgkftm2p29n0msdb`
- `/var/log/smsd.log`
- `/var/qmux_connect`
- `/var/spool/sms`
- `/var/tmp/zbgjp0yc6izgkftm2p29n0msdb`

### Extracted URLs

- `https://31.57.216.121/sh`

---

## Top Attack Patterns (SSH)

- [287x] `lspci`
- [167x] `/bin/./uname -s -v -n -r -m`
- [145x] `nvidia-smi -q`
- [145x] `grep "Product Name`
- [138x] `uptime -p`
- [121x] `$f" 2>/dev/null`
- [121x] `echo 0`
- [121x] `echo 1`
- [117x] `grep VGA`
- [100x] `grep VGA -c`
- [70x] `grep "3D controller`
- [61x] `grep . -c`
- [18x] `echo login_success`
- [17x] `uname -a`
- [11x] `cat /etc/os-release 2>/dev/null`

## Top Attack Patterns (HTTP)

| URI | Hits | Category |
|-----|------|----------|
| `/favicon.ico` | 2 | Web Scan |

### HTTP Methods

- **GET**: 159
- **PROPFIND**: 23
- **POST**: 3
- **HEAD**: 2

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 6 | `sigma/*.yml` |
| YARA (Payload) | 5 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 514 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*