# Threat Intelligence Report

**Generated**: 2026-03-27 15:37 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,001 events** from **565 unique source IPs** across **36 countries** and **50 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 1 |
| Unique Attacker IPs | 565 |
| Atomic Attack Patterns | 1604 |
| MITRE ATT&CK Techniques | 8 |
| Generated Sigma Rules | 5 |
| Generated YARA Rules | 4 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 511 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 880 |
| T1059.004 (Unix Shell) | | 81 |
| T1105 (Ingress Tool Transfer) | | 17 |
| T1033 (System Owner/User Discovery) | | 9 |
| T1016 (System Network Configuration Discovery) | | 3 |
| T1057 (Process Discovery) | | 2 |
| T1552.001 (Credentials In Files) | | 2 |
| T1543.002 (Systemd Service) | | 2 |

### Tactics Distribution

- **discovery**: 894 events ████████████████████████████████████████
- **execution**: 81 events ████████████████████████████████████████
- **command_and_control**: 17 events ████████
- **credential_access**: 2 events █
- **persistence**: 2 events █

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 9,935 |
| Brazil | 5,765 |
| Indonesia | 2,551 |
| India | 2,349 |
| Singapore | 2,101 |
| China | 2,037 |
| South Korea | 1,815 |
| Hong Kong | 1,809 |
| Germany | 1,698 |
| France | 1,584 |
| United Kingdom | 1,079 |
| Russia | 905 |
| Romania | 805 |
| Switzerland | 719 |
| Japan | 606 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| DigitalOcean, LLC | 4,706 |
| LANTEC COMUNICACAO MULTIMIDIA LTDA | 4,202 |
| Alibaba US Technology Co., Ltd. | 2,519 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 2,091 |
| Google LLC | 2,000 |
| Amazon.com, Inc. | 1,247 |
| Microsoft Corporation | 1,187 |
| PT Cloud Hosting Indonesia | 1,178 |
| Korea Telecom | 1,152 |
| ONYPHE SAS | 1,142 |
| Unmanaged Ltd | 1,045 |
| CHINA UNICOM China169 Backbone | 666 |
| Modat B.V. | 631 |
| Vpsvault.host Ltd | 567 |
| Private Layer INC | 551 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `187.108.1.130` | 4,202 | Attacker |
| `134.199.196.64` | 1,185 | Attacker |
| `134.209.166.254` | 1,181 | Attacker |
| `68.183.66.16` | 714 | Attacker |
| `46.19.137.194` | 551 | Attacker |
| `129.212.184.91` | 494 | Attacker |
| `103.105.176.70` | 304 | Attacker |
| `168.167.228.123` | 304 | Attacker |
| `201.77.124.248` | 300 | Attacker |
| `116.193.190.100` | 298 | Attacker |
| `187.120.41.39` | 298 | Attacker |
| `201.186.40.161` | 298 | Attacker |
| `36.91.166.34` | 298 | Attacker |
| `45.205.1.110` | 287 | Attacker |
| `2.57.122.238` | 254 | Attacker |
| `121.153.60.137` | 252 | Attacker |
| `103.194.243.196` | 236 | Attacker |
| `47.83.130.34` | 236 | Attacker |
| `47.86.18.208` | 236 | Attacker |
| `72.253.251.3` | 236 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 564 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 12 |

### Targeted File Paths

- `/etc/hostname`
- `/etc/netplan`
- `/etc/network/interfaces`
- `/etc/os-release`
- `/etc/passwd`
- `/etc/shadow`
- `/etc/sysconfig/network-scripts`
- `/tmp/test`
- `/tmp/test_1774550975`
- `/tmp/test_1774565799`
- `/tmp/zbgjp0yc6izgkftm2p29n0msdb`
- `/var/tmp/zbgjp0yc6izgkftm2p29n0msdb`

### Extracted URLs

- `https://31.57.216.121/sh`

---

## Top Attack Patterns (SSH)

- [323x] `lspci`
- [193x] `/bin/./uname -s -v -n -r -m`
- [160x] `nvidia-smi -q`
- [160x] `grep "Product Name`
- [159x] `uptime -p`
- [133x] `grep VGA`
- [112x] `grep VGA -c`
- [78x] `grep "3D controller`
- [65x] `grep . -c`
- [28x] `echo login_success`
- [23x] `uname -a`
- [14x] `cat /etc/os-release 2>/dev/null`
- [14x] `echo no_os_release`
- [13x] `$f" 2>/dev/null`
- [13x] `echo 0`

## Top Attack Patterns (HTTP)

| URI | Hits | Category |
|-----|------|----------|
| `/favicon.ico` | 3 | Web Scan |
| `/eee.php` | 1 | Web Scan |

### HTTP Methods

- **GET**: 150
- **PROPFIND**: 20
- **HEAD**: 4
- **POST**: 3

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 5 | `sigma/*.yml` |
| YARA (Payload) | 4 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 511 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*