# Threat Intelligence Report

**Generated**: 2026-03-27 21:37 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **743 events** from **571 unique source IPs** across **36 countries** and **49 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 742 |
| HTTP Events (Galah) | 1 |
| Unique Attacker IPs | 571 |
| Atomic Attack Patterns | 1206 |
| MITRE ATT&CK Techniques | 9 |
| Generated Sigma Rules | 5 |
| Generated YARA Rules | 4 |
| Generated Suricata Rules | 24 |
| Blocked IPs (Firewall) | 512 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 654 |
| T1059.004 (Unix Shell) | | 65 |
| T1105 (Ingress Tool Transfer) | | 11 |
| T1033 (System Owner/User Discovery) | | 6 |
| T1016 (System Network Configuration Discovery) | | 3 |
| T1057 (Process Discovery) | | 2 |
| T1005 (Data from Local System) | | 2 |
| T1552.001 (Credentials In Files) | | 2 |
| T1543.002 (Systemd Service) | | 1 |

### Tactics Distribution

- **discovery**: 665 events ████████████████████████████████████████
- **execution**: 65 events ████████████████████████████████
- **command_and_control**: 11 events █████
- **collection**: 2 events █
- **credential_access**: 2 events █
- **persistence**: 1 events 

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 10,321 |
| South Korea | 4,799 |
| Indonesia | 4,461 |
| India | 2,138 |
| France | 1,908 |
| Singapore | 1,877 |
| China | 1,744 |
| Hong Kong | 1,730 |
| Japan | 1,359 |
| Germany | 941 |
| United Kingdom | 884 |
| Switzerland | 731 |
| Brazil | 713 |
| Russia | 627 |
| The Netherlands | 561 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| DigitalOcean, LLC | 4,254 |
| Alibaba US Technology Co., Ltd. | 2,994 |
| Korea Telecom | 2,773 |
| HUAWEI CLOUDS | 2,603 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 2,203 |
| Google LLC | 2,110 |
| Amazon.com, Inc. | 1,304 |
| SK Broadband Co Ltd | 1,271 |
| ONYPHE SAS | 1,128 |
| Microsoft Corporation | 929 |
| PT Cloud Hosting Indonesia | 857 |
| SMILESERV | 728 |
| Unmanaged Ltd | 671 |
| PT Telekomunikasi Indonesia | 662 |
| Modat B.V. | 631 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `110.239.90.94` | 2,379 | Attacker |
| `134.199.196.64` | 1,186 | Attacker |
| `134.209.166.254` | 1,181 | Attacker |
| `68.183.66.16` | 588 | Attacker |
| `46.19.137.194` | 551 | Attacker |
| `121.153.60.137` | 530 | Attacker |
| `118.219.239.123` | 496 | Attacker |
| `129.212.184.91` | 495 | Attacker |
| `118.35.127.66` | 430 | Attacker |
| `211.213.96.6` | 430 | Attacker |
| `59.26.132.170` | 430 | Attacker |
| `222.108.100.117` | 369 | Attacker |
| `115.68.208.117` | 364 | Attacker |
| `115.68.226.124` | 364 | Attacker |
| `124.36.45.178` | 364 | Attacker |
| `152.32.144.167` | 364 | Attacker |
| `211.228.218.47` | 364 | Attacker |
| `222.124.177.148` | 364 | Attacker |
| `86.110.51.47` | 332 | Attacker |
| `103.105.176.70` | 304 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 571 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 14 |

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
- `/tmp/test_1774565799`
- `/var/log/smsd.log`
- `/var/qmux_connect`
- `/var/spool/sms`

### Extracted URLs

- `https://31.57.216.121/sh`

---

## Top Attack Patterns (SSH)

- [244x] `lspci`
- [136x] `/bin/./uname -s -v -n -r -m`
- [124x] `nvidia-smi -q`
- [124x] `grep "Product Name`
- [114x] `uptime -p`
- [97x] `grep VGA`
- [86x] `grep VGA -c`
- [61x] `grep "3D controller`
- [50x] `grep . -c`
- [27x] `echo login_success`
- [19x] `uname -a`
- [10x] `cat /etc/os-release 2>/dev/null`
- [10x] `echo no_os_release`
- [9x] `nproc --all`
- [9x] `$f" 2>/dev/null`

## Top Attack Patterns (HTTP)

| URI | Hits | Category |
|-----|------|----------|
| `/favicon.ico` | 3 | Web Scan |
| `/eee.php` | 1 | Web Scan |

### HTTP Methods

- **GET**: 150
- **PROPFIND**: 21
- **POST**: 5
- **HEAD**: 3

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 5 | `sigma/*.yml` |
| YARA (Payload) | 4 | `yara/*.yar` |
| Suricata (IDS/IPS) | 24 | `suricata/honeypot.rules` |
| Firewall (iptables) | 512 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*