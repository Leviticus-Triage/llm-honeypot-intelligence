# Threat Intelligence Report

**Generated**: 2026-03-28 15:37 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,000 events** from **567 unique source IPs** across **36 countries** and **51 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 567 |
| Atomic Attack Patterns | 3652 |
| MITRE ATT&CK Techniques | 8 |
| Generated Sigma Rules | 4 |
| Generated YARA Rules | 3 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 511 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 1879 |
| T1059.004 (Unix Shell) | | 1180 |
| T1033 (System Owner/User Discovery) | | 156 |
| T1016 (System Network Configuration Discovery) | | 4 |
| T1005 (Data from Local System) | | 4 |
| T1105 (Ingress Tool Transfer) | | 3 |
| T1057 (Process Discovery) | | 3 |
| T1543.002 (Systemd Service) | | 1 |

### Tactics Distribution

- **discovery**: 2042 events ████████████████████████████████████████
- **execution**: 1180 events ████████████████████████████████████████
- **collection**: 4 events ██
- **command_and_control**: 3 events █
- **persistence**: 1 events 

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 9,407 |
| Indonesia | 4,366 |
| South Korea | 3,473 |
| Singapore | 2,204 |
| China | 2,112 |
| Switzerland | 1,726 |
| Armenia | 1,526 |
| Hong Kong | 1,493 |
| Brazil | 1,350 |
| Japan | 1,200 |
| Romania | 1,086 |
| France | 919 |
| Germany | 910 |
| Vietnam | 874 |
| United Kingdom | 864 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| DigitalOcean, LLC | 3,702 |
| HUAWEI CLOUDS | 2,379 |
| Alibaba US Technology Co., Ltd. | 2,377 |
| Korea Telecom | 1,982 |
| Google LLC | 1,899 |
| Private Layer INC | 1,704 |
| Arpinet LLC | 1,520 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 1,449 |
| LANTEC COMUNICACAO MULTIMIDIA LTDA | 1,314 |
| Amazon.com, Inc. | 1,228 |
| SK Broadband Co Ltd | 836 |
| PT Cloud Hosting Indonesia | 745 |
| SS-Net | 689 |
| 365 Online technology joint stock company | 672 |
| Microsoft Corporation | 651 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `110.239.90.94` | 2,379 | Attacker |
| `46.19.137.194` | 1,700 | Attacker |
| `91.231.202.24` | 1,520 | Attacker |
| `187.108.1.130` | 1,314 | Attacker |
| `134.199.196.64` | 1,188 | Attacker |
| `134.209.166.254` | 1,182 | Attacker |
| `80.94.95.43` | 681 | Attacker |
| `103.199.19.57` | 672 | Attacker |
| `129.212.184.91` | 496 | Attacker |
| `23.95.55.242` | 399 | Attacker |
| `222.108.100.117` | 375 | Attacker |
| `59.26.132.170` | 344 | Attacker |
| `118.35.127.66` | 339 | Attacker |
| `211.213.96.6` | 339 | Attacker |
| `86.110.51.47` | 332 | Attacker |
| `103.154.158.70` | 302 | Attacker |
| `5.181.86.60` | 300 | Attacker |
| `42.200.66.164` | 297 | Attacker |
| `8.219.236.45` | 297 | Attacker |
| `222.124.177.148` | 283 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 567 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 12 |

### Targeted File Paths

- `/.local/share/TelegramDesktop/tdata`
- `/etc/hostname`
- `/etc/netplan`
- `/etc/network/interfaces`
- `/etc/os-release`
- `/etc/smsd.conf`
- `/etc/sysconfig/network-scripts`
- `/tmp/test`
- `/tmp/test_1774704507`
- `/var/log/smsd.log`
- `/var/qmux_connect`
- `/var/spool/sms`

### Extracted URLs

- `https://31.57.216.121/sh`

---

## Top Attack Patterns (SSH)

- [172x] `nproc 2>/dev/null`
- [141x] `$f" 2>/dev/null`
- [141x] `echo 0`
- [141x] `echo 1`
- [105x] `uname -a`
- [97x] `hostname`
- [96x] `free -h 2>/dev/null`
- [96x] `grep Mem`
- [96x] `df -h 2>/dev/null`
- [96x] `ssh -V 2>&1`
- [96x] `grep -c ^processor /proc/cpuinfo 2>/dev/null`
- [96x] `echo 'bash_test_12345`
- [96x] `echo 'second_line`
- [76x] `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH`
- [76x] `uname -s -v -n -m 2>/dev/null`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 4 | `sigma/*.yml` |
| YARA (Payload) | 3 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 511 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*