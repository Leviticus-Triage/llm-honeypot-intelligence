# Threat Intelligence Report

**Generated**: 2026-03-28 09:37 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **987 events** from **573 unique source IPs** across **38 countries** and **49 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 986 |
| HTTP Events (Galah) | 1 |
| Unique Attacker IPs | 573 |
| Atomic Attack Patterns | 4555 |
| MITRE ATT&CK Techniques | 7 |
| Generated Sigma Rules | 4 |
| Generated YARA Rules | 3 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 511 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 2637 |
| T1059.004 (Unix Shell) | | 1331 |
| T1033 (System Owner/User Discovery) | | 208 |
| T1105 (Ingress Tool Transfer) | | 5 |
| T1005 (Data from Local System) | | 2 |
| T1016 (System Network Configuration Discovery) | | 1 |
| T1057 (Process Discovery) | | 1 |

### Tactics Distribution

- **discovery**: 2847 events ████████████████████████████████████████
- **execution**: 1331 events ████████████████████████████████████████
- **command_and_control**: 5 events ██
- **collection**: 2 events █

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 9,665 |
| South Korea | 4,654 |
| Indonesia | 3,745 |
| Singapore | 2,428 |
| China | 2,030 |
| Japan | 1,641 |
| Armenia | 1,525 |
| Switzerland | 1,496 |
| Hong Kong | 1,358 |
| Romania | 957 |
| United Kingdom | 922 |
| India | 905 |
| France | 800 |
| Germany | 792 |
| The Netherlands | 739 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| DigitalOcean, LLC | 3,808 |
| Korea Telecom | 2,599 |
| Alibaba US Technology Co., Ltd. | 2,585 |
| HUAWEI CLOUDS | 2,379 |
| Google LLC | 2,061 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 1,637 |
| Arpinet LLC | 1,520 |
| Private Layer INC | 1,454 |
| SK Broadband Co Ltd | 1,257 |
| Amazon.com, Inc. | 1,233 |
| ONYPHE SAS | 831 |
| Microsoft Corporation | 754 |
| SMILESERV | 728 |
| Unmanaged Ltd | 661 |
| SS-Net | 519 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `110.239.90.94` | 2,379 | Attacker |
| `91.231.202.24` | 1,520 | Attacker |
| `46.19.137.194` | 1,454 | Attacker |
| `134.199.196.64` | 1,188 | Attacker |
| `134.209.166.254` | 1,184 | Attacker |
| `80.94.95.43` | 517 | Attacker |
| `118.219.239.123` | 496 | Attacker |
| `129.212.184.91` | 496 | Attacker |
| `187.108.1.130` | 438 | Attacker |
| `118.35.127.66` | 430 | Attacker |
| `211.213.96.6` | 430 | Attacker |
| `59.26.132.170` | 430 | Attacker |
| `222.108.100.117` | 369 | Attacker |
| `115.68.208.117` | 364 | Attacker |
| `115.68.226.124` | 364 | Attacker |
| `121.153.60.137` | 364 | Attacker |
| `124.36.45.178` | 364 | Attacker |
| `152.32.144.167` | 364 | Attacker |
| `211.228.218.47` | 364 | Attacker |
| `222.124.177.148` | 364 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 573 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 6 |

### Targeted File Paths

- `/.local/share/TelegramDesktop/tdata`
- `/etc/os-release`
- `/etc/smsd.conf`
- `/var/log/smsd.log`
- `/var/qmux_connect`
- `/var/spool/sms`

### Extracted URLs

- `https://31.57.216.121/sh`

---

## Top Attack Patterns (SSH)

- [232x] `lspci`
- [181x] `$f" 2>/dev/null`
- [181x] `echo 0`
- [181x] `echo 1`
- [170x] `/bin/./uname -s -v -n -r -m`
- [129x] `uptime -p`
- [107x] `nvidia-smi -q`
- [107x] `grep "Product Name`
- [104x] `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH`
- [104x] `uname -s -v -n -m 2>/dev/null`
- [104x] `uname -m 2>/dev/null`
- [104x] `cat /proc/uptime 2>/dev/null`
- [104x] `nproc 2>/dev/null`
- [104x] `/usr/bin/nproc 2>/dev/null`
- [104x] `grep -c "^processor" /proc/cpuinfo 2>/dev/null`

## Top Attack Patterns (HTTP)

| URI | Hits | Category |
|-----|------|----------|
| `/eee.php` | 1 | Web Scan |
| `/favicon.ico` | 1 | Web Scan |

### HTTP Methods

- **GET**: 142
- **PROPFIND**: 25
- **HEAD**: 3
- **POST**: 2

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