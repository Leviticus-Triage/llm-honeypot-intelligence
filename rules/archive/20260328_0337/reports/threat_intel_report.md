# Threat Intelligence Report

**Generated**: 2026-03-28 03:37 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **808 events** from **568 unique source IPs** across **36 countries** and **45 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 807 |
| HTTP Events (Galah) | 1 |
| Unique Attacker IPs | 568 |
| Atomic Attack Patterns | 3863 |
| MITRE ATT&CK Techniques | 7 |
| Generated Sigma Rules | 4 |
| Generated YARA Rules | 3 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 512 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 2199 |
| T1059.004 (Unix Shell) | | 1163 |
| T1033 (System Owner/User Discovery) | | 178 |
| T1105 (Ingress Tool Transfer) | | 7 |
| T1005 (Data from Local System) | | 2 |
| T1016 (System Network Configuration Discovery) | | 1 |
| T1057 (Process Discovery) | | 1 |

### Tactics Distribution

- **discovery**: 2379 events ████████████████████████████████████████
- **execution**: 1163 events ████████████████████████████████████████
- **command_and_control**: 7 events ███
- **collection**: 2 events █

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 9,531 |
| South Korea | 4,821 |
| Indonesia | 4,415 |
| Singapore | 2,664 |
| Hong Kong | 1,496 |
| Switzerland | 1,395 |
| Japan | 1,368 |
| China | 1,205 |
| India | 1,110 |
| France | 1,060 |
| United Kingdom | 951 |
| Germany | 906 |
| The Netherlands | 724 |
| Russia | 595 |
| Brazil | 566 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| DigitalOcean, LLC | 3,986 |
| Alibaba US Technology Co., Ltd. | 2,960 |
| Korea Telecom | 2,773 |
| HUAWEI CLOUDS | 2,404 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 2,162 |
| Google LLC | 2,093 |
| SK Broadband Co Ltd | 1,277 |
| Private Layer INC | 1,209 |
| Amazon.com, Inc. | 1,194 |
| ONYPHE SAS | 993 |
| Microsoft Corporation | 936 |
| PT Cloud Hosting Indonesia | 862 |
| SMILESERV | 728 |
| PT Telekomunikasi Indonesia | 662 |
| Vpsvault.host Ltd | 550 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `110.239.90.94` | 2,379 | Attacker |
| `46.19.137.194` | 1,209 | Attacker |
| `134.199.196.64` | 1,188 | Attacker |
| `134.209.166.254` | 1,182 | Attacker |
| `121.153.60.137` | 530 | Attacker |
| `118.219.239.123` | 496 | Attacker |
| `129.212.184.91` | 496 | Attacker |
| `118.35.127.66` | 430 | Attacker |
| `211.213.96.6` | 430 | Attacker |
| `59.26.132.170` | 430 | Attacker |
| `68.183.66.16` | 420 | Attacker |
| `222.108.100.117` | 369 | Attacker |
| `115.68.208.117` | 364 | Attacker |
| `115.68.226.124` | 364 | Attacker |
| `124.36.45.178` | 364 | Attacker |
| `152.32.144.167` | 364 | Attacker |
| `211.228.218.47` | 364 | Attacker |
| `222.124.177.148` | 364 | Attacker |
| `86.110.51.47` | 332 | Attacker |
| `116.193.190.100` | 298 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 568 |
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

- [187x] `lspci`
- [158x] `$f" 2>/dev/null`
- [158x] `echo 0`
- [158x] `echo 1`
- [113x] `/bin/./uname -s -v -n -r -m`
- [90x] `uptime -p`
- [90x] `nvidia-smi -q`
- [90x] `grep "Product Name`
- [89x] `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH`
- [89x] `uname -s -v -n -m 2>/dev/null`
- [89x] `uname -m 2>/dev/null`
- [89x] `cat /proc/uptime 2>/dev/null`
- [89x] `nproc 2>/dev/null`
- [89x] `/usr/bin/nproc 2>/dev/null`
- [89x] `grep -c "^processor" /proc/cpuinfo 2>/dev/null`

## Top Attack Patterns (HTTP)

| URI | Hits | Category |
|-----|------|----------|
| `/favicon.ico` | 2 | Web Scan |
| `/eee.php` | 1 | Web Scan |

### HTTP Methods

- **GET**: 147
- **PROPFIND**: 28
- **HEAD**: 2
- **POST**: 2

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 4 | `sigma/*.yml` |
| YARA (Payload) | 3 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 512 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*