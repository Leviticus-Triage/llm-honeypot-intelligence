# Threat Intelligence Report

**Generated**: 2026-03-27 03:37 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,000 events** from **568 unique source IPs** across **38 countries** and **55 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 568 |
| Atomic Attack Patterns | 1458 |
| MITRE ATT&CK Techniques | 8 |
| Generated Sigma Rules | 5 |
| Generated YARA Rules | 4 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 512 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 577 |
| T1059.004 (Unix Shell) | | 414 |
| T1105 (Ingress Tool Transfer) | | 13 |
| T1033 (System Owner/User Discovery) | | 9 |
| T1016 (System Network Configuration Discovery) | | 3 |
| T1057 (Process Discovery) | | 2 |
| T1552.001 (Credentials In Files) | | 2 |
| T1543.002 (Systemd Service) | | 2 |

### Tactics Distribution

- **discovery**: 591 events ████████████████████████████████████████
- **execution**: 414 events ████████████████████████████████████████
- **command_and_control**: 13 events ██████
- **credential_access**: 2 events █
- **persistence**: 2 events █

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United Arab Emirates | 61,114 |
| United States | 11,653 |
| Brazil | 8,359 |
| Indonesia | 4,751 |
| Hong Kong | 3,156 |
| Singapore | 3,114 |
| Germany | 3,036 |
| France | 3,009 |
| China | 2,628 |
| India | 2,611 |
| South Korea | 2,251 |
| United Kingdom | 1,901 |
| Vietnam | 970 |
| Russia | 804 |
| Taiwan | 695 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Emirates Telecommunications Group Company (etisalat Group) Pjsc | 60,808 |
| LANTEC COMUNICACAO MULTIMIDIA LTDA | 6,303 |
| DigitalOcean, LLC | 5,704 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 2,512 |
| Alibaba US Technology Co., Ltd. | 2,274 |
| PT Cloud Hosting Indonesia | 2,258 |
| Google LLC | 1,891 |
| Korea Telecom | 1,707 |
| Microsoft Corporation | 1,444 |
| Amazon.com, Inc. | 1,435 |
| OVH SAS | 1,241 |
| Modat B.V. | 1,217 |
| ONYPHE SAS | 1,171 |
| IONOS SE | 1,163 |
| Cloud Host Pte Ltd | 954 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `94.56.40.180` | 60,808 | Attacker |
| `187.108.1.130` | 6,303 | Attacker |
| `134.199.196.64` | 1,186 | Attacker |
| `134.209.166.254` | 1,181 | Attacker |
| `68.183.66.16` | 693 | Attacker |
| `129.212.184.91` | 494 | Attacker |
| `46.19.137.194` | 401 | Attacker |
| `103.147.150.236` | 360 | Attacker |
| `165.154.6.150` | 326 | Attacker |
| `221.161.235.168` | 305 | Attacker |
| `103.105.176.70` | 304 | Attacker |
| `168.167.228.123` | 304 | Attacker |
| `201.77.124.248` | 300 | Attacker |
| `8.219.156.182` | 300 | Attacker |
| `20.203.42.204` | 282 | Attacker |
| `45.205.1.110` | 280 | Attacker |
| `121.142.87.218` | 274 | Attacker |
| `200.24.69.113` | 262 | Attacker |
| `66.96.237.254` | 258 | Attacker |
| `161.35.17.41` | 257 | Attacker |

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

- `/etc/hostname`
- `/etc/netplan`
- `/etc/network/interfaces`
- `/etc/os-release`
- `/etc/passwd`
- `/etc/shadow`
- `/etc/sysconfig/network-scripts`
- `/tmp/test`
- `/tmp/test_1774550975`
- `/tmp/test_1774565799`
- `/tmp/zbgjp0yc6izgkftm2p29n0msdb`
- `/var/tmp/zbgjp0yc6izgkftm2p29n0msdb`

### Extracted URLs

- `https://31.57.216.121/sh`

---

## Top Attack Patterns (SSH)

- [299x] `echo -e "\x6F\x6B`
- [209x] `lspci`
- [129x] `/bin/./uname -s -v -n -r -m`
- [107x] `uptime -p`
- [103x] `nvidia-smi -q`
- [103x] `grep "Product Name`
- [88x] `grep VGA`
- [72x] `grep VGA -c`
- [49x] `grep "3D controller`
- [45x] `$f" 2>/dev/null`
- [45x] `echo 0`
- [45x] `echo 1`
- [42x] `grep . -c`
- [12x] `uname -a`
- [8x] `echo login_success`

## Top Attack Patterns (HTTP)

| URI | Hits | Category |
|-----|------|----------|
| `/favicon.ico` | 1 | Web Scan |

### HTTP Methods

- **GET**: 165
- **PROPFIND**: 23
- **POST**: 3
- **HEAD**: 2

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 5 | `sigma/*.yml` |
| YARA (Payload) | 4 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 512 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*