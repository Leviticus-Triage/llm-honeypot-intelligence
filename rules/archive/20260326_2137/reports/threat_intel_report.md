# Threat Intelligence Report

**Generated**: 2026-03-26 21:37 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,000 events** from **568 unique source IPs** across **37 countries** and **55 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 568 |
| Atomic Attack Patterns | 1310 |
| MITRE ATT&CK Techniques | 8 |
| Generated Sigma Rules | 4 |
| Generated YARA Rules | 3 |
| Generated Suricata Rules | 27 |
| Blocked IPs (Firewall) | 515 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1059.004 (Unix Shell) | | 605 |
| T1082 (System Information Discovery) | | 393 |
| T1105 (Ingress Tool Transfer) | | 18 |
| T1033 (System Owner/User Discovery) | | 3 |
| T1057 (Process Discovery) | | 2 |
| T1016 (System Network Configuration Discovery) | | 2 |
| T1005 (Data from Local System) | | 2 |
| T1543.002 (Systemd Service) | | 1 |

### Tactics Distribution

- **execution**: 605 events ████████████████████████████████████████
- **discovery**: 400 events ████████████████████████████████████████
- **command_and_control**: 18 events █████████
- **collection**: 2 events █
- **persistence**: 1 events 

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United Arab Emirates | 61,098 |
| United States | 12,021 |
| Brazil | 8,278 |
| Indonesia | 5,412 |
| Singapore | 3,612 |
| Germany | 3,442 |
| Hong Kong | 2,896 |
| France | 2,735 |
| South Korea | 2,723 |
| China | 2,157 |
| United Kingdom | 2,051 |
| Pakistan | 1,822 |
| India | 1,670 |
| The Netherlands | 1,136 |
| Switzerland | 1,112 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Emirates Telecommunications Group Company (etisalat Group) Pjsc | 60,808 |
| LANTEC COMUNICACAO MULTIMIDIA LTDA | 6,303 |
| DigitalOcean, LLC | 5,462 |
| PT Cloud Hosting Indonesia | 2,955 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 2,450 |
| Google LLC | 2,001 |
| Korea Telecom | 1,955 |
| Ghosty Networks LLC | 1,652 |
| OVH SAS | 1,617 |
| Microsoft Corporation | 1,534 |
| Amazon.com, Inc. | 1,340 |
| Byteplus Pte. Ltd. | 1,238 |
| Cloud Host Pte Ltd | 1,236 |
| ONYPHE SAS | 1,227 |
| Alibaba US Technology Co., Ltd. | 1,224 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `94.56.40.180` | 60,808 | Attacker |
| `187.108.1.130` | 6,303 | Attacker |
| `134.199.196.64` | 1,187 | Attacker |
| `134.209.166.254` | 1,184 | Attacker |
| `46.19.137.194` | 916 | Attacker |
| `68.183.66.16` | 658 | Attacker |
| `129.212.184.91` | 495 | Attacker |
| `103.147.150.236` | 360 | Attacker |
| `165.154.6.150` | 326 | Attacker |
| `221.161.235.168` | 305 | Attacker |
| `201.77.124.248` | 300 | Attacker |
| `8.219.156.182` | 300 | Attacker |
| `20.203.42.204` | 282 | Attacker |
| `37.59.110.4` | 282 | Attacker |
| `45.205.1.110` | 280 | Attacker |
| `121.142.87.218` | 274 | Attacker |
| `161.35.17.41` | 257 | Attacker |
| `69.149.23.135` | 257 | Attacker |
| `103.103.245.61` | 256 | Attacker |
| `217.154.35.203` | 256 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 567 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 16 |

### Targeted File Paths

- `/.local/share/TelegramDesktop/tdata`
- `/etc/hostname`
- `/etc/netplan`
- `/etc/network/interfaces`
- `/etc/os-release`
- `/etc/smsd.conf`
- `/etc/sysconfig/network-scripts`
- `/tmp/ltyu2gbpejb4dog81ohvxsrwvs`
- `/tmp/test`
- `/tmp/test_1774550975`
- `/tmp/zbgjp0yc6izgkftm2p29n0msdb`
- `/var/log/smsd.log`
- `/var/qmux_connect`
- `/var/spool/sms`
- `/var/tmp/ltyu2gbpejb4dog81ohvxsrwvs`
- `/var/tmp/zbgjp0yc6izgkftm2p29n0msdb`

### Extracted URLs

- `https://31.57.216.121/sh`

---

## Top Attack Patterns (SSH)

- [510x] `echo -e "\x6F\x6B`
- [137x] `lspci`
- [96x] `/bin/./uname -s -v -n -r -m`
- [76x] `uptime -p`
- [62x] `nvidia-smi -q`
- [62x] `grep "Product Name`
- [61x] `grep VGA`
- [47x] `grep VGA -c`
- [36x] `$f" 2>/dev/null`
- [36x] `echo 0`
- [36x] `echo 1`
- [29x] `grep "3D controller`
- [25x] `grep . -c`
- [10x] `uname -a`
- [8x] `echo login_success`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 4 | `sigma/*.yml` |
| YARA (Payload) | 3 | `yara/*.yar` |
| Suricata (IDS/IPS) | 27 | `suricata/honeypot.rules` |
| Firewall (iptables) | 515 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*