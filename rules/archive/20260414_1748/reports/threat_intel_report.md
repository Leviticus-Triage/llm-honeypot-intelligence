# Threat Intelligence Report

**Generated**: 2026-04-14 17:48 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,000 events** from **579 unique source IPs** across **33 countries** and **53 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 579 |
| Atomic Attack Patterns | 1786 |
| MITRE ATT&CK Techniques | 9 |
| Generated Sigma Rules | 5 |
| Generated YARA Rules | 4 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 512 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 962 |
| T1059.004 (Unix Shell) | | 19 |
| T1033 (System Owner/User Discovery) | | 11 |
| T1105 (Ingress Tool Transfer) | | 11 |
| T1057 (Process Discovery) | | 5 |
| T1016 (System Network Configuration Discovery) | | 2 |
| T1552.001 (Credentials In Files) | | 2 |
| T1053.003 (Cron) | | 2 |
| T1543.002 (Systemd Service) | | 1 |

### Tactics Distribution

- **discovery**: 980 events ████████████████████████████████████████
- **execution**: 19 events █████████
- **command_and_control**: 11 events █████
- **persistence**: 3 events █
- **credential_access**: 2 events █

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 13,037 |
| Germany | 11,002 |
| Netherlands | 956 |
| Romania | 864 |
| France | 667 |
| Brazil | 634 |
| Bulgaria | 590 |
| United Kingdom | 586 |
| China | 519 |
| Portugal | 283 |
| Russia | 225 |
| Hong Kong | 203 |
| Singapore | 142 |
| Serbia | 129 |
| Japan | 83 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Pfcloud UG (haftungsbeschrankt) | 10,579 |
| ISAEV Igor | 3,522 |
| ReliableSite.Net LLC | 2,517 |
| DigitalOcean, LLC | 1,553 |
| ONYPHE SAS | 1,246 |
| Amazon.com, Inc. | 1,201 |
| Google LLC | 1,155 |
| Unmanaged Ltd | 985 |
| Akamai Connected Cloud | 853 |
| Censys, Inc. | 722 |
| W-NET TELLECOM EIRELI ME | 617 |
| Hydra Communications Ltd | 587 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 572 |
| ColocaTel Inc. | 524 |
| Vpsvault.host Ltd | 449 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `176.65.132.254` | 10,379 | Attacker |
| `87.251.64.159` | 3,495 | Attacker |
| `104.243.32.126` | 1,221 | Attacker |
| `45.228.8.33` | 617 | Attacker |
| `193.32.162.151` | 544 | Attacker |
| `85.11.167.11` | 508 | Attacker |
| `104.243.43.7` | 412 | Attacker |
| `45.205.1.5` | 203 | Attacker |
| `80.94.92.182` | 202 | Attacker |
| `104.243.35.104` | 196 | Attacker |
| `206.221.176.60` | 195 | Attacker |
| `45.205.1.110` | 182 | Attacker |
| `18.218.118.203` | 175 | Attacker |
| `104.243.32.235` | 167 | Attacker |
| `16.58.56.214` | 155 | Attacker |
| `18.116.101.220` | 144 | Attacker |
| `3.129.187.38` | 132 | Attacker |
| `3.130.168.2` | 130 | Attacker |
| `178.221.54.184` | 129 | Attacker |
| `81.29.142.100` | 114 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 579 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 16 |

### Targeted File Paths

- `/etc/netplan`
- `/etc/network/interfaces`
- `/etc/passwd`
- `/etc/shadow`
- `/etc/sysconfig/network-scripts`
- `/tmp/.`
- `/tmp/cache`
- `/tmp/d.log`
- `/tmp/irToIbNv`
- `/tmp/test`
- `/tmp/test_1776183069225922178`
- `/tmp/xOjPSMpn`
- `/var/tmp`
- `/var/tmp/.`
- `/var/tmp/irToIbNv`
- `/var/tmp/xOjPSMpn`

### Extracted URLs

- `https://46.151.182.82/sh`

---

## Top Attack Patterns (SSH)

- [386x] `lspci`
- [238x] `nvidia-smi -q`
- [238x] `grep "Product Name`
- [147x] `/bin/./uname -s -v -n -r -m`
- [140x] `uptime -p`
- [132x] `grep VGA`
- [127x] `grep VGA -c`
- [119x] `grep "3D controller`
- [110x] `grep . -c`
- [8x] `uname -a`
- [8x] `xargs rm -f 2>/dev/null`
- [8x] `uname -m`
- [7x] `uname -r`
- [7x] `egrep VGA`
- [6x] `grep Radeon`

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