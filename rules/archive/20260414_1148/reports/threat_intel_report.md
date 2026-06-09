# Threat Intelligence Report

**Generated**: 2026-04-14 11:48 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,000 events** from **564 unique source IPs** across **31 countries** and **51 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 564 |
| Atomic Attack Patterns | 1821 |
| MITRE ATT&CK Techniques | 6 |
| Generated Sigma Rules | 4 |
| Generated YARA Rules | 3 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 506 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 959 |
| T1105 (Ingress Tool Transfer) | | 69 |
| T1059.004 (Unix Shell) | | 42 |
| T1033 (System Owner/User Discovery) | | 27 |
| T1057 (Process Discovery) | | 18 |
| T1053.003 (Cron) | | 9 |

### Tactics Distribution

- **discovery**: 1004 events ████████████████████████████████████████
- **command_and_control**: 69 events ██████████████████████████████████
- **execution**: 42 events █████████████████████
- **persistence**: 9 events ████

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| Germany | 10,823 |
| United States | 10,078 |
| Netherlands | 611 |
| Bulgaria | 504 |
| France | 480 |
| United Kingdom | 446 |
| China | 338 |
| Romania | 305 |
| Portugal | 278 |
| Russia | 216 |
| Hong Kong | 143 |
| Serbia | 129 |
| Singapore | 91 |
| India | 77 |
| Pakistan | 75 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Pfcloud UG (haftungsbeschrankt) | 10,537 |
| ISAEV Igor | 2,694 |
| ReliableSite.Net LLC | 2,089 |
| Google LLC | 984 |
| DigitalOcean, LLC | 970 |
| ONYPHE SAS | 963 |
| Amazon.com, Inc. | 926 |
| Censys, Inc. | 570 |
| Akamai Connected Cloud | 539 |
| ColocaTel Inc. | 459 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 440 |
| Unmanaged Ltd | 435 |
| Hydra Communications Ltd | 428 |
| Vpsvault.host Ltd | 357 |
| Microsoft Corporation | 268 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `176.65.132.254` | 10,379 | Attacker |
| `87.251.64.159` | 2,676 | Attacker |
| `104.243.32.126` | 1,187 | Attacker |
| `85.11.167.11` | 448 | Attacker |
| `104.243.43.7` | 251 | Attacker |
| `80.94.92.182` | 202 | Attacker |
| `104.243.35.104` | 179 | Attacker |
| `206.221.176.60` | 178 | Attacker |
| `45.205.1.5` | 161 | Attacker |
| `104.243.32.235` | 150 | Attacker |
| `45.205.1.110` | 147 | Attacker |
| `178.221.54.184` | 129 | Attacker |
| `18.218.118.203` | 128 | Attacker |
| `81.29.142.100` | 119 | Attacker |
| `16.58.56.214` | 115 | Attacker |
| `92.118.39.72` | 106 | Attacker |
| `18.116.101.220` | 105 | Attacker |
| `3.129.187.38` | 102 | Attacker |
| `3.131.220.121` | 99 | Attacker |
| `2.57.122.238` | 86 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 564 |
| URLs | 0 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 21 |

### Targeted File Paths

- `/tmp/.`
- `/tmp/YXgFiVHZ`
- `/tmp/cache`
- `/tmp/d.log`
- `/tmp/inLKeqBu`
- `/tmp/irToIbNv`
- `/tmp/nFFqwKAF`
- `/tmp/njEmzmlF`
- `/tmp/vstzwavn`
- `/tmp/wxRxEdHR`
- `/tmp/xOjPSMpn`
- `/var/tmp`
- `/var/tmp/.`
- `/var/tmp/YXgFiVHZ`
- `/var/tmp/inLKeqBu`
- `/var/tmp/irToIbNv`
- `/var/tmp/nFFqwKAF`
- `/var/tmp/njEmzmlF`
- `/var/tmp/vstzwavn`
- `/var/tmp/wxRxEdHR`

---

## Top Attack Patterns (SSH)

- [282x] `lspci`
- [180x] `nvidia-smi -q`
- [180x] `grep "Product Name`
- [93x] `egrep VGA`
- [92x] `uname -m`
- [60x] `/bin/./uname -s -v -n -r -m`
- [58x] `uptime -p`
- [52x] `grep VGA`
- [49x] `grep VGA -c`
- [48x] `grep Radeon`
- [47x] `uname -n`
- [47x] `uname -r`
- [46x] `uptime`
- [46x] `grep -ohe 'up .*`
- [45x] `nproc`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 4 | `sigma/*.yml` |
| YARA (Payload) | 3 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 506 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*