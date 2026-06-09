# Threat Intelligence Report

**Generated**: 2026-04-14 05:48 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,000 events** from **541 unique source IPs** across **31 countries** and **43 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 541 |
| Atomic Attack Patterns | 1845 |
| MITRE ATT&CK Techniques | 6 |
| Generated Sigma Rules | 4 |
| Generated YARA Rules | 3 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 373 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 940 |
| T1105 (Ingress Tool Transfer) | | 84 |
| T1059.004 (Unix Shell) | | 60 |
| T1033 (System Owner/User Discovery) | | 36 |
| T1057 (Process Discovery) | | 24 |
| T1053.003 (Cron) | | 12 |

### Tactics Distribution

- **discovery**: 1000 events ████████████████████████████████████████
- **command_and_control**: 84 events ████████████████████████████████████████
- **execution**: 60 events ██████████████████████████████
- **persistence**: 12 events ██████

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| Germany | 10,640 |
| United States | 5,399 |
| Bulgaria | 386 |
| Netherlands | 332 |
| France | 325 |
| Romania | 300 |
| United Kingdom | 297 |
| China | 224 |
| Russia | 153 |
| Serbia | 129 |
| Portugal | 97 |
| Hong Kong | 94 |
| Singapore | 78 |
| India | 75 |
| Japan | 43 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Pfcloud UG (haftungsbeschrankt) | 10,494 |
| ISAEV Igor | 1,785 |
| Google LLC | 742 |
| ONYPHE SAS | 661 |
| DigitalOcean, LLC | 530 |
| Amazon.com, Inc. | 443 |
| Censys, Inc. | 395 |
| Unmanaged Ltd | 373 |
| Akamai Connected Cloud | 372 |
| ColocaTel Inc. | 355 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 305 |
| Vpsvault.host Ltd | 259 |
| Hydra Communications Ltd | 254 |
| ReliableSite.Net LLC | 196 |
| Microsoft Corporation | 184 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `176.65.132.254` | 10,379 | Attacker |
| `87.251.64.159` | 1,776 | Attacker |
| `85.11.167.11` | 348 | Attacker |
| `80.94.92.182` | 202 | Attacker |
| `206.221.176.60` | 178 | Attacker |
| `178.221.54.184` | 129 | Attacker |
| `45.205.1.5` | 112 | Attacker |
| `81.29.142.100` | 112 | Attacker |
| `45.205.1.110` | 105 | Attacker |
| `2.57.122.238` | 86 | Attacker |
| `45.33.114.45` | 81 | Attacker |
| `3.131.220.121` | 77 | Attacker |
| `92.118.39.72` | 49 | Attacker |
| `103.199.123.32` | 46 | Attacker |
| `46.151.178.13` | 40 | Attacker |
| `134.122.28.163` | 39 | Attacker |
| `138.68.58.48` | 39 | Attacker |
| `147.182.209.206` | 39 | Attacker |
| `157.230.13.255` | 39 | Attacker |
| `157.245.168.43` | 39 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 541 |
| URLs | 0 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 29 |

### Targeted File Paths

- `/tmp/.`
- `/tmp/GTrPtNDL`
- `/tmp/TricaLzn`
- `/tmp/YXgFiVHZ`
- `/tmp/cache`
- `/tmp/d.log`
- `/tmp/inLKeqBu`
- `/tmp/irToIbNv`
- `/tmp/jNWdLwgu`
- `/tmp/nFFqwKAF`
- `/tmp/njEmzmlF`
- `/tmp/tkuzdOqW`
- `/tmp/vstzwavn`
- `/tmp/wxRxEdHR`
- `/tmp/xOjPSMpn`
- `/var/tmp`
- `/var/tmp/.`
- `/var/tmp/GTrPtNDL`
- `/var/tmp/TricaLzn`
- `/var/tmp/YXgFiVHZ`

---

## Top Attack Patterns (SSH)

- [267x] `lspci`
- [169x] `nvidia-smi -q`
- [169x] `grep "Product Name`
- [102x] `uname -m`
- [101x] `egrep VGA`
- [53x] `grep Radeon`
- [53x] `uname -n`
- [53x] `uname -r`
- [51x] `/bin/./uname -s -v -n -r -m`
- [49x] `uptime -p`
- [48x] `xargs rm -f 2>/dev/null`
- [48x] `nproc`
- [48x] `grep 3D`
- [48x] `uname -s -v -n -r -m`
- [48x] `uptime`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 4 | `sigma/*.yml` |
| YARA (Payload) | 3 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 373 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*