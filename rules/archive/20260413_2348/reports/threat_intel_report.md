# Threat Intelligence Report

**Generated**: 2026-04-13 23:48 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,000 events** from **516 unique source IPs** across **30 countries** and **38 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 516 |
| Atomic Attack Patterns | 1912 |
| MITRE ATT&CK Techniques | 6 |
| Generated Sigma Rules | 4 |
| Generated YARA Rules | 3 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 237 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 909 |
| T1105 (Ingress Tool Transfer) | | 121 |
| T1059.004 (Unix Shell) | | 92 |
| T1033 (System Owner/User Discovery) | | 58 |
| T1057 (Process Discovery) | | 38 |
| T1053.003 (Cron) | | 19 |

### Tactics Distribution

- **discovery**: 1005 events ████████████████████████████████████████
- **command_and_control**: 121 events ████████████████████████████████████████
- **execution**: 92 events ████████████████████████████████████████
- **persistence**: 19 events █████████

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| Germany | 10,511 |
| United States | 2,643 |
| Netherlands | 216 |
| France | 164 |
| United Kingdom | 154 |
| Bulgaria | 120 |
| China | 108 |
| Russia | 76 |
| Hong Kong | 48 |
| Singapore | 42 |
| Portugal | 36 |
| Japan | 31 |
| India | 22 |
| Romania | 18 |
| Brazil | 17 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Pfcloud UG (haftungsbeschrankt) | 10,454 |
| ISAEV Igor | 952 |
| Google LLC | 408 |
| ONYPHE SAS | 348 |
| DigitalOcean, LLC | 296 |
| Censys, Inc. | 192 |
| Amazon.com, Inc. | 187 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 181 |
| Vpsvault.host Ltd | 144 |
| Hydra Communications Ltd | 117 |
| ColocaTel Inc. | 102 |
| Unmanaged Ltd | 99 |
| Microsoft Corporation | 93 |
| Alibaba US Technology Co., Ltd. | 91 |
| Akamai Connected Cloud | 82 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `176.65.132.254` | 10,379 | Attacker |
| `87.251.64.159` | 950 | Attacker |
| `85.11.167.11` | 98 | Attacker |
| `45.205.1.5` | 63 | Attacker |
| `81.29.142.100` | 59 | Attacker |
| `45.205.1.110` | 56 | Attacker |
| `92.118.39.72` | 49 | Attacker |
| `138.68.58.48` | 39 | Attacker |
| `147.182.209.206` | 39 | Attacker |
| `157.245.168.43` | 39 | Attacker |
| `167.71.31.191` | 39 | Attacker |
| `23.239.29.27` | 39 | Attacker |
| `45.33.114.92` | 39 | Attacker |
| `92.118.39.76` | 34 | Attacker |
| `45.153.34.204` | 28 | Attacker |
| `128.199.225.7` | 25 | Attacker |
| `3.130.168.2` | 25 | Attacker |
| `103.97.215.11` | 22 | Attacker |
| `46.151.178.13` | 21 | Attacker |
| `45.205.1.26` | 21 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 515 |
| URLs | 0 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 41 |

### Targeted File Paths

- `/tmp/.`
- `/tmp/BlMjEFHm`
- `/tmp/GTrPtNDL`
- `/tmp/HbQlqYct`
- `/tmp/MGsSTmiJ`
- `/tmp/TricaLzn`
- `/tmp/YXgFiVHZ`
- `/tmp/cache`
- `/tmp/d.log`
- `/tmp/eHZMJvMa`
- `/tmp/inLKeqBu`
- `/tmp/irToIbNv`
- `/tmp/jNWdLwgu`
- `/tmp/lCQUgUCQ`
- `/tmp/nFFqwKAF`
- `/tmp/naNirqoI`
- `/tmp/njEmzmlF`
- `/tmp/tkuzdOqW`
- `/tmp/vstzwavn`
- `/tmp/wxRxEdHR`

---

## Top Attack Patterns (SSH)

- [211x] `lspci`
- [142x] `nvidia-smi -q`
- [142x] `grep "Product Name`
- [140x] `uname -m`
- [138x] `egrep VGA`
- [76x] `xargs rm -f 2>/dev/null`
- [71x] `grep Radeon`
- [71x] `uname -n`
- [71x] `uname -r`
- [67x] `nproc`
- [67x] `grep 3D`
- [67x] `uname -s -v -n -r -m`
- [67x] `uptime`
- [67x] `grep -ohe 'up .*`
- [67x] `lscpu`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 4 | `sigma/*.yml` |
| YARA (Payload) | 3 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 237 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*