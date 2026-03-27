# Threat Intelligence Report

**Generated**: 2026-03-26 15:37 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **997 events** from **575 unique source IPs** across **38 countries** and **57 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 997 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 575 |
| Atomic Attack Patterns | 1392 |
| MITRE ATT&CK Techniques | 10 |
| Generated Sigma Rules | 6 |
| Generated YARA Rules | 4 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 517 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1059.004 (Unix Shell) | | 699 |
| T1082 (System Information Discovery) | | 315 |
| T1105 (Ingress Tool Transfer) | | 33 |
| T1222.002 (Linux File Permissions Modification) | | 9 |
| T1552.004 (Private Keys) | | 6 |
| T1033 (System Owner/User Discovery) | | 6 |
| T1016 (System Network Configuration Discovery) | | 4 |
| T1005 (Data from Local System) | | 4 |
| T1057 (Process Discovery) | | 3 |
| T1552.001 (Credentials In Files) | | 2 |

### Tactics Distribution

- **execution**: 699 events ████████████████████████████████████████
- **discovery**: 328 events ████████████████████████████████████████
- **command_and_control**: 33 events ████████████████
- **defense_evasion**: 9 events ████
- **credential_access**: 8 events ████
- **collection**: 4 events ██

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United Arab Emirates | 61,090 |
| United States | 12,075 |
| Indonesia | 5,663 |
| Brazil | 3,218 |
| France | 3,209 |
| Singapore | 3,051 |
| South Korea | 2,794 |
| Germany | 2,668 |
| China | 2,574 |
| Hong Kong | 2,563 |
| India | 2,304 |
| Pakistan | 2,239 |
| United Kingdom | 2,112 |
| Switzerland | 1,432 |
| The Netherlands | 1,194 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Emirates Telecommunications Group Company (etisalat Group) Pjsc | 60,808 |
| DigitalOcean, LLC | 5,300 |
| PT Cloud Hosting Indonesia | 2,968 |
| LANTEC COMUNICACAO MULTIMIDIA LTDA | 2,101 |
| Google LLC | 2,071 |
| Ghosty Networks LLC | 1,951 |
| Korea Telecom | 1,899 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 1,873 |
| Microsoft Corporation | 1,609 |
| OVH SAS | 1,386 |
| ONYPHE SAS | 1,275 |
| Amazon.com, Inc. | 1,249 |
| Private Layer INC | 1,238 |
| Alibaba US Technology Co., Ltd. | 1,155 |
| Cloud Host Pte Ltd | 983 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `94.56.40.180` | 60,808 | Attacker |
| `187.108.1.130` | 2,101 | Attacker |
| `46.19.137.194` | 1,238 | Attacker |
| `134.199.196.64` | 1,186 | Attacker |
| `134.209.166.254` | 1,184 | Attacker |
| `68.183.66.16` | 567 | Attacker |
| `129.212.184.91` | 496 | Attacker |
| `119.18.55.118` | 376 | Attacker |
| `193.227.241.201` | 376 | Attacker |
| `103.147.150.236` | 360 | Attacker |
| `165.154.6.150` | 326 | Attacker |
| `103.191.14.210` | 307 | Attacker |
| `103.63.25.171` | 307 | Attacker |
| `156.236.75.188` | 307 | Attacker |
| `170.79.37.88` | 307 | Attacker |
| `221.161.235.168` | 305 | Attacker |
| `8.219.156.182` | 300 | Attacker |
| `20.203.42.204` | 282 | Attacker |
| `37.59.110.4` | 282 | Attacker |
| `45.205.1.110` | 280 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 575 |
| URLs | 2 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 15 |

### Targeted File Paths

- `/.local/share/TelegramDesktop/tdata`
- `/etc/hostname`
- `/etc/netplan`
- `/etc/network/interfaces`
- `/etc/passwd`
- `/etc/shadow`
- `/etc/smsd.conf`
- `/etc/sysconfig/network-scripts`
- `/tmp/ltyu2gbpejb4dog81ohvxsrwvs`
- `/tmp/test`
- `/tmp/test_1774464627`
- `/var/log/smsd.log`
- `/var/qmux_connect`
- `/var/spool/sms`
- `/var/tmp/ltyu2gbpejb4dog81ohvxsrwvs`

### Extracted URLs

- `http://88.214.20.143/sshbins.sh`
- `https://31.57.216.121/sh`

---

## Top Attack Patterns (SSH)

- [535x] `echo -e "\x6F\x6B`
- [116x] `lspci`
- [76x] `$f" 2>/dev/null`
- [76x] `echo 0`
- [76x] `echo 1`
- [62x] `nvidia-smi -q`
- [62x] `grep "Product Name`
- [59x] `/bin/./uname -s -v -n -r -m`
- [54x] `uptime -p`
- [47x] `grep VGA`
- [40x] `grep VGA -c`
- [29x] `grep "3D controller`
- [28x] `grep . -c`
- [6x] `uname -a`
- [5x] `uname -s -m`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 6 | `sigma/*.yml` |
| YARA (Payload) | 4 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 517 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*