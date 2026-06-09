# Threat Intelligence Report

**Generated**: 2026-05-22 06:53 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **1,000 events** from **603 unique source IPs** across **41 countries** and **73 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 1,000 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 603 |
| Atomic Attack Patterns | 1946 |
| MITRE ATT&CK Techniques | 10 |
| Generated Sigma Rules | 7 |
| Generated YARA Rules | 5 |
| Generated Suricata Rules | 30 |
| Blocked IPs (Firewall) | 509 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1082 (System Information Discovery) | | 886 |
| T1552.004 (Private Keys) | | 169 |
| T1059.004 (Unix Shell) | | 73 |
| T1105 (Ingress Tool Transfer) | | 49 |
| T1222.002 (Linux File Permissions Modification) | | 30 |
| T1033 (System Owner/User Discovery) | | 22 |
| T1057 (Process Discovery) | | 15 |
| T1053.003 (Cron) | | 8 |
| T1005 (Data from Local System) | | 3 |
| T1016 (System Network Configuration Discovery) | | 1 |

### Tactics Distribution

- **discovery**: 924 events ████████████████████████████████████████
- **credential_access**: 169 events ████████████████████████████████████████
- **execution**: 73 events ████████████████████████████████████
- **command_and_control**: 49 events ████████████████████████
- **defense_evasion**: 30 events ███████████████
- **persistence**: 8 events ████
- **collection**: 3 events █

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| The Netherlands | 61,317 |
| Seychelles | 18,685 |
| United States | 9,269 |
| Brazil | 4,246 |
| France | 2,090 |
| Romania | 1,978 |
| Poland | 1,193 |
| Luxembourg | 748 |
| Singapore | 682 |
| China | 659 |
| Bulgaria | 582 |
| United Kingdom | 557 |
| Pakistan | 460 |
| Hong Kong | 418 |
| Germany | 403 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| Alsycon B.V. | 70,850 |
| Pfcloud UG (haftungsbeschrankt) | 8,738 |
| LANTEC COMUNICACAO MULTIMIDIA LTDA | 4,138 |
| Internap Holding LLC | 2,088 |
| Google LLC | 1,867 |
| Akamai Connected Cloud | 1,820 |
| DigitalOcean, LLC | 1,358 |
| ONYPHE SAS | 1,195 |
| Unmanaged Ltd | 1,034 |
| SS-Net | 921 |
| Alibaba US Technology Co., Ltd. | 790 |
| Amazon.com, Inc. | 788 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 787 |
| ISAEV Igor | 785 |
| Offshore LC | 748 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `45.95.147.229` | 52,149 | Attacker |
| `160.119.76.4` | 18,667 | Attacker |
| `45.153.34.114` | 8,644 | Attacker |
| `187.108.1.130` | 4,138 | Attacker |
| `198.143.146.226` | 2,077 | Attacker |
| `172.234.162.56` | 1,332 | Attacker |
| `80.94.95.34` | 899 | Attacker |
| `176.65.139.118` | 707 | Attacker |
| `87.251.64.176` | 588 | Attacker |
| `193.32.162.145` | 456 | Attacker |
| `152.42.229.216` | 456 | Attacker |
| `2.57.122.99` | 392 | Attacker |
| `185.16.39.100` | 383 | Attacker |
| `45.198.224.18` | 371 | Attacker |
| `64.89.162.15` | 289 | Attacker |
| `89.45.222.186` | 250 | Attacker |
| `85.11.167.11` | 239 | Attacker |
| `45.205.1.5` | 209 | Attacker |
| `87.251.64.146` | 186 | Attacker |
| `45.141.56.49` | 150 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 603 |
| URLs | 2 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 29 |

### Targeted File Paths

- `/.local/share/TelegramDesktop/tdata`
- `/etc/hosts.deny`
- `/etc/smsd.conf`
- `/tmp/.`
- `/tmp/BaZAkxlp`
- `/tmp/DTURvuPq`
- `/tmp/NfUJZBuw`
- `/tmp/ZsveeUXA`
- `/tmp/auth.sh`
- `/tmp/cache`
- `/tmp/d.log`
- `/tmp/fjLaBUQT`
- `/tmp/k4hpytt9p9vk4tst6uuygjcnjz`
- `/tmp/kDSAADoJ`
- `/tmp/secure.sh`
- `/tmp/uYkJtZaN`
- `/var/log/smsd.log`
- `/var/qmux_connect`
- `/var/spool/sms`
- `/var/tmp`

### Extracted URLs

- `http://180.129.130.18/amd`
- `http://180.129.130.18/syss`

---

## Top Attack Patterns (SSH)

- [327x] `lspci`
- [218x] `nvidia-smi -q`
- [217x] `grep "Product Name`
- [91x] `/bin/./uname -s -v -n -r -m`
- [91x] `uptime -p`
- [91x] `grep VGA -c`
- [91x] `grep VGA`
- [91x] `grep "3D controller`
- [90x] `grep . -c`
- [36x] `egrep VGA`
- [28x] `chattr -ia .ssh`
- [28x] `lockr -ia .ssh`
- [28x] `rm -rf .ssh`
- [28x] `mkdir .ssh`
- [28x] `echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 7 | `sigma/*.yml` |
| YARA (Payload) | 5 | `yara/*.yar` |
| Suricata (IDS/IPS) | 30 | `suricata/honeypot.rules` |
| Firewall (iptables) | 509 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*