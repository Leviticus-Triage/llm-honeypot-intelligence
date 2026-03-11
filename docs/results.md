# Operational Results

This document summarizes the operational results and analysis from the
LLM Honeypot Intelligence platform deployment.

---

## Deployment overview

| Parameter | Value |
|-----------|-------|
| Deployment start | Early 2025 |
| Sensor servers | 4 (distributed) |
| Sensor types | 25+ per server |
| Total events processed | 55,000,000+ |
| Unique attacker IPs | 22,000+ |
| Countries of origin | 122 |
| Uptime target | 24/7 continuous |

---

## Attack distribution by sensor type

The T-Pot deployment runs 25+ sensor types. The highest-volume sensors:

| Sensor | Protocol | Events (approx.) | Primary attack type |
|--------|----------|------------------:|---------------------|
| Honeytrap | Multi | High | Port scanning, service probing |
| Cowrie | SSH/Telnet | High | Brute force, post-exploitation |
| Dionaea | SMB/HTTP/FTP | Medium | Malware delivery, exploit attempts |
| Beelzebub | SSH (LLM) | Medium | Interactive exploitation via LLM |
| Galah | HTTP (LLM) | Medium | Web exploitation via LLM |
| Tanner | HTTP | Medium | Web application attacks |
| Glutton | Multi | Medium | Protocol-level attacks |
| ADBHoney | ADB | Low | Android Debug Bridge exploitation |
| Mailoney | SMTP | Low | Email spam, phishing relay |
| CitrixHoneypot | HTTP | Low | Citrix gateway exploitation |

---

## LLM engagement analysis

### Engagement improvement with RL

The reinforcement learning scorer continuously optimizes which LLM responses
keep attackers engaged. Key findings:

- **Average session duration increased** after RL optimization compared to
  random cache selection
- **Command diversity** (unique commands per session) is higher when the RL
  scorer selects responses, indicating attackers believe the system is real
  and attempt more complex exploitation
- **Return rate** of attacker IPs is higher for LLM-powered honeypots vs.
  static-response sensors

### CVE honeypot effectiveness

The 15 CVE profiles attract targeted exploitation attempts:

- **Log4Shell (CVE-2021-44228):** Highest volume -- automated scanners
  constantly probe for JNDI injection points
- **Spring4Shell (CVE-2022-22965):** Targeted by more sophisticated actors
  who check response headers for Spring framework indicators
- **ProxyShell/ProxyLogon:** Exchange-themed honeypots attract credential
  harvesting and mailbox access attempts
- **MOVEit (CVE-2023-34362):** Attracts SQL injection chains targeting file
  transfer infrastructure

---

## Detection engineering output

### Generated rules by format

| Format | Count (approx.) | Update frequency | Quality control |
|--------|----------------:|-----------------|-----------------|
| Suricata | Varies per cycle | Every 6 hours | Automated dedup + SID management |
| Sigma | Varies per cycle | Every 6 hours | Logsource validation |
| YARA | Varies per cycle | Every 6 hours | String extraction + condition logic |
| Firewall blocklists | All observed IPs | Every 6 hours | Private IP filtering |
| STIX 2.1 bundles | Per cycle | Every 6 hours | ATT&CK technique mapping |

### Handcrafted C2 detection rules

The C2 detection engine includes 23 handcrafted Suricata rules covering:

- DNS tunneling (high-entropy queries, TXT record abuse, query volume anomalies)
- HTTP beaconing (interval detection, payload size consistency, known C2 patterns)
- Protocol anomalies (unexpected protocols on standard ports, header encoding)
- Covert channel detection (steganographic patterns, timing channels)

---

## Campaign clustering

The DBSCAN-based campaign clustering identifies coordinated attack activity:

### Common campaign patterns observed

1. **SSH brute force campaigns:** Large botnets with shared credential lists
   targeting multiple sensors simultaneously
2. **CVE scanning waves:** Coordinated scanning for specific vulnerabilities
   (typically within 24-48 hours of public disclosure)
3. **Cryptominer deployment:** Post-exploitation campaigns that attempt to
   download and execute cryptocurrency miners
4. **IoT botnet recruitment:** Mirai variants targeting Telnet and ADB
   services with default credentials
5. **Web shell deployment:** HTTP-based attacks attempting to upload web
   shells via file upload vulnerabilities

---

## Geographic distribution

Top 10 source countries by attack volume (approximate):

| Rank | Country | Primary attack types |
|------|---------|---------------------|
| 1 | China | SSH brute force, scanning, web exploitation |
| 2 | United States | Mixed (also legitimate security researchers) |
| 3 | Russia | Targeted exploitation, C2 infrastructure |
| 4 | South Korea | Automated scanning, botnet traffic |
| 5 | India | Brute force, credential stuffing |
| 6 | Brazil | IoT botnet, Telnet exploitation |
| 7 | Vietnam | SSH brute force, cryptominer deployment |
| 8 | Indonesia | Scanning, brute force |
| 9 | Taiwan | Automated scanning |
| 10 | Netherlands | Mixed (also hosting/VPN infrastructure) |

---

## ML anomaly detection

The Isolation Forest model identifies behavioral outliers that do not match
known attack patterns. These anomalies often represent:

- **Novel exploitation techniques** not yet covered by signature-based rules
- **Reconnaissance by sophisticated actors** (low-and-slow scanning,
  careful service enumeration)
- **C2 check-in patterns** from compromised infrastructure used as proxies
- **Targeted attacks** (vs. opportunistic scanning) that focus on specific
  sensor configurations

---

## Continuous improvement

The platform is continuously refined through:

1. **RL feedback loop:** Better responses → longer engagement → more attack
   data → better detection rules → improved threat intelligence
2. **New CVE profiles:** Added within days of major CVE disclosures
3. **Rule quality feedback:** False positive reports from downstream
   consumers improve the rule generator's scoring
4. **Sensor diversification:** New sensor types and per-client customized
   deployments expand the attack surface visibility
