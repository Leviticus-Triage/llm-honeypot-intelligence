# MITRE ATT&CK Mapping

Detailed mapping of observed attacker techniques to MITRE ATT&CK framework,
including detection sources and generated outputs.

---

## Reconnaissance

| ID | Technique | Observation | Detection |
|----|-----------|-------------|-----------|
| [T1595](https://attack.mitre.org/techniques/T1595/) | Active Scanning | Port scanning across all honeypot sensors | Suricata + IP reputation |
| [T1595.001](https://attack.mitre.org/techniques/T1595/001/) | Scanning IP Blocks | Sequential IP scanning patterns | ML anomaly detection |
| [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Vulnerability Scanning | CVE-specific probes (Log4Shell, ProxyShell, etc.) | CVE engine + Suricata |
| [T1592](https://attack.mitre.org/techniques/T1592/) | Gather Victim Host Information | OS fingerprinting, service version probing | Sigma |

## Resource Development

| ID | Technique | Observation | Detection |
|----|-----------|-------------|-----------|
| [T1583.004](https://attack.mitre.org/techniques/T1583/004/) | Server (Infrastructure) | Compromised hosts used as scanning proxies | IP reputation + campaign clustering |
| [T1588.005](https://attack.mitre.org/techniques/T1588/005/) | Exploits | Public exploit usage against CVE honeypots | YARA + CVE engine |

## Initial Access

| ID | Technique | Observation | Detection |
|----|-----------|-------------|-----------|
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | CVE exploitation against 15 honeypot profiles | Suricata + YARA |
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | SSH/Telnet credential stuffing | Sigma + blocklist |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing | Manual credential attempts in SSH | Sigma |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password Spraying | Same password across multiple usernames | Campaign clustering |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Credential reuse across sensors | Sigma |

## Execution

| ID | Technique | Observation | Detection |
|----|-----------|-------------|-----------|
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Shell commands in SSH sessions | Sigma + YARA |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | PowerShell payloads in web exploitation | YARA |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Unix Shell | Bash/sh commands post-SSH access | Sigma |
| [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | JavaScript | Malicious JS in web requests | YARA |

## Persistence

| ID | Technique | Observation | Detection |
|----|-----------|-------------|-----------|
| [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Web Shell | Web shell upload attempts via HTTP honeypots | YARA + Suricata |
| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Crontab modifications in SSH sessions | Sigma |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | SSH key injection attempts | Sigma |

## Command and Control

| ID | Technique | Observation | Detection |
|----|-----------|-------------|-----------|
| [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol | HTTP/DNS C2 patterns | C2 engine + Suricata |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols | HTTP beaconing to known C2 frameworks | C2 engine |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | DNS | DNS tunneling, high-entropy queries | C2 engine + Suricata |
| [T1571](https://attack.mitre.org/techniques/T1571/) | Non-Standard Port | C2 over unusual ports | C2 engine |
| [T1573](https://attack.mitre.org/techniques/T1573/) | Encrypted Channel | TLS C2 on non-standard ports | Suricata |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | wget/curl/tftp download attempts | YARA + Suricata |

## Exfiltration

| ID | Technique | Observation | Detection |
|----|-----------|-------------|-----------|
| [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | Large outbound data in sessions | ML detector |

## Impact

| ID | Technique | Observation | Detection |
|----|-----------|-------------|-----------|
| [T1496](https://attack.mitre.org/techniques/T1496/) | Resource Hijacking | Cryptominer deployment attempts | YARA + Sigma |

---

## Detection coverage by component

| Component | Techniques covered | Primary output |
|-----------|-------------------|----------------|
| CVE Engine | T1190, T1595.002, T1588.005 | Enhanced LLM responses for targeted collection |
| Rule Generator | T1110, T1059, T1190, T1595, T1105, T1505.003 | Suricata, Sigma, YARA rules |
| ML Detector | T1041, T1595.001, T1036, T1078 | IP reputation, campaign clusters, alerts |
| C2 Engine | T1071, T1071.001, T1071.004, T1571, T1573 | C2 Suricata rules, real-time alerts |
| Campaign Clustering | T1110.003, T1583.004, T1078 | Campaign reports, coordinated IP groups |
