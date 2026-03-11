# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it
responsibly:

1. **Do NOT open a public GitHub issue.**
2. Email: **d.hensen2904@gmail.com**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
4. You will receive an acknowledgment within 48 hours.

## Scope

This project generates and publishes security rules (Suricata, Sigma, YARA)
and threat intelligence data (IOCs, blocklists) derived from honeypot
observations. The data is intended for defensive use only.

## Responsible Use

- The generated rules and IOCs are based on real attack traffic observed by
  honeypot sensors. Use them to **improve your defenses**, not to target
  the listed IPs or infrastructure.
- IP addresses in blocklists may be compromised systems, not the actual
  threat actors. Handle them accordingly.
- STIX bundles and IOC feeds are provided as-is for integration into your
  SIEM, SOAR, or threat intelligence platform.

## Auto-Synced Data

The `rules/` and `threat-intel/` directories are automatically updated from
a live honeypot infrastructure. All internal infrastructure details are
sanitized before publication. If you find any leaked internal information,
please report it immediately using the contact above.
